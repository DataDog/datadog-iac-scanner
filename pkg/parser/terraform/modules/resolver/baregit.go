/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// dirPerm is the permission mode used for all directories created by resolvers.
const dirPerm = 0o750

// maxArchiveExtractBytes caps cumulative bytes read from a single git archive tar stream.
const maxArchiveExtractBytes = 200 * 1024 * 1024

// BareGitResolver keeps one bare clone per repo and extracts refs via git archive.
type BareGitResolver struct {
	// Defaults to <user-cache-dir>/datadog-iac-scanner/git-bare.
	CacheDir string
	Budget   *ModuleCacheBudget

	hostAllowlist []string
	policy        *httpDestinationPolicy
	mu            sync.Mutex
	repos         map[string]*bareRepo
}

const bareCloneAttempts = 3

type bareRepo struct {
	barePath     string // path to the bare clone on disk
	extractBase  string // base dir for per-(sha,subdir) extracted trees
	refCachePath string // path to the persistent ref→SHA JSON file
	policy       *httpDestinationPolicy

	cloneOK   atomic.Bool
	cloneMu   sync.Mutex       // serializes clone attempts against barePath
	cloneErrs map[string]error // transport → clone failure, guarded by cloneMu
	networkMu sync.RWMutex     // isolates transactional fetches from lazy object writes

	fetchSF   singleflight.Group
	extractSF singleflight.Group

	refMu    sync.RWMutex
	refCache map[string]string // tag/branch ref → resolved SHA (warm from disk on init)
}

// bareRemote binds a bare clone to the transport one module source requires.
// Transport is part of the cache identity so an https spelling and an ssh
// spelling never share a remote or a clone failure.
type bareRemote struct {
	*bareRepo
	transport string // https or ssh; selects how network commands reach the remote
	cloneURL  string // canonical remote URL, by hostname rather than address
}

// sfKey namespaces a singleflight key by transport so that a network failure on
// one transport is never handed to a caller that asked for the other.
func (rem *bareRemote) sfKey(key string) string {
	return rem.transport + "\x00" + key
}

func NewBareGitResolver(cacheDir string, hostAllowlist ...string) *BareGitResolver {
	return &BareGitResolver{
		CacheDir:      cacheDir,
		hostAllowlist: hostAllowlist,
		policy:        newHTTPDestinationPolicy(hostAllowlist),
		repos:         make(map[string]*bareRepo),
	}
}

func (r *BareGitResolver) effectiveCacheDir() string {
	if r.CacheDir != "" {
		return r.CacheDir
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "datadog-iac-scanner", "git-bare")
}

func repoURLKey(normalizedRepo string) string {
	h := sha256.Sum256([]byte(normalizedRepo))
	return fmt.Sprintf("%x", h[:12])
}

func canonicalHTTPSCloneURL(repoURL string) string {
	parsed, err := url.Parse(repoURL)
	if err != nil || parsed.Scheme != httpsScheme || parsed.Hostname() == "" || parsed.User != nil {
		return ""
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// canonicalSSHCloneURL returns the ssh remote URL with the go-getter query stripped.
// A URL carrying a password is rejected; ssh authenticates through an agent or key.
func canonicalSSHCloneURL(repoURL string) string {
	parsed, err := url.Parse(repoURL)
	if err != nil || parsed.Scheme != sshScheme || parsed.Hostname() == "" {
		return ""
	}
	if parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			return ""
		}
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func canonicalGitCloneURL(repoURL string) string {
	if gitModuleTransportKey(repoURL) == sshScheme {
		return canonicalSSHCloneURL(repoURL)
	}
	return canonicalHTTPSCloneURL(repoURL)
}

// getOrInitRemote returns the bare clone backing repoURL, bound to the transport
// repoURL asks for. Transport is part of the identity: sharing one store between an
// https and an scp-form spelling of the same repository costs more than the duplicate
// clone saves, because extraction serializes on a per-(clone, sha) lock and the two
// spellings then queue behind each other instead of materializing in parallel.
func (r *BareGitResolver) getOrInitRemote(repoURL string) *bareRemote {
	transport := gitModuleTransportKey(repoURL)
	key := transport + "\x00" + normalizeGitRepoURL(repoURL)
	remote := &bareRemote{
		transport: transport,
		cloneURL:  canonicalGitCloneURL(repoURL),
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if repo, ok := r.repos[key]; ok {
		remote.bareRepo = repo
		return remote
	}
	base := filepath.Join(r.effectiveCacheDir(), repoURLKey(key))
	refCachePath := filepath.Join(base, "refs.json")
	repo := &bareRepo{
		barePath:     filepath.Join(base, "repo.git"),
		extractBase:  filepath.Join(base, "extracted"),
		refCachePath: refCachePath,
		policy:       r.policy,
		refCache:     loadBareRefCache(refCachePath),
	}
	r.repos[key] = repo
	remote.bareRepo = repo
	return remote
}

// loadBareRefCache reads the persistent ref→SHA map for a bare clone.
func loadBareRefCache(path string) map[string]string {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return make(map[string]string)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]string)
	}
	return m
}

// saveBareRefCache writes the ref→SHA map atomically so concurrent runs don't corrupt it.
func (repo *bareRepo) saveBareRefCache() {
	repo.refMu.RLock()
	m := make(map[string]string, len(repo.refCache))
	for k, v := range repo.refCache {
		m[k] = v
	}
	repo.refMu.RUnlock()

	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	tmp := repo.refCachePath + ".tmp"
	if err := os.WriteFile(tmp, data, cacheFilePerms); err != nil {
		return
	}
	_ = os.Rename(tmp, repo.refCachePath)
}

func (rem *bareRemote) runNetworkGitWith(
	ctx context.Context, command gitNetworkCommand, output gitOutputFunc,
) ([]byte, error) {
	if rem.transport == sshScheme {
		return runGitSSHCommand(ctx, rem.policy, rem.cloneURL, command, output)
	}
	return runGitHTTPSCommand(rem.policy, rem.cloneURL, command, output)
}

func (rem *bareRemote) runNetworkGit(ctx context.Context, command gitNetworkCommand) ([]byte, error) {
	rem.networkMu.Lock()
	defer rem.networkMu.Unlock()

	var terminalBudgetErr error
	output := func(cmd *exec.Cmd) ([]byte, error) {
		if terminalBudgetErr != nil {
			return nil, terminalBudgetErr
		}
		objectsDir := filepath.Join(rem.barePath, "objects")
		existing, err := snapshotPackageTree(objectsDir)
		if err != nil {
			return nil, err
		}
		out, err := runGitCommandWithResourceBudget(
			ctx, cmd, rem.barePath, ResourceBudgetFromContext(ctx),
		)
		if err != nil {
			rollbackPackageTree(objectsDir, existing)
			var budgetErr *BudgetExceededError
			if errors.As(err, &budgetErr) {
				terminalBudgetErr = err
			}
		}
		return out, err
	}
	out, err := rem.runNetworkGitWith(ctx, command, output)
	if terminalBudgetErr != nil {
		return out, terminalBudgetErr
	}
	return out, err
}

func (rem *bareRemote) archiveGitCommand(ctx context.Context, remote string, extraConfig, args []string) *exec.Cmd {
	full := make([]string, 0, len(extraConfig)+len(args)+2)
	full = append(full, extraConfig...)
	full = append(full, "-c", "remote.origin.url="+remote)
	full = append(full, args...)
	return gitInDir(ctx, rem.barePath, full...)
}

// archiveCommand prepares git archive against the bare clone. A blob:none clone
// may lazily fetch missing blobs; that fetch is pointed at the destination the
// policy just validated. SSH returns one prep per validated address.
func (rem *bareRemote) archiveCommand(ctx context.Context, args []string) ([]archivePrep, error) {
	command := func(remote string, extraConfig []string) *exec.Cmd {
		return rem.archiveGitCommand(ctx, remote, extraConfig, args)
	}
	if rem.transport == sshScheme {
		return prepareGitSSHArchives(ctx, rem.policy, rem.cloneURL, command)
	}
	cmd, cleanup, err := prepareGitHTTPSCommand(rem.policy, rem.cloneURL, command)
	if err != nil {
		return nil, err
	}
	return []archivePrep{{cmd: cmd, cleanup: cleanup}}, nil
}

func (rem *bareRemote) ensureClone(ctx context.Context) error {
	if rem.cloneOK.Load() {
		return nil
	}
	rem.cloneMu.Lock()
	defer rem.cloneMu.Unlock()
	if rem.cloneOK.Load() {
		return nil
	}
	if err, failed := rem.cloneErrs[rem.transport]; failed {
		return err
	}
	err := rem.doClone(ctx)
	if err != nil {
		if rem.cloneErrs == nil {
			rem.cloneErrs = make(map[string]error)
		}
		rem.cloneErrs[rem.transport] = err
	}
	return err
}

// doClone checks for an existing bare clone, validates it, and attempts a fresh
// clone with retries if needed. It is always called while holding cloneMu.
func (rem *bareRemote) doClone(ctx context.Context) error {
	if info, err := os.Stat(rem.barePath); err == nil && info.IsDir() {
		// Validate that the directory is a real bare repo, not a partial clone
		// left by a killed process. This is a local-only read (no network, no
		// pack-file I/O) so it intentionally bypasses the acquireGitProc semaphore,
		// which is reserved for operations that meaningfully consume system resources.
		if gitInDir(ctx, rem.barePath, "rev-parse", "--git-dir").Run() == nil &&
			rem.cachedConfigIsSafe(ctx) {
			if gitInDir(ctx, rem.barePath, "remote", "set-url", "origin", rem.cloneURL).Run() == nil {
				rem.cloneOK.Store(true)
				return nil
			}
		}
		// Partial or corrupt clone — remove and reclone.
		_ = os.RemoveAll(rem.barePath)
	}
	var lastErr error
	for attempt := 0; attempt < bareCloneAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * 500 * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		if err := os.MkdirAll(filepath.Dir(rem.barePath), dirPerm); err != nil {
			lastErr = err
			continue
		}
		_ = os.RemoveAll(rem.barePath)
		release, err := acquireGitProc(ctx)
		if err != nil {
			lastErr = err
			continue
		}
		if _, urlErr := gitSafeArg(rem.cloneURL); urlErr != nil {
			lastErr = urlErr
			continue
		}
		out, cloneErr := rem.runNetworkGit(ctx, func(remote string, extraConfig []string) *exec.Cmd {
			return gitCloneBare(ctx, remote, rem.barePath, extraConfig)
		})
		release()
		if cloneErr == nil {
			// The clone contacted a policy-validated address literal, which git records
			// as origin. Persist the canonical hostname instead so a later run does not
			// reuse an address that has since moved.
			_ = gitInDir(ctx, rem.barePath, "remote", "set-url", "origin", rem.cloneURL).Run()
			rem.cloneOK.Store(true)
			return nil
		}
		_ = os.RemoveAll(rem.barePath)
		lastErr = fmt.Errorf("git clone --bare %s: %w\n%s", rem.cloneURL, cloneErr, bytes.TrimSpace(out))
		if !gitCloneRetryable(out, cloneErr) {
			break
		}
	}
	log := logger.FromContext(ctx)
	log.Warn().Err(lastErr).Msgf("BareGitResolver: failed to clone %s", rem.cloneURL)
	return lastErr
}

// gitCloneRetryable is false when another attempt cannot succeed without a
// credential or prompt change — typical for private HTTPS sources in CI.
func gitCloneRetryable(out []byte, err error) bool {
	if err == nil {
		return true
	}
	var budgetErr *BudgetExceededError
	if errors.As(err, &budgetErr) {
		return false
	}
	blob := strings.ToLower(string(out) + "\n" + err.Error())
	return !strings.Contains(blob, "could not read username") &&
		!strings.Contains(blob, "terminal prompts disabled") &&
		!strings.Contains(blob, "authentication failed") &&
		!strings.Contains(blob, "invalid username or password")
}

func (repo *bareRepo) cachedConfigIsSafe(ctx context.Context) bool {
	out, err := gitInDir(
		ctx,
		repo.barePath,
		"config",
		"--local",
		"--no-includes",
		"--name-only",
		"--null",
		"--list",
	).Output()
	if err != nil {
		return false
	}
	for _, rawKey := range bytes.Split(out, []byte{0}) {
		key := strings.ToLower(strings.TrimSpace(string(rawKey)))
		if key == "" {
			continue
		}
		if strings.HasPrefix(key, "http.") ||
			strings.HasPrefix(key, "url.") ||
			strings.HasPrefix(key, "credential.") ||
			strings.HasPrefix(key, "include.") ||
			strings.HasPrefix(key, "includeif.") ||
			strings.HasPrefix(key, "protocol.") ||
			strings.Contains(key, "proxy") ||
			key == "core.sshcommand" ||
			key == "core.gitproxy" {
			return false
		}
	}
	return true
}

// fetchRef ensures ref is present and returns its canonical commit SHA.
func (rem *bareRemote) fetchRef(ctx context.Context, ref string) (string, error) {
	if looksLikeSHA(ref) {
		return rem.fetchSHARef(ctx, ref)
	}
	return rem.fetchNamedRef(ctx, ref)
}

// fetchSHARef handles the case where ref is already a full 40-char SHA.
// It checks that the object is locally present, fetching it from origin if not.
func (rem *bareRemote) fetchSHARef(ctx context.Context, ref string) (string, error) {
	v, err, _ := rem.fetchSF.Do(rem.sfKey(ref), func() (interface{}, error) {
		release, acqErr := acquireGitProc(ctx)
		if acqErr != nil {
			return "", acqErr
		}
		defer release()
		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", refErr
		}
		if gitInDir(ctx, rem.barePath, "cat-file", "-t", safeRef).Run() == nil {
			return ref, nil // already present
		}
		out, err := rem.runNetworkGit(ctx, func(remote string, extraConfig []string) *exec.Cmd {
			args := append(append([]string{}, extraConfig...),
				"fetch", "--filter=blob:none", remote, safeRef)
			return gitInDir(ctx, rem.barePath, args...)
		})
		if err != nil {
			return "", fmt.Errorf("git fetch %s %s: %w\n%s", rem.cloneURL, ref, err, bytes.TrimSpace(out))
		}
		return ref, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// fetchNamedRef handles branch/tag refs: it resolves the name to a commit SHA,
// using an in-memory and on-disk cache to avoid unnecessary network fetches.
func (rem *bareRemote) fetchNamedRef(ctx context.Context, ref string) (string, error) {
	// Key on "ref:<name>" so SHA keys and name keys never collide in fetchSF.
	v, err, _ := rem.fetchSF.Do(rem.sfKey("ref:"+ref), func() (interface{}, error) {
		// HEAD moves; do not reuse a cached or clone-time value across scans.
		if !mutableGitRef(ref) {
			rem.refMu.RLock()
			if cachedSHA, ok := rem.refCache[ref]; ok {
				rem.refMu.RUnlock()
				return cachedSHA, nil
			}
			rem.refMu.RUnlock()
		}

		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", refErr
		}

		// Local fast path: if the bare clone already contains this ref (e.g. a
		// pre-populated clone or a prior fetch), resolve it without hitting the network.
		// This is a local-only read so it intentionally bypasses acquireGitProc;
		// the semaphore is acquired below only when a network fetch is needed.
		if !mutableGitRef(ref) {
			if out, localErr := gitInDir(ctx, rem.barePath, "rev-parse", "--verify", safeRef).Output(); localErr == nil {
				if resolved := strings.TrimSpace(string(out)); looksLikeSHA(resolved) {
					rem.refMu.Lock()
					rem.refCache[ref] = resolved
					rem.refMu.Unlock()
					go rem.saveBareRefCache()
					return resolved, nil
				}
			}
		}

		release, acqErr := acquireGitProc(ctx)
		if acqErr != nil {
			return "", acqErr
		}
		defer release()
		// Shallow fetch the named ref.
		out, err := rem.runNetworkGit(ctx, func(remote string, extraConfig []string) *exec.Cmd {
			args := append(append([]string{}, extraConfig...),
				"fetch", "--filter=blob:none", "--depth=1", remote, safeRef)
			return gitInDir(ctx, rem.barePath, args...)
		})
		if err != nil {
			var budgetErr *BudgetExceededError
			if errors.As(err, &budgetErr) {
				return "", fmt.Errorf("git fetch %s %s: %w\n%s", rem.cloneURL, ref, err, bytes.TrimSpace(out))
			}
			// Retry without --depth in case the server rejects shallow fetches.
			out2, err2 := rem.runNetworkGit(ctx, func(remote string, extraConfig []string) *exec.Cmd {
				args := append(append([]string{}, extraConfig...),
					"fetch", "--filter=blob:none", remote, safeRef)
				return gitInDir(ctx, rem.barePath, args...)
			})
			if err2 != nil {
				return "", fmt.Errorf(
					"git fetch %s %s: %w\n%s\n%s",
					rem.cloneURL, ref, err2, bytes.TrimSpace(out), bytes.TrimSpace(out2),
				)
			}
		}
		// Resolve FETCH_HEAD to the commit SHA.
		sha, revErr := gitInDir(ctx, rem.barePath, "rev-parse", "FETCH_HEAD").Output()
		if revErr != nil {
			return "", fmt.Errorf("git rev-parse FETCH_HEAD: %w", revErr)
		}
		resolved := strings.TrimSpace(string(sha))
		if !looksLikeSHA(resolved) {
			return "", fmt.Errorf("unexpected FETCH_HEAD value %q for ref %s", resolved, ref)
		}
		if !mutableGitRef(ref) {
			rem.refMu.Lock()
			rem.refCache[ref] = resolved
			rem.refMu.Unlock()
			go rem.saveBareRefCache()
		}
		return resolved, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func archiveCacheKey(sha string) string {
	h := sha256.Sum256([]byte("sparse-package-v1\x00" + sha))
	// sha[:8] prefix makes the directory human-readable during debugging.
	return sha[:8] + "-" + fmt.Sprintf("%x", h[:4])
}

func archiveCacheDir(extractBase, sha string) string {
	return filepath.Join(extractBase, archiveCacheKey(sha))
}

func archiveMarkerPath(extractBase, sha, subdir string) string {
	h := sha256.Sum256([]byte(filepath.ToSlash(filepath.Clean(subdir))))
	return filepath.Join(extractBase, ".sparse-state", archiveCacheKey(sha), fmt.Sprintf("%x", h[:8]))
}

func cachedArchiveDir(extractBase, sha, subdir string) (string, bool) {
	dest := archiveCacheDir(extractBase, sha)
	info, err := os.Stat(dest)
	if err != nil || !info.IsDir() {
		return "", false
	}
	_, err = os.Stat(archiveMarkerPath(extractBase, sha, subdir))
	return dest, err == nil
}

var archiveMaterializeLocks sync.Map

func archiveMaterializeLock(gitDir, sha string) *sync.Mutex {
	key := filepath.Clean(gitDir) + "\x00" + sha
	lock, _ := archiveMaterializeLocks.LoadOrStore(key, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

type archivePrep struct {
	cmd     *exec.Cmd
	cleanup func()
}

func (p archivePrep) close() {
	if p.cleanup != nil {
		p.cleanup()
	}
}

// archiveCommandFunc prepares git archive invocations against a specific clone.
// SSH may return one command per validated address so a dead first answer can fail over.
type archiveCommandFunc func(ctx context.Context, args []string) ([]archivePrep, error)

func localCloneArchiveCommand(gitDir string) archiveCommandFunc {
	return func(ctx context.Context, args []string) ([]archivePrep, error) {
		return []archivePrep{{cmd: gitInDir(ctx, gitDir, args...)}}, nil
	}
}

// archiveExtract materializes the selected module and its local-module closure
// into a sparse directory whose layout matches the repository at the given SHA.
func archiveExtract(
	ctx context.Context, gitDir, extractBase, sha, subdir string, runArchive archiveCommandFunc,
	objectMu *sync.RWMutex,
) error {
	cleanSubdir, err := cleanArchiveSubdir(subdir)
	if err != nil {
		return err
	}

	lock := archiveMaterializeLock(gitDir, sha)
	lock.Lock()
	defer lock.Unlock()

	key := archiveCacheKey(sha)
	dest := filepath.Join(extractBase, key)
	if _, ok := cachedArchiveDir(extractBase, sha, cleanSubdir); ok {
		return nil
	}
	if err := os.MkdirAll(dest, dirPerm); err != nil {
		return err
	}

	budget := ResourceBudgetFromContext(ctx)
	usage, err := MeasurePackage(ctx, dest, budget.Limits())
	if err != nil {
		return err
	}
	existing, err := snapshotPackageTree(dest)
	if err != nil {
		return err
	}
	stateRoot := filepath.Dir(archiveMarkerPath(extractBase, sha, "."))
	existingState, err := snapshotPackageTree(stateRoot)
	if err != nil {
		return err
	}
	guard, err := newGitObjectGuard(ctx, gitDir, budget)
	if err != nil {
		return err
	}
	extracted := int64(0)
	counter := &PackageCounter{limits: budget.Limits(), usage: usage}
	visited := map[string]bool{}
	if err := materializeModuleClosure(
		ctx, runArchive, sha, dest, extractBase, cleanSubdir, visited, &extracted, counter,
		objectMu, guard,
	); err != nil {
		rollbackPackageTree(dest, existing)
		rollbackPackageTree(stateRoot, existingState)
		return err
	}
	return nil
}

func cleanArchiveSubdir(subdir string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(subdir))
	if clean == "." {
		return clean, nil
	}
	if !filepath.IsLocal(clean) {
		return "", fmt.Errorf("module subdirectory %q is not a local path", subdir)
	}
	return clean, nil
}

func materializeModuleClosure(
	ctx context.Context,
	runArchive archiveCommandFunc,
	sha, packageRoot, extractBase, subdir string,
	visited map[string]bool,
	extracted *int64,
	counter *PackageCounter,
	objectMu *sync.RWMutex,
	guard *gitObjectGuard,
) error {
	if visited[subdir] {
		return nil
	}
	visited[subdir] = true

	marker := archiveMarkerPath(extractBase, sha, subdir)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	if err := extractArchiveSubdir(
		ctx, runArchive, sha, packageRoot, subdir, extracted, counter, objectMu, guard,
	); err != nil {
		return err
	}

	moduleDir := packageRoot
	if subdir != "." {
		moduleDir = filepath.Join(packageRoot, subdir)
	}
	children, err := localModuleArchiveSubdirs(moduleDir, packageRoot)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := materializeModuleClosure(
			ctx, runArchive, sha, packageRoot, extractBase, child, visited, extracted, counter,
			objectMu, guard,
		); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(marker), dirPerm); err != nil {
		return fmt.Errorf("creating sparse archive state: %w", err)
	}
	if err := os.WriteFile(marker, nil, cacheFilePerms); err != nil {
		return fmt.Errorf("marking sparse archive path %q: %w", subdir, err)
	}
	return nil
}

func extractArchiveSubdir(
	ctx context.Context, runArchive archiveCommandFunc, sha, dest, subdir string,
	extracted *int64, counter *PackageCounter, objectMu *sync.RWMutex, guard *gitObjectGuard,
) error {
	release, err := acquireGitProc(ctx)
	if err != nil {
		return err
	}
	defer release()

	archiveArg, argErr := gitSafeArg(sha)
	if argErr != nil {
		return argErr
	}
	archiveArgs := []string{"archive", "--format=tar", archiveArg}
	if subdir != "." {
		archiveArgs = append(archiveArgs, "--", filepath.ToSlash(subdir))
	}
	preps, err := runArchive(ctx, archiveArgs)
	if err != nil {
		return fmt.Errorf("git archive %s path %q: %w", archiveArg, subdir, err)
	}
	var lastErr error
	for _, prep := range preps {
		existing, snapshotErr := snapshotPackageTree(dest)
		if snapshotErr != nil {
			prep.close()
			return snapshotErr
		}
		usageBefore := counter.Usage()
		extractedBefore := *extracted
		if objectMu != nil {
			objectMu.RLock()
		}
		err := extractArchiveCommandWithResourceBudget(
			ctx, prep.cmd, dest, extracted, maxArchiveExtractBytes, counter, guard,
		)
		if objectMu != nil {
			objectMu.RUnlock()
		}
		prep.close()
		if err == nil {
			return nil
		}
		rollbackPackageTree(dest, existing)
		var budgetErr *BudgetExceededError
		if errors.As(err, &budgetErr) && budgetErr.Limit == limitPackageBytes {
			rollbackGitObjects(guard, objectMu)
		}
		counter.usage = usageBefore
		*extracted = extractedBefore
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("git archive %s path %q: no prepared command", archiveArg, subdir)
	}
	return fmt.Errorf("extracting git archive %s: %w", archiveArg, lastErr)
}

// rollbackGitObjects undoes objects fetched lazily by an aborted `git archive`.
// It upgrades to the clone's write lock so no concurrent reader is relying on
// the objects being removed.
func rollbackGitObjects(guard *gitObjectGuard, objectMu *sync.RWMutex) {
	if guard == nil {
		return
	}
	if objectMu != nil {
		objectMu.Lock()
		defer objectMu.Unlock()
	}
	guard.rollback()
}

func extractArchiveCommandWithResourceBudget(
	ctx context.Context, cmd *exec.Cmd, dest string, extracted *int64, maxBytes int64,
	counter *PackageCounter, guard *gitObjectGuard,
) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("opening git archive stream: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting git archive: %w", err)
	}
	stopGuard := guard.watch(ctx, func() { _ = cmd.Process.Kill() })

	stream := &io.LimitedReader{R: stdout, N: maxBytes + 1}
	extractErr := extractRegularFilesWithResourceBudget(stream, dest, extracted, counter)
	if extractErr == nil {
		_, extractErr = io.Copy(io.Discard, stream)
	}
	if extractErr != nil || stream.N == 0 {
		_ = stdout.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if budgetErr := stopGuard(); budgetErr != nil {
			return budgetErr
		}
		if stream.N == 0 {
			return fmt.Errorf("git archive exceeds %d byte limit", maxBytes)
		}
		return extractErr
	}
	waitErr := cmd.Wait()
	if budgetErr := stopGuard(); budgetErr != nil {
		return budgetErr
	}
	if waitErr != nil {
		return fmt.Errorf("running git archive: %w", waitErr)
	}
	return nil
}

func snapshotPackageTree(root string) (map[string]bool, error) {
	paths := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		paths[filepath.Clean(path)] = true
		return nil
	})
	return paths, err
}

func rollbackPackageTree(root string, existing map[string]bool) {
	var added []string
	err := filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !existing[filepath.Clean(path)] {
			added = append(added, path)
		}
		return nil
	})
	if err != nil {
		_ = os.RemoveAll(root)
		return
	}
	sort.Slice(added, func(i, j int) bool {
		return len(added[i]) > len(added[j])
	})
	for _, path := range added {
		if err := os.RemoveAll(path); err != nil {
			_ = os.RemoveAll(root)
			return
		}
	}
}

func extractRegularFilesWithResourceBudget(
	r io.Reader, dest string, extracted *int64, counter *PackageCounter,
) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}
		if *extracted > maxArchiveExtractBytes {
			return fmt.Errorf("git archive exceeds %d byte limit", maxArchiveExtractBytes)
		}
		name := filepath.Clean(header.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("tar entry %q is not a local path", header.Name)
		}
		if err := extractTarEntry(tr, header, dest, name, extracted, counter); err != nil {
			return err
		}
	}
}

func extractTarEntry(
	tr *tar.Reader, header *tar.Header, dest, name string, extracted *int64, counter *PackageCounter,
) error {
	switch header.Typeflag {
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return countArchiveMetadataEntry(counter)
	case tar.TypeDir:
		path := filepath.Join(dest, name)
		if err := countImplicitParentDirs(dest, name, counter); err != nil {
			return err
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if err := countArchiveMetadataEntry(counter); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := os.MkdirAll(path, dirPerm); err != nil {
			return fmt.Errorf("creating directory for tar entry %q: %w", header.Name, err)
		}
		return nil
	case tar.TypeReg:
		return extractTarRegularFile(tr, header, dest, name, extracted, counter)
	case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo, tar.TypeCont:
		return countArchiveMetadataEntry(counter)
	default:
		return fmt.Errorf("tar entry %q has unsupported type %d", header.Name, header.Typeflag)
	}
}

func countArchiveMetadataEntry(counter *PackageCounter) error {
	if counter == nil {
		return nil
	}
	return counter.AddEntry(0)
}

// countImplicitParentDirs charges directories that only exist because a nested
// entry needs them. Archives may omit explicit directory entries, so without
// this the file count would understate what is written to disk.
func countImplicitParentDirs(dest, name string, counter *PackageCounter) error {
	if counter == nil {
		return nil
	}
	parent := filepath.Dir(name)
	if parent == "." || parent == name {
		return nil
	}
	if err := countImplicitParentDirs(dest, parent, counter); err != nil {
		return err
	}
	_, err := os.Lstat(filepath.Join(dest, parent))
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return counter.AddEntry(0)
}

func extractTarRegularFile(
	tr *tar.Reader, header *tar.Header, dest, name string, extracted *int64, counter *PackageCounter,
) error {
	path := filepath.Join(dest, name)
	if header.Size > maxArchiveExtractBytes-*extracted {
		return fmt.Errorf("git archive exceeds %d byte limit", maxArchiveExtractBytes)
	}
	if _, err := os.Lstat(path); err == nil {
		_, discardErr := io.CopyN(io.Discard, tr, header.Size)
		return discardErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := countImplicitParentDirs(dest, name, counter); err != nil {
		return err
	}
	if counter != nil {
		if err := counter.AddEntry(header.Size); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return fmt.Errorf("creating parent for tar entry %q: %w", header.Name, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, header.FileInfo().Mode().Perm()) //nolint:gosec
	if err != nil {
		return fmt.Errorf("creating tar entry %q: %w", header.Name, err)
	}
	_, copyErr := io.CopyN(file, tr, header.Size)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("writing tar entry %q: %w", header.Name, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("closing tar entry %q: %w", header.Name, closeErr)
	}
	*extracted += header.Size
	return nil
}

func localModuleArchiveSubdirs(moduleDir, packageRoot string) ([]string, error) {
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("reading materialized module %q: %w", moduleDir, err)
	}
	seen := make(map[string]bool)
	var children []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".tf") {
			continue
		}
		path := filepath.Join(moduleDir, entry.Name())
		src, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			continue
		}
		for _, source := range localModuleSources(src, path) {
			rel, ok := localArchiveSubdir(moduleDir, packageRoot, source)
			if !ok || seen[rel] {
				continue
			}
			seen[rel] = true
			children = append(children, rel)
		}
	}
	return children, nil
}

func localModuleSources(src []byte, path string) []string {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil
	}
	var sources []string
	for _, block := range body.Blocks {
		if block.Type != "module" {
			continue
		}
		attr := block.Body.Attributes["source"]
		if attr == nil {
			continue
		}
		value, valueDiags := attr.Expr.Value(nil)
		if valueDiags.HasErrors() || !value.IsKnown() || value.IsNull() || value.Type() != cty.String {
			continue
		}
		sources = append(sources, strings.TrimSpace(value.AsString()))
	}
	return sources
}

func localArchiveSubdir(moduleDir, packageRoot, source string) (string, bool) {
	if !tfmodules.LooksLikeLocalModuleSource(source) ||
		filepath.IsAbs(source) || strings.HasPrefix(source, "file://") {
		return "", false
	}
	childPath := filepath.Clean(filepath.Join(moduleDir, filepath.FromSlash(source)))
	rel, err := filepath.Rel(packageRoot, childPath)
	if err != nil || pathEscapesDir(rel) || rel == "." {
		return "", false
	}
	return rel, true
}

func (rem *bareRemote) extract(ctx context.Context, sha, subdir string) (string, error) {
	key := archiveCacheKey(sha) + "\x00" + filepath.Clean(subdir)
	_, err, _ := rem.extractSF.Do(rem.sfKey(key), func() (interface{}, error) {
		return nil, archiveExtract(
			ctx, rem.barePath, rem.extractBase, sha, subdir, rem.archiveCommand,
			&rem.networkMu,
		)
	})
	if err != nil {
		return "", err
	}
	dest := archiveCacheDir(rem.extractBase, sha)
	return dest, nil
}

func (r *BareGitResolver) admitGitEntry(repoEntry string) error {
	if r == nil || r.Budget == nil {
		return nil
	}
	if err := r.Budget.EnsureEntryFits(repoEntry); err != nil {
		return err
	}
	r.Budget.Admit(repoEntry)
	return nil
}

func (r *BareGitResolver) resolveCachedSHAArchive(
	ctx context.Context, remote *bareRemote, repoEntry, ref, subdir string,
) (Resolution, bool, error) {
	if !looksLikeSHA(ref) {
		return Resolution{}, false, nil
	}
	packageRoot, ok := cachedArchiveDir(remote.extractBase, ref, subdir)
	if !ok {
		return Resolution{}, false, nil
	}
	release := r.Budget.Lease(repoEntry)
	if err := r.Budget.EnsureEntryFits(repoEntry); err != nil {
		release()
		return Resolution{}, true, unresolvedResourceError(err)
	}
	resolution, err := ConfineResolution(ctx, Resolution{
		LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
		PackageRoot: packageRoot,
	})
	if err != nil {
		release()
		return Resolution{}, true, err
	}
	return withResolutionCleanup(resolution, release), true, nil
}

func (r *BareGitResolver) resolveRemoteArchive(
	ctx context.Context, remote *bareRemote, repoEntry, repoURL, ref, subdir string,
) (Resolution, error) {
	contextLogger := logger.FromContext(ctx)
	release := r.Budget.Lease(repoEntry)
	if err := remote.ensureClone(ctx); err != nil {
		release()
		return Resolution{}, unresolvedResourceError(err)
	}

	sha, err := remote.fetchRef(ctx, ref)
	if err != nil {
		release()
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: ref %q not reachable from %s", ref, repoURL)
		return Resolution{}, unresolvedResourceError(err)
	}

	packageRoot, err := remote.extract(ctx, sha, subdir)
	if err != nil {
		release()
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: archive %s:%s failed", sha, subdir)
		return Resolution{}, unresolvedResourceError(err)
	}
	if err := r.admitGitEntry(repoEntry); err != nil {
		release()
		return Resolution{}, unresolvedResourceError(err)
	}

	resolution, err := ConfineResolution(ctx, Resolution{
		LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
		PackageRoot: packageRoot,
	})
	if err != nil {
		release()
		return Resolution{}, err
	}
	return withResolutionCleanup(resolution, release), nil
}

// Resolve implements Resolver for pinnable git:: sources. A missing ref uses HEAD.
func (r *BareGitResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	repoURL, subdir, ref, ok := parseGitGetterSource(mod.Source)
	if !ok {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: "BareGitResolver: not a git:: source",
		}
	}
	if ref == "" {
		ref = defaultGitRef
	}
	parsedRepo, parseErr := url.Parse(repoURL)
	if parseErr != nil || parsedRepo.Hostname() == "" {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: "git module source is not a valid remote URL",
		}
	}
	if err := checkGitTransportAllowed(ctx, parsedRepo); err != nil {
		return Resolution{}, err
	}
	if err := checkHostAllowlist(mod.Source, r.hostAllowlist); err != nil {
		return Resolution{}, err
	}

	remote := r.getOrInitRemote(repoURL)
	repoEntry := filepath.Dir(remote.barePath)

	if resolution, ok, err := r.resolveCachedSHAArchive(ctx, remote, repoEntry, ref, subdir); ok {
		return resolution, err
	}

	if _, err := r.policy.resolveHost(ctx, parsedRepo.Hostname()); err != nil {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	return r.resolveRemoteArchive(ctx, remote, repoEntry, repoURL, ref, subdir)
}

// checkGitTransportAllowed accepts only the transports whose destination the
// resolver can pin: HTTPS through the policy proxy, and ssh to a host whose key is
// already known. Credentials embedded in the URL are refused for both.
func checkGitTransportAllowed(ctx context.Context, repo *url.URL) error {
	switch repo.Scheme {
	case httpsScheme:
		if repo.User != nil {
			return &tfmodules.UnresolvedError{
				Reason: "HTTPS git module transport does not accept credentials embedded in the source URL",
			}
		}
		return nil
	case sshScheme:
		if repo.User != nil {
			if _, hasPassword := repo.User.Password(); hasPassword {
				return &tfmodules.UnresolvedError{
					Reason: "ssh git module transport does not accept a password embedded in the source URL",
				}
			}
		}
		if err := checkSSHHostKeyPinned(ctx, sshHostKeyName(repo.Hostname(), repo.Port())); err != nil {
			return &tfmodules.UnresolvedError{Reason: err.Error()}
		}
		return nil
	default:
		return &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf(
				"git module transport %q is disabled because its destination cannot be pinned",
				repo.Scheme,
			),
		}
	}
}

// normalizeSCPGitSource converts SCP-form git sources to git::ssh://git@... so
// BareGitResolver can clone them using the same SSH credentials that would be
// used by a native git client.  HTTPS is intentionally avoided here because SCP
// sources typically point at private repositories that require SSH auth.
//
//	"git@github.com:org/repo//subdir?ref=tag"
//	→ "git::ssh://git@github.com/org/repo//subdir?ref=tag", true
//
// Returns ("", false) if source is not SCP form.
func normalizeSCPGitSource(source string) (string, bool) {
	// Must not already carry a getter scheme prefix.
	if strings.Contains(source, "::") {
		return "", false
	}
	// SCP form: [user@]host:path — @ precedes a colon that comes before any slash.
	atIdx := strings.IndexByte(source, '@')
	if atIdx < 0 {
		return "", false
	}
	user := source[:atIdx]   // e.g. "git"
	rest := source[atIdx+1:] // host:org/repo//subdir?ref=tag
	colonIdx := strings.IndexByte(rest, ':')
	if colonIdx < 0 {
		return "", false
	}
	// Ensure the colon is a host separator, not a path colon (no slash before it).
	if slashIdx := strings.IndexByte(rest, '/'); slashIdx >= 0 && slashIdx < colonIdx {
		return "", false
	}
	host := rest[:colonIdx]
	path := rest[colonIdx+1:] // org/repo//subdir?ref=tag
	return "git::ssh://" + user + "@" + host + "/" + path, true
}

// normalizeImplicitGitHubSource converts Terraform's implicit GitHub module paths to git::https://.
//
//	"github.com/org/repo//subdir?ref=tag"
//	→ "git::https://github.com/org/repo//subdir?ref=tag", true
func normalizeImplicitGitHubSource(source string) (string, bool) {
	if strings.Contains(source, "::") {
		return "", false
	}
	if !strings.HasPrefix(source, "github.com/") {
		return "", false
	}
	// Require a subdir marker or ref= so registry short forms are not matched.
	if !strings.Contains(source, "//") && !strings.Contains(source, "ref=") {
		return "", false
	}
	return "git::https://" + source, true
}

// normalizeGitModuleSourceForGetter applies SCP and implicit GitHub normalization
// without rewriting git::https sources to SSH (go-getter should keep HTTPS).
func normalizeGitModuleSourceForGetter(source string) (string, bool) {
	if source == "" {
		return "", false
	}
	original := source
	if normalized, ok := normalizeSCPGitSource(source); ok {
		source = normalized
	} else if normalized, ok := normalizeImplicitGitHubSource(source); ok {
		source = normalized
	}
	return source, source != original
}

// normalizeGitModuleSource applies git source normalizations used by resolvers.
func normalizeGitModuleSource(source string) (string, bool) {
	if source == "" {
		return "", false
	}
	original := source
	if normalized, ok := normalizeGitModuleSourceForGetter(source); ok {
		source = normalized
	}
	return source, source != original
}

// parseGitGetterSource parses a go-getter git source into its canonical components.
// Sources are normalized via normalizeGitModuleSource before parsing.
//
//	"git::https://github.com/org/repo.git//path/to/mod?ref=abc123"
//	→ repoURL="https://github.com/org/repo.git", subdir="path/to/mod", ref="abc123"
func parseGitGetterSource(source string) (repoURL, subdir, ref string, ok bool) {
	if normalized, changed := normalizeGitModuleSource(source); changed {
		source = normalized
	}
	const prefix = "git::"
	if !strings.HasPrefix(source, prefix) {
		return "", "", "", false
	}
	s := strings.TrimPrefix(source, prefix)

	// Parse query string first (url.Parse handles ? correctly).
	u, err := url.Parse(s)
	if err != nil {
		return "", "", "", false
	}
	ref = u.Query().Get("ref")
	u.RawQuery = ""

	// go-getter separates repo URL from subdir with //. Split on u.Path so we
	// don't accidentally match the // in the URL scheme (e.g. https://).
	if idx := strings.Index(u.Path, "//"); idx >= 0 {
		subdir = u.Path[idx+2:]
		u.Path = u.Path[:idx]
	}

	repoURL = u.String()
	ok = repoURL != ""
	return
}

// normalizeGitRepoURL strips scheme prefixes, trailing .git, and trailing slashes
// so that URLs referring to the same repo compare equal regardless of transport.
//
//	"https://github.com/org/repo.git"  →  "github.com/org/repo"
//	"git@github.com:org/repo.git"      →  "github.com/org/repo"
//	"ssh://git@github.com/org/repo"    →  "github.com/org/repo"
func normalizeGitRepoURL(raw string) string {
	// Strip getter protocol prefix (git::, etc.)
	if idx := strings.Index(raw, "::"); idx != -1 {
		raw = raw[idx+2:]
	}
	// Strip query string.
	if idx := strings.Index(raw, "?"); idx != -1 {
		raw = raw[:idx]
	}
	// Strip the transport scheme BEFORE removing the go-getter subdir separator.
	// Otherwise the "//" in "https://" is mistaken for the subdir marker and the
	// URL collapses to "https:", so https sources never match SCP-form remotes.
	for _, scheme := range []string{"https://", "http://", "ssh://", "git://"} {
		raw = strings.TrimPrefix(raw, scheme)
	}
	// SCP-style git@host:org/repo → host/org/repo
	if at := strings.IndexByte(raw, '@'); at != -1 {
		after := raw[at+1:]
		raw = strings.Replace(after, ":", "/", 1)
	}
	// Strip the go-getter subdir separator, now unambiguous after scheme removal.
	if idx := strings.Index(raw, "//"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSuffix(raw, ".git")
	raw = strings.TrimSuffix(raw, "/")
	return raw
}
