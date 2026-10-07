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

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
)

// dirPerm is the permission mode used for all directories created by resolvers.
const dirPerm = 0o750

// maxArchiveExtractBytes caps cumulative bytes read from a single git archive
// tar stream unless a larger package limit applies.
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
	// writes counts operations that may have changed the clone on disk, so the
	// resolver knows when the cache budget must measure the entry again.
	writes atomic.Uint64

	refMu    sync.RWMutex
	refCache map[string]bareRefEntry // named ref → resolved commit (warm from disk on init)
	saveMu   sync.Mutex              // orders refs.json writes so the newest snapshot lands last
}

// movingRefTTL bounds how long a branch, or any other ref that is not a tag,
// is served from the ref cache before it is fetched again.
const movingRefTTL = 10 * time.Minute

// bareRefEntry records the commit a named ref resolved to. Only tags are
// immutable; a moving entry is refreshed once it is older than movingRefTTL.
type bareRefEntry struct {
	SHA      string    `json:"sha"`
	Moving   bool      `json:"moving,omitempty"`
	Resolved time.Time `json:"resolved"`
}

func (e bareRefEntry) fresh(now time.Time) bool {
	if !looksLikeSHA(e.SHA) {
		return false
	}
	age := now.Sub(e.Resolved)
	return !e.Moving || age >= 0 && age < movingRefTTL
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

// loadBareRefCache reads the persistent ref map for a bare clone. Entries from
// the earlier ref→SHA format carry no ref kind, so they load as moving and
// stale: the next resolution refreshes them, and an offline one still uses them.
func loadBareRefCache(path string) map[string]bareRefEntry {
	refs := make(map[string]bareRefEntry)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return refs
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return refs
	}
	for ref, value := range raw {
		var entry bareRefEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			var legacySHA string
			if json.Unmarshal(value, &legacySHA) != nil {
				continue
			}
			entry = bareRefEntry{SHA: legacySHA, Moving: true}
		}
		if looksLikeSHA(entry.SHA) {
			refs[ref] = entry
		}
	}
	return refs
}

func (repo *bareRepo) refEntry(ref string) (bareRefEntry, bool) {
	repo.refMu.RLock()
	defer repo.refMu.RUnlock()
	entry, ok := repo.refCache[ref]
	return entry, ok
}

func (repo *bareRepo) storeRef(ref string, entry bareRefEntry) {
	repo.refMu.Lock()
	repo.refCache[ref] = entry
	repo.refMu.Unlock()
	repo.saveBareRefCache()
}

// saveBareRefCache replaces refs.json through a private temporary file, so
// concurrent writers in this process or another never interleave their bytes.
func (repo *bareRepo) saveBareRefCache() {
	repo.saveMu.Lock()
	defer repo.saveMu.Unlock()
	repo.refMu.RLock()
	data, err := json.Marshal(repo.refCache)
	repo.refMu.RUnlock()
	if err != nil {
		return
	}
	dir := filepath.Dir(repo.refCachePath)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(repo.refCachePath)+".*.tmp")
	if err != nil {
		return
	}
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if writeErr != nil || closeErr != nil || os.Chmod(tmp.Name(), cacheFilePerms) != nil ||
		os.Rename(tmp.Name(), repo.refCachePath) != nil {
		_ = os.Remove(tmp.Name())
	}
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
	return rem.runNetworkGitThen(ctx, command, nil)
}

// runNetworkGitThen runs after once command succeeds, while the clone is still
// held exclusively, so another fetch cannot replace FETCH_HEAD in between.
func (rem *bareRemote) runNetworkGitThen(
	ctx context.Context, command gitNetworkCommand, after func() error,
) ([]byte, error) {
	rem.networkMu.Lock()
	defer rem.networkMu.Unlock()
	defer rem.writes.Add(1)

	var terminalBudgetErr error
	output := func(cmd *exec.Cmd) ([]byte, error) {
		if terminalBudgetErr != nil {
			return nil, terminalBudgetErr
		}
		objectsDir := filepath.Join(rem.barePath, "objects")
		existing, err := snapshotTree(objectsDir)
		if err != nil {
			return nil, err
		}
		out, err := runGitCommandWithResourceBudget(
			ctx, cmd, rem.barePath, ResourceBudgetFromContext(ctx),
		)
		if err != nil {
			rollbackTree(objectsDir, existing)
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
	if err == nil && after != nil {
		err = after()
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
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Err(lastErr).Msgf("BareGitResolver: failed to clone %s", rem.cloneURL)
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
	if isSSHAuthFailure(out, err) {
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
		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", refErr
		}
		// Local-only read; acquireGitProc is taken only for the network fetch.
		if localReadsStayLocal() && gitLocalInDir(ctx, rem.barePath, "cat-file", "-t", safeRef).Run() == nil {
			return ref, nil // already present
		}
		release, acqErr := acquireGitProc(ctx)
		if acqErr != nil {
			return "", acqErr
		}
		defer release()
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
		var stale bareRefEntry
		if !mutableGitRef(ref) {
			if entry, ok := rem.refEntry(ref); ok {
				if entry.fresh(time.Now()) {
					return entry.SHA, nil
				}
				stale = entry
			}
		}

		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", refErr
		}

		// Local fast path: a tag or abbreviated commit already in the bare clone
		// resolves without the network. Branch heads there are only as recent as
		// the clone, so they are always fetched, including a branch the clone
		// has whose name reads like an abbreviated commit. This is a local-only
		// read so it intentionally bypasses acquireGitProc.
		if local, ok := immutableLocalRev(ref, safeRef); ok && localReadsStayLocal() &&
			(!abbreviatedSHA(ref) || !rem.hasLocalBranch(ctx, safeRef)) {
			if out, localErr := gitLocalInDir(ctx, rem.barePath, "rev-parse", "--verify", local+"^{commit}").Output(); localErr == nil {
				if resolved := strings.TrimSpace(string(out)); looksLikeSHA(resolved) {
					rem.storeRef(ref, bareRefEntry{SHA: resolved, Resolved: time.Now()})
					return resolved, nil
				}
			}
		}

		release, acqErr := acquireGitProc(ctx)
		if acqErr != nil {
			return "", acqErr
		}
		defer release()
		fetched, err := rem.fetchNamedRefFromRemote(ctx, ref, safeRef)
		if err != nil {
			return rem.staleRefFallback(ctx, ref, stale, err)
		}
		if !mutableGitRef(ref) {
			rem.storeRef(ref, fetched)
		}
		return fetched.SHA, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// staleRefFallback serves the commit ref last resolved to when refreshing it
// failed for a reason that may clear up, such as a dropped connection. A ref
// or repository that is gone, or access that is refused, stands: serving the
// old commit would scan content the source no longer has.
func (rem *bareRemote) staleRefFallback(ctx context.Context, ref string, stale bareRefEntry, err error) (string, error) {
	var budgetErr *BudgetExceededError
	if stale.SHA == "" || ctx.Err() != nil || errors.As(err, &budgetErr) || isDestinationDenied(err) ||
		!isTransientFetchError(err) {
		return "", err
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().Err(err).
		Msgf("BareGitResolver: refreshing ref %q of %s failed; using cached commit %s", ref, rem.cloneURL, stale.SHA)
	return stale.SHA, nil
}

// immutableLocalRev names the local ref that ref can only mean when it is a tag
// or an abbreviated commit. Branches and other refs are not served locally.
func immutableLocalRev(ref, safeRef string) (string, bool) {
	switch {
	case mutableGitRef(ref):
		return "", false
	case strings.HasPrefix(ref, "refs/tags/"), abbreviatedSHA(ref):
		return safeRef, true
	case strings.HasPrefix(ref, "refs/"):
		return "", false
	default:
		return "refs/tags/" + safeRef, true
	}
}

// hasLocalBranch reports whether the bare clone has a branch named name.
func (rem *bareRemote) hasLocalBranch(ctx context.Context, name string) bool {
	return gitLocalInDir(ctx, rem.barePath, "show-ref", "--verify", "--quiet", "refs/heads/"+name).Run() == nil
}

func abbreviatedSHA(ref string) bool {
	if len(ref) < 7 || len(ref) >= gitSHALength {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// fetchNamedRefFromRemote shallow-fetches ref, retrying without --depth only
// when the server rejects the shallow fetch itself.
func (rem *bareRemote) fetchNamedRefFromRemote(ctx context.Context, ref, safeRef string) (bareRefEntry, error) {
	var fetched bareRefEntry
	readFetchHead := func() error {
		var err error
		fetched, err = rem.readFetchHead(ctx, ref)
		return err
	}
	out, err := rem.runNetworkGitThen(ctx, func(remote string, extraConfig []string) *exec.Cmd {
		args := append(append([]string{}, extraConfig...),
			"fetch", "--filter=blob:none", "--depth=1", remote, safeRef)
		return gitInDir(ctx, rem.barePath, args...)
	}, readFetchHead)
	if err == nil {
		return fetched, nil
	}
	var budgetErr *BudgetExceededError
	if errors.As(err, &budgetErr) || !isShallowUnsupportedMessage(err.Error()+"\n"+string(out)) {
		return bareRefEntry{}, fmt.Errorf("git fetch %s %s: %w\n%s", rem.cloneURL, ref, err, bytes.TrimSpace(out))
	}
	out2, err2 := rem.runNetworkGitThen(ctx, func(remote string, extraConfig []string) *exec.Cmd {
		args := append(append([]string{}, extraConfig...),
			"fetch", "--filter=blob:none", remote, safeRef)
		return gitInDir(ctx, rem.barePath, args...)
	}, readFetchHead)
	if err2 != nil {
		return bareRefEntry{}, fmt.Errorf(
			"git fetch %s %s: %w\n%s\n%s",
			rem.cloneURL, ref, err2, bytes.TrimSpace(out), bytes.TrimSpace(out2),
		)
	}
	return fetched, nil
}

// readFetchHead resolves the commit a fetch of ref left in FETCH_HEAD, peeling
// annotated tags, and records whether the fetched ref was a tag.
func (rem *bareRemote) readFetchHead(ctx context.Context, ref string) (bareRefEntry, error) {
	sha, err := gitInDir(ctx, rem.barePath, "rev-parse", "--verify", "FETCH_HEAD^{commit}").Output()
	if err != nil {
		return bareRefEntry{}, fmt.Errorf("git rev-parse FETCH_HEAD: %w", err)
	}
	resolved := strings.TrimSpace(string(sha))
	if !looksLikeSHA(resolved) {
		return bareRefEntry{}, fmt.Errorf("unexpected FETCH_HEAD value %q for ref %s", resolved, ref)
	}
	head, err := os.ReadFile(filepath.Join(rem.barePath, "FETCH_HEAD"))
	if err != nil {
		return bareRefEntry{}, fmt.Errorf("reading FETCH_HEAD: %w", err)
	}
	return bareRefEntry{SHA: resolved, Moving: !fetchedTag(head), Resolved: time.Now()}, nil
}

// fetchedTag reports whether FETCH_HEAD records a tag. Its lines read
// "<sha>\t<not-for-merge>\t<kind> '<name>' of <url>", where kind is "branch",
// "tag", or empty for any other ref.
func fetchedTag(fetchHead []byte) bool {
	line, _, _ := bytes.Cut(fetchHead, []byte("\n"))
	fields := bytes.SplitN(line, []byte("\t"), 3)
	return len(fields) == 3 && bytes.HasPrefix(fields[2], []byte("tag '"))
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

// localCloneArchiveCommand reads from the scanned checkout. Lazy fetches are
// disabled so a partial checkout falls through to BareGitResolver, which applies
// the destination policy, instead of reaching the checkout's own remote.
func localCloneArchiveCommand(gitDir string) archiveCommandFunc {
	return func(ctx context.Context, args []string) ([]archivePrep, error) {
		return []archivePrep{{cmd: gitLocalInDir(ctx, gitDir, args...)}}, nil
	}
}

// archiveExtract materializes the selected module and its local-module closure
// into a sparse directory whose layout matches the repository at the given SHA.
// It returns the bytes it added under extractBase.
func archiveExtract(
	ctx context.Context, gitDir, extractBase, sha, subdir string, runArchive archiveCommandFunc,
	objectMu *sync.RWMutex,
) (int64, error) {
	cleanSubdir, err := cleanArchiveSubdir(subdir)
	if err != nil {
		return 0, err
	}
	// A marker is only written once its whole closure is on disk, so a hit does
	// not have to wait behind another subdirectory being materialized.
	if _, ok := cachedArchiveDir(extractBase, sha, cleanSubdir); ok {
		return 0, nil
	}

	lock := archiveMaterializeLock(gitDir, sha)
	lock.Lock()
	defer lock.Unlock()

	dest := archiveCacheDir(extractBase, sha)
	if _, ok := cachedArchiveDir(extractBase, sha, cleanSubdir); ok {
		return 0, nil
	}
	if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
		forgetArchiveUsage(dest)
	}
	if err := os.MkdirAll(dest, dirPerm); err != nil {
		return 0, err
	}

	budget := ResourceBudgetFromContext(ctx)
	usage, err := archiveBaselineUsage(ctx, dest, budget.Limits())
	if err != nil {
		return 0, err
	}
	// Only clones owned by the resolver fetch objects lazily; guarding any other
	// repository would scan, and on rollback delete from, a store we do not own.
	var guard *gitObjectGuard
	if objectMu != nil {
		guard, err = newGitObjectGuard(ctx, gitDir, budget)
		if err != nil {
			return 0, err
		}
	}
	archive := &sparseArchive{
		runArchive:  runArchive,
		sha:         sha,
		dest:        dest,
		extractBase: extractBase,
		counter:     &PackageCounter{limits: budget.Limits(), usage: usage},
		objectMu:    objectMu,
		guard:       guard,
		visited:     map[string]bool{},
	}
	if err := archive.materialize(ctx, cleanSubdir); err != nil {
		archive.discard()
		return 0, err
	}
	storeArchiveUsage(dest, PackageUsage{
		Bytes: usage.Bytes + archive.written.usage.Bytes,
		Files: usage.Files + archive.written.usage.Files,
	})
	return archive.written.usage.Bytes + archive.markers.usage.Bytes, nil
}

func archiveBaselineUsage(ctx context.Context, dest string, limits ResourceLimits) (PackageUsage, error) {
	if usage, ok := knownArchiveUsage(dest); ok {
		return usage, CheckPackageUsage(usage, limits)
	}
	return MeasurePackage(ctx, dest, limits)
}

// sparseArchive is one archiveExtract call materializing a module closure into
// the shared per-SHA tree. It records everything it creates so a failure undoes
// exactly its own writes.
type sparseArchive struct {
	runArchive  archiveCommandFunc
	sha         string
	dest        string
	extractBase string
	counter     *PackageCounter
	objectMu    *sync.RWMutex
	guard       *gitObjectGuard
	extracted   int64
	visited     map[string]bool
	unmarked    []string
	written     archiveWrites
	markers     archiveWrites
}

func (a *sparseArchive) materialize(ctx context.Context, subdir string) error {
	if err := a.materializeClosure(ctx, subdir); err != nil {
		return err
	}
	for _, extracted := range a.unmarked {
		marker := archiveMarkerPath(a.extractBase, a.sha, extracted)
		if err := a.markers.mkdirAll(filepath.Dir(marker)); err != nil {
			return fmt.Errorf("creating sparse archive state: %w", err)
		}
		a.markers.addFile(marker, 0)
		if err := os.WriteFile(marker, nil, cacheFilePerms); err != nil {
			return fmt.Errorf("marking sparse archive path %q: %w", extracted, err)
		}
	}
	return nil
}

// discard undoes this call's writes. If that fails the tree no longer matches
// its markers, so the whole cache entry is dropped instead.
func (a *sparseArchive) discard() {
	// Markers go first so none outlives the files it vouches for. Files are only
	// renamed into place complete, so whatever cannot be removed is still correct
	// for this commit and stays for other modules sharing the tree; only the
	// recorded usage no longer matches the disk.
	if err := a.markers.rollback(); err != nil {
		forgetArchiveUsage(a.dest)
		return
	}
	if err := a.written.rollback(); err != nil {
		forgetArchiveUsage(a.dest)
	}
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

func (a *sparseArchive) materializeClosure(ctx context.Context, subdir string) error {
	if a.visited[subdir] {
		return nil
	}
	a.visited[subdir] = true

	if _, err := os.Stat(archiveMarkerPath(a.extractBase, a.sha, subdir)); err == nil {
		return nil
	}
	if err := a.extract(ctx, subdir); err != nil {
		return err
	}
	a.unmarked = append(a.unmarked, subdir)

	moduleDir := a.dest
	if subdir != "." {
		moduleDir = filepath.Join(a.dest, subdir)
	}
	children, err := localModuleArchiveSubdirs(ctx, moduleDir, a.dest)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := a.materializeClosure(ctx, child); err != nil {
			return err
		}
	}
	return nil
}

func (a *sparseArchive) extract(ctx context.Context, subdir string) error {
	release, err := acquireGitProc(ctx)
	if err != nil {
		return err
	}
	defer release()

	archiveArg, argErr := gitSafeArg(a.sha)
	if argErr != nil {
		return argErr
	}
	archiveArgs := []string{"archive", "--format=tar", archiveArg}
	if subdir != "." {
		archiveArgs = append(archiveArgs, "--", filepath.ToSlash(subdir))
	}
	preps, err := a.runArchive(ctx, archiveArgs)
	if err != nil {
		return fmt.Errorf("git archive %s path %q: %w", archiveArg, subdir, err)
	}
	var lastErr error
	for i, prep := range preps {
		usageBefore := a.counter.Usage()
		extractedBefore := a.extracted
		attempt := &archiveWrites{}
		if a.objectMu != nil {
			a.objectMu.RLock()
		}
		err := extractArchiveCommandWithResourceBudget(
			ctx, prep.cmd, a.dest, &a.extracted, a.counter.archiveStreamLimit(), a.counter, a.guard, attempt,
		)
		if a.objectMu != nil {
			a.objectMu.RUnlock()
		}
		prep.close()
		if err == nil {
			a.written.merge(attempt)
			return nil
		}
		var budgetErr *BudgetExceededError
		if errors.As(err, &budgetErr) && budgetErr.Limit == limitPackageBytes {
			rollbackGitObjects(a.guard, a.objectMu)
		}
		if rollbackErr := attempt.rollback(); rollbackErr != nil {
			a.written.merge(attempt)
			for _, remaining := range preps[i+1:] {
				remaining.close()
			}
			return fmt.Errorf("extracting git archive %s: %w (rollback: %v)", archiveArg, err, rollbackErr)
		}
		a.counter.usage = usageBefore
		a.extracted = extractedBefore
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
	counter *PackageCounter, guard *gitObjectGuard, written *archiveWrites,
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
	extractErr := extractRegularFilesWithResourceBudget(stream, dest, extracted, counter, written)
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

func snapshotTree(root string) (map[string]bool, error) {
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

func rollbackTree(root string, existing map[string]bool) {
	var added []string
	err := filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) {
			return nil
		}
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
	r io.Reader, dest string, extracted *int64, counter *PackageCounter, written *archiveWrites,
) error {
	tr := tar.NewReader(r)
	limit := counter.archiveContentLimit()
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}
		if *extracted > limit {
			return fmt.Errorf("git archive exceeds %d byte limit", limit)
		}
		name := filepath.Clean(header.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("tar entry %q is not a local path", header.Name)
		}
		if err := extractTarEntry(tr, header, dest, name, extracted, counter, written); err != nil {
			return err
		}
	}
}

func extractTarEntry(
	tr *tar.Reader, header *tar.Header, dest, name string, extracted *int64, counter *PackageCounter,
	written *archiveWrites,
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
		if err := written.mkdirAll(path); err != nil {
			return fmt.Errorf("creating directory for tar entry %q: %w", header.Name, err)
		}
		return nil
	case tar.TypeReg:
		return extractTarRegularFile(tr, header, dest, name, extracted, counter, written)
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
	written *archiveWrites,
) error {
	path := filepath.Join(dest, name)
	if limit := counter.archiveContentLimit(); header.Size > limit-*extracted {
		return fmt.Errorf("git archive exceeds %d byte limit", limit)
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
	if err := written.mkdirAll(filepath.Dir(path)); err != nil {
		return fmt.Errorf("creating parent for tar entry %q: %w", header.Name, err)
	}
	// Other modules may read the shared tree without the lock, so an entry only
	// appears under its name once it is complete.
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.partial")
	if err != nil {
		return fmt.Errorf("creating tar entry %q: %w", header.Name, err)
	}
	_, copyErr := io.CopyN(temp, tr, header.Size)
	writeErr := errors.Join(copyErr, temp.Close())
	if writeErr == nil {
		writeErr = os.Chmod(temp.Name(), header.FileInfo().Mode().Perm())
	}
	if writeErr == nil {
		writeErr = os.Rename(temp.Name(), path)
	}
	if writeErr != nil {
		_ = os.Remove(temp.Name())
		return fmt.Errorf("writing tar entry %q: %w", header.Name, writeErr)
	}
	written.addFile(path, header.Size)
	*extracted += header.Size
	return nil
}

func localModuleArchiveSubdirs(ctx context.Context, moduleDir, packageRoot string) ([]string, error) {
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("reading materialized module %q: %w", moduleDir, err)
	}
	seen := make(map[string]bool)
	var children []string
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	maxConfigBytes := tfmodules.MaxConfigFileBytesFromContext(ctx)
	for _, name := range tfpath.Select(names, tfpath.IsConfig) {
		path := filepath.Join(moduleDir, name)
		if tfmodules.ConfigFileTooLarge(path, maxConfigBytes) {
			continue
		}
		src, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			continue
		}
		for _, source := range configModuleSources(src, path) {
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

// configModuleSources returns the literal module sources a configuration file
// declares, in native or JSON syntax.
func configModuleSources(src []byte, path string) []string {
	if tfpath.IsJSONConfig(path) {
		return jsonModuleSources(src)
	}
	return localModuleSources(src, path)
}

// jsonModuleSources reads the "module" object of a JSON configuration file.
// Sources with template sequences are not literal, as in native syntax.
func jsonModuleSources(src []byte) []string {
	var root struct {
		Module map[string]json.RawMessage `json:"module"`
	}
	if json.Unmarshal(src, &root) != nil {
		return nil
	}
	sources := make([]string, 0, len(root.Module))
	for _, body := range root.Module {
		var attrs struct {
			Source string `json:"source"`
		}
		if json.Unmarshal(body, &attrs) != nil || attrs.Source == "" || strings.Contains(attrs.Source, "${") {
			continue
		}
		sources = append(sources, strings.TrimSpace(attrs.Source))
	}
	sort.Strings(sources)
	return sources
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
		if valueDiags.HasErrors() {
			continue
		}
		source, ok := ctyutil.ConcreteString(value)
		if !ok {
			continue
		}
		sources = append(sources, strings.TrimSpace(source))
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
	if err != nil || pathutil.PathEscapesDir(rel) || rel == "." {
		return "", false
	}
	return rel, true
}

func (rem *bareRemote) extract(ctx context.Context, sha, subdir string) (string, error) {
	key := archiveCacheKey(sha) + "\x00" + filepath.Clean(subdir)
	_, err, _ := rem.extractSF.Do(rem.sfKey(key), func() (interface{}, error) {
		written, extractErr := archiveExtract(
			ctx, rem.barePath, rem.extractBase, sha, subdir, rem.archiveCommand,
			&rem.networkMu,
		)
		// Extraction can also fetch missing blobs into the clone, whose size is
		// not reported, so any write marks the whole entry for measurement.
		if written != 0 || extractErr != nil {
			rem.writes.Add(1)
		}
		return nil, extractErr
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

// resolveCachedArchive serves a pinned SHA, or a named ref already mapped to
// one, from an extracted archive without touching the network. allowStale also
// serves a moving ref past movingRefTTL, for when the remote is unreachable.
func (r *BareGitResolver) resolveCachedArchive(
	ctx context.Context, remote *bareRemote, repoEntry, ref, subdir string, allowStale bool,
) (Resolution, bool, error) {
	sha, ok := remote.cachedSHA(ref, allowStale)
	if !ok {
		return Resolution{}, false, nil
	}
	packageRoot, ok := cachedArchiveDir(remote.extractBase, sha, subdir)
	if !ok {
		return Resolution{}, false, nil
	}
	release := r.Budget.Lease(repoEntry)
	if err := r.Budget.EnsureEntryFits(repoEntry); err != nil {
		release()
		return Resolution{}, true, unresolvedResourceError(err)
	}
	resolution, err := ConfineResolution(ctx, &Resolution{
		LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
		PackageRoot: packageRoot,
		Usage:       archiveUsageHint(packageRoot),
		ResolvedRef: sha,
		Origin:      "git",
	})
	if err != nil {
		release()
		return Resolution{}, true, err
	}
	return withResolutionCleanup(&resolution, release), true, nil
}

func (rem *bareRemote) cachedSHA(ref string, allowStale bool) (string, bool) {
	if looksLikeSHA(ref) {
		return ref, true
	}
	if mutableGitRef(ref) {
		return "", false
	}
	entry, ok := rem.refEntry(ref)
	if !ok || !looksLikeSHA(entry.SHA) {
		return "", false
	}
	return entry.SHA, allowStale || entry.fresh(time.Now())
}

func (r *BareGitResolver) resolveRemoteArchive(
	ctx context.Context, remote *bareRemote, repoEntry, repoURL, ref, subdir string,
) (Resolution, error) {
	contextLogger := logger.FromContext(ctx)
	release := r.Budget.Lease(repoEntry)
	writes := remote.writes.Load()
	invalidateIfWritten := func() {
		if remote.writes.Load() != writes {
			r.Budget.Invalidate(repoEntry)
		}
	}
	if err := remote.ensureClone(ctx); err != nil {
		invalidateIfWritten()
		release()
		return Resolution{}, unresolvedResourceError(err)
	}

	sha, err := remote.fetchRef(ctx, ref)
	if err != nil {
		invalidateIfWritten()
		release()
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: ref %q not reachable from %s", ref, repoURL)
		return Resolution{}, unresolvedResourceError(err)
	}

	packageRoot, err := remote.extract(ctx, sha, subdir)
	if err != nil {
		invalidateIfWritten()
		release()
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: archive %s:%s failed", sha, subdir)
		return Resolution{}, unresolvedResourceError(err)
	}
	invalidateIfWritten()
	if err := r.admitGitEntry(repoEntry); err != nil {
		release()
		return Resolution{}, unresolvedResourceError(err)
	}

	resolution, err := ConfineResolution(ctx, &Resolution{
		LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
		PackageRoot: packageRoot,
		Usage:       archiveUsageHint(packageRoot),
		ResolvedRef: sha,
		Origin:      "git",
	})
	if err != nil {
		release()
		return Resolution{}, err
	}
	return withResolutionCleanup(&resolution, release), nil
}

// bareGitSource is a git:: source BareGitResolver has admitted: parsed, on an
// allowed transport, and on an allowed host.
type bareGitSource struct {
	repoURL, subdir, ref string
	parsed               *url.URL
}

func (r *BareGitResolver) admit(ctx context.Context, mod *tfmodules.ParsedModule) (bareGitSource, error) {
	repoURL, subdir, ref, ok := parseGitGetterSource(mod.Source)
	if !ok {
		return bareGitSource{}, notApplicable("BareGitResolver: not a git:: source")
	}
	if ref == "" {
		ref = defaultGitRef
	}
	parsedRepo, parseErr := url.Parse(repoURL)
	if parseErr != nil || parsedRepo.Hostname() == "" {
		return bareGitSource{}, &tfmodules.UnresolvedError{
			Reason: "git module source is not a valid remote URL",
		}
	}
	if err := checkGitTransportAllowed(ctx, parsedRepo); err != nil {
		return bareGitSource{}, err
	}
	if err := checkHostAllowlist(mod.Source, r.hostAllowlist); err != nil {
		return bareGitSource{}, err
	}
	return bareGitSource{repoURL: repoURL, subdir: subdir, ref: ref, parsed: parsedRepo}, nil
}

func (r *BareGitResolver) Screen(ctx context.Context, mod *tfmodules.ParsedModule) error {
	_, err := r.admit(ctx, mod)
	return err
}

// Resolve implements Resolver for pinnable git:: sources. A missing ref uses HEAD.
func (r *BareGitResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	source, err := r.admit(ctx, mod)
	if err != nil {
		return Resolution{}, err
	}
	remote := r.getOrInitRemote(source.repoURL)
	repoEntry := filepath.Dir(remote.barePath)

	if resolution, ok, err := r.resolveCachedArchive(ctx, remote, repoEntry, source.ref, source.subdir, false); ok {
		return resolution, err
	}

	if _, err := r.policy.resolveHost(ctx, source.parsed.Hostname()); err != nil {
		// A stale commit only stands in for an unreachable host; a destination
		// the policy denies stays denied even when an older copy is cached.
		if !isDestinationDenied(err) {
			if resolution, ok, cachedErr := r.resolveCachedArchive(
				ctx, remote, repoEntry, source.ref, source.subdir, true,
			); ok {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Warn().Err(err).Msgf(
					"BareGitResolver: %s is unreachable; using the cached commit for ref %q",
					source.parsed.Hostname(), source.ref,
				)
				return resolution, cachedErr
			}
		}
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	return r.resolveRemoteArchive(ctx, remote, repoEntry, source.repoURL, source.ref, source.subdir)
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
			return &tfmodules.UnresolvedError{Reason: err.Error(), NotApplicable: true}
		}
		return nil
	default:
		return &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf(
				"git module transport %q is disabled because its destination cannot be pinned",
				repo.Scheme,
			),
			NotApplicable: true,
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
	// Extra slashes after the separator ("repo///sub") still name a path under
	// the package root, as they do for go-getter.
	if idx := strings.Index(u.Path, "//"); idx >= 0 {
		subdir = strings.TrimLeft(u.Path[idx+2:], "/")
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
