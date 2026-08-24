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
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

	hostAllowlist []string
	mu            sync.Mutex
	repos         map[string]*bareRepo
}

const bareCloneAttempts = 3

type bareRepo struct {
	cloneURL     string // canonical ssh:// URL passed to git clone
	barePath     string // path to the bare clone on disk
	extractBase  string // base dir for per-(sha,subdir) extracted trees
	refCachePath string // path to the persistent ref→SHA JSON file

	cloneOK     atomic.Bool
	cloneFailed atomic.Bool
	cloneErrMu  sync.Mutex
	cloneErr    error
	cloneSF     singleflight.Group
	fetchSF     singleflight.Group
	extractSF   singleflight.Group

	refMu    sync.RWMutex
	refCache map[string]string // tag/branch ref → resolved SHA (warm from disk on init)
}

func NewBareGitResolver(cacheDir string, hostAllowlist ...string) *BareGitResolver {
	return &BareGitResolver{
		CacheDir:      cacheDir,
		hostAllowlist: hostAllowlist,
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

// canonicalSSHCloneURL builds a stable ssh:// clone URL for a parsed repo URL.
func canonicalSSHCloneURL(repoURL string) string {
	norm := normalizeGitRepoURL(repoURL)
	if norm == "" {
		return repoURL
	}
	return "ssh://git@" + norm
}

func (r *BareGitResolver) getOrInitRepo(repoURL string) *bareRepo {
	key := normalizeGitRepoURL(repoURL)
	r.mu.Lock()
	defer r.mu.Unlock()
	if repo, ok := r.repos[key]; ok {
		return repo
	}
	base := filepath.Join(r.effectiveCacheDir(), repoURLKey(key))
	refCachePath := filepath.Join(base, "refs.json")
	repo := &bareRepo{
		cloneURL:     canonicalSSHCloneURL(repoURL),
		barePath:     filepath.Join(base, "repo.git"),
		extractBase:  filepath.Join(base, "extracted"),
		refCachePath: refCachePath,
		refCache:     loadBareRefCache(refCachePath),
	}
	r.repos[key] = repo
	return repo
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

func (repo *bareRepo) cachedCloneError() error {
	repo.cloneErrMu.Lock()
	defer repo.cloneErrMu.Unlock()
	return repo.cloneErr
}

func (repo *bareRepo) setCloneError(err error) {
	repo.cloneErrMu.Lock()
	repo.cloneErr = err
	repo.cloneErrMu.Unlock()
	repo.cloneFailed.Store(true)
}

func (repo *bareRepo) ensureClone(ctx context.Context) error {
	if repo.cloneOK.Load() {
		return nil
	}
	if repo.cloneFailed.Load() {
		return repo.cachedCloneError()
	}
	_, err, _ := repo.cloneSF.Do("clone", func() (interface{}, error) {
		if repo.cloneOK.Load() {
			return nil, nil
		}
		if repo.cloneFailed.Load() {
			return nil, repo.cachedCloneError()
		}
		return nil, repo.doClone(ctx)
	})
	return err
}

// doClone checks for an existing bare clone, validates it, and attempts a fresh
// clone with retries if needed. It is always called inside the cloneSF singleflight.
func (repo *bareRepo) doClone(ctx context.Context) error {
	if info, err := os.Stat(repo.barePath); err == nil && info.IsDir() {
		// Validate that the directory is a real bare repo, not a partial clone
		// left by a killed process. This is a local-only read (no network, no
		// pack-file I/O) so it intentionally bypasses the acquireGitProc semaphore,
		// which is reserved for operations that meaningfully consume system resources.
		if gitInDir(ctx, repo.barePath, "rev-parse", "--git-dir").Run() == nil {
			repo.cloneOK.Store(true)
			return nil
		}
		// Partial or corrupt clone — remove and reclone.
		_ = os.RemoveAll(repo.barePath)
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
		if err := os.MkdirAll(filepath.Dir(repo.barePath), dirPerm); err != nil {
			lastErr = err
			continue
		}
		_ = os.RemoveAll(repo.barePath)
		release, err := acquireGitProc(ctx)
		if err != nil {
			lastErr = err
			continue
		}
		cloneURL, urlErr := gitSafeArg(repo.cloneURL)
		if urlErr != nil {
			lastErr = urlErr
			continue
		}
		cmd := gitCloneBare(ctx, cloneURL, repo.barePath)
		out, cloneErr := cmd.CombinedOutput()
		release()
		if cloneErr == nil {
			repo.cloneOK.Store(true)
			return nil
		}
		_ = os.RemoveAll(repo.barePath)
		lastErr = fmt.Errorf("git clone --bare %s: %w\n%s", repo.cloneURL, cloneErr, bytes.TrimSpace(out))
	}
	repo.setCloneError(lastErr)
	log := logger.FromContext(ctx)
	log.Warn().Err(lastErr).Msgf("BareGitResolver: failed to clone %s after %d attempts", repo.cloneURL, bareCloneAttempts)
	return lastErr
}

// fetchRef ensures ref is present and returns its canonical commit SHA.
func (repo *bareRepo) fetchRef(ctx context.Context, ref string) (string, error) {
	if looksLikeSHA(ref) {
		return repo.fetchSHARef(ctx, ref)
	}
	return repo.fetchNamedRef(ctx, ref)
}

// fetchSHARef handles the case where ref is already a full 40-char SHA.
// It checks that the object is locally present, fetching it from origin if not.
func (repo *bareRepo) fetchSHARef(ctx context.Context, ref string) (string, error) {
	v, err, _ := repo.fetchSF.Do(ref, func() (interface{}, error) {
		release, acqErr := acquireGitProc(ctx)
		if acqErr != nil {
			return "", acqErr
		}
		defer release()
		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", refErr
		}
		if gitInDir(ctx, repo.barePath, "cat-file", "-t", safeRef).Run() == nil {
			return ref, nil // already present
		}
		cmd := gitInDir(ctx, repo.barePath, "fetch", "--filter=blob:none", "origin", safeRef)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("git fetch origin %s: %w\n%s", ref, err, bytes.TrimSpace(out))
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
func (repo *bareRepo) fetchNamedRef(ctx context.Context, ref string) (string, error) {
	// Key on "ref:<name>" so SHA keys and name keys never collide in fetchSF.
	v, err, _ := repo.fetchSF.Do("ref:"+ref, func() (interface{}, error) {
		// In-process cache: skip the network if we resolved this ref earlier.
		repo.refMu.RLock()
		if cachedSHA, ok := repo.refCache[ref]; ok {
			repo.refMu.RUnlock()
			return cachedSHA, nil
		}
		repo.refMu.RUnlock()

		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", refErr
		}

		// Local fast path: if the bare clone already contains this ref (e.g. a
		// pre-populated clone or a prior fetch), resolve it without hitting the network.
		// This is a local-only read so it intentionally bypasses acquireGitProc;
		// the semaphore is acquired below only when a network fetch is needed.
		if out, localErr := gitInDir(ctx, repo.barePath, "rev-parse", "--verify", safeRef).Output(); localErr == nil {
			if resolved := strings.TrimSpace(string(out)); looksLikeSHA(resolved) {
				repo.refMu.Lock()
				repo.refCache[ref] = resolved
				repo.refMu.Unlock()
				go repo.saveBareRefCache()
				return resolved, nil
			}
		}

		release, acqErr := acquireGitProc(ctx)
		if acqErr != nil {
			return "", acqErr
		}
		defer release()
		// Shallow fetch the named ref.
		cmd := gitInDir(ctx, repo.barePath, "fetch", "--filter=blob:none", "--depth=1", "origin", safeRef)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Retry without --depth in case the server rejects shallow fetches.
			cmd2 := gitInDir(ctx, repo.barePath, "fetch", "--filter=blob:none", "origin", safeRef)
			if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
				return "", fmt.Errorf("git fetch origin %s: %w\n%s\n%s", ref, err2, bytes.TrimSpace(out), bytes.TrimSpace(out2))
			}
		}
		// Resolve FETCH_HEAD to the commit SHA.
		sha, revErr := gitInDir(ctx, repo.barePath, "rev-parse", "FETCH_HEAD").Output()
		if revErr != nil {
			return "", fmt.Errorf("git rev-parse FETCH_HEAD: %w", revErr)
		}
		resolved := strings.TrimSpace(string(sha))
		if !looksLikeSHA(resolved) {
			return "", fmt.Errorf("unexpected FETCH_HEAD value %q for ref %s", resolved, ref)
		}
		// Persist synchronously so subsequent in-process callers skip the fetch too,
		// then write to disk in the background (non-critical).
		repo.refMu.Lock()
		repo.refCache[ref] = resolved
		repo.refMu.Unlock()
		go repo.saveBareRefCache()
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

// archiveExtract materializes the selected module and its local-module closure
// into a sparse directory whose layout matches the repository at the given SHA.
func archiveExtract(ctx context.Context, gitDir, extractBase, sha, subdir string) error {
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

	extracted := int64(0)
	if err := materializeModuleClosure(ctx, gitDir, sha, dest, extractBase, cleanSubdir, map[string]bool{}, &extracted); err != nil {
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
	gitDir, sha, packageRoot, extractBase, subdir string,
	visited map[string]bool,
	extracted *int64,
) error {
	if visited[subdir] {
		return nil
	}
	visited[subdir] = true

	marker := archiveMarkerPath(extractBase, sha, subdir)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	if err := extractArchiveSubdir(ctx, gitDir, sha, packageRoot, subdir, extracted); err != nil {
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
			ctx, gitDir, sha, packageRoot, extractBase, child, visited, extracted,
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
	ctx context.Context, gitDir, sha, dest, subdir string, extracted *int64,
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
	archive := gitInDir(ctx, gitDir, archiveArgs...)
	if err := extractArchiveCommand(archive, dest, extracted); err != nil {
		return fmt.Errorf("extracting git archive %s: %w", archiveArg, err)
	}
	return nil
}

func extractArchiveCommand(cmd *exec.Cmd, dest string, extracted *int64) error {
	return extractArchiveCommandWithLimit(cmd, dest, extracted, maxArchiveExtractBytes)
}

func extractArchiveCommandWithLimit(cmd *exec.Cmd, dest string, extracted *int64, maxBytes int64) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("opening git archive stream: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting git archive: %w", err)
	}

	stream := &io.LimitedReader{R: stdout, N: maxBytes + 1}
	extractErr := extractRegularFilesWithBudget(stream, dest, extracted)
	if extractErr == nil {
		_, extractErr = io.Copy(io.Discard, stream)
	}
	if extractErr != nil || stream.N == 0 {
		_ = stdout.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if stream.N == 0 {
			return fmt.Errorf("git archive exceeds %d byte limit", maxBytes)
		}
		return extractErr
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("running git archive: %w", err)
	}
	return nil
}

func extractRegularFilesWithBudget(r io.Reader, dest string, extracted *int64) error {
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
		if name == "." || !filepath.IsLocal(name) {
			return fmt.Errorf("tar entry %q is not a local path", header.Name)
		}
		if err := extractTarEntry(tr, header, dest, name, extracted); err != nil {
			return err
		}
	}
}

func extractTarEntry(
	tr *tar.Reader, header *tar.Header, dest, name string, extracted *int64,
) error {
	switch header.Typeflag {
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return nil
	case tar.TypeDir:
		if err := os.MkdirAll(filepath.Join(dest, name), dirPerm); err != nil {
			return fmt.Errorf("creating directory for tar entry %q: %w", header.Name, err)
		}
		return nil
	case tar.TypeReg:
		return extractTarRegularFile(tr, header, filepath.Join(dest, name), extracted)
	case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo, tar.TypeCont:
		return nil
	default:
		return fmt.Errorf("tar entry %q has unsupported type %d", header.Name, header.Typeflag)
	}
}

func extractTarRegularFile(
	tr *tar.Reader, header *tar.Header, path string, extracted *int64,
) error {
	if header.Size > maxArchiveExtractBytes-*extracted {
		return fmt.Errorf("git archive exceeds %d byte limit", maxArchiveExtractBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return fmt.Errorf("creating parent for tar entry %q: %w", header.Name, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, header.FileInfo().Mode().Perm()) //nolint:gosec
	if err != nil {
		return fmt.Errorf("creating tar entry %q: %w", header.Name, err)
	}
	_, copyErr := io.CopyN(file, tr, header.Size)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("writing tar entry %q: %w", header.Name, copyErr)
	}
	if closeErr != nil {
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

func (repo *bareRepo) extract(ctx context.Context, sha, subdir string) (string, error) {
	key := archiveCacheKey(sha) + "\x00" + filepath.Clean(subdir)
	_, err, _ := repo.extractSF.Do(key, func() (interface{}, error) {
		return nil, archiveExtract(ctx, repo.barePath, repo.extractBase, sha, subdir)
	})
	if err != nil {
		return "", err
	}
	return archiveCacheDir(repo.extractBase, sha), nil
}

// Resolve implements Resolver for any git:: source that carries a ref= parameter.
func (r *BareGitResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	repoURL, subdir, ref, ok := parseGitGetterSource(mod.Source)
	if !ok || ref == "" {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: "BareGitResolver: not a git:: source with a ref= parameter",
		}
	}
	if err := checkHostAllowlist(mod.Source, r.hostAllowlist); err != nil {
		return Resolution{}, err
	}

	contextLogger := logger.FromContext(ctx)
	repo := r.getOrInitRepo(repoURL)

	// SHA refs have stable extraction keys; branch/tag refs must be re-resolved.
	if looksLikeSHA(ref) {
		if packageRoot, ok := cachedArchiveDir(repo.extractBase, ref, subdir); ok {
			return ConfineResolution(ctx, Resolution{
				LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
				PackageRoot: packageRoot,
			})
		}
	}

	if err := repo.ensureClone(ctx); err != nil {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	sha, err := repo.fetchRef(ctx, ref)
	if err != nil {
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: ref %q not reachable from %s", ref, repoURL)
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	packageRoot, err := repo.extract(ctx, sha, subdir)
	if err != nil {
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: archive %s:%s failed", sha, subdir)
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	return ConfineResolution(ctx, Resolution{
		LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
		PackageRoot: packageRoot,
	})
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

// normalizeImplicitGitHubSource converts Terraform's implicit GitHub module paths to git::ssh://.
//
//	"github.com/org/repo//subdir?ref=tag"
//	→ "git::ssh://git@github.com/org/repo//subdir?ref=tag", true
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
	return "git::ssh://git@" + source, true
}

// normalizeHTTPGitToSSH rewrites git::http(s)://host/... to git::ssh://git@host/...
// so git clones use SSH credentials instead of unauthenticated HTTPS.
func normalizeHTTPGitToSSH(source string) (string, bool) {
	const prefix = "git::"
	if !strings.HasPrefix(source, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(source, prefix)
	if strings.HasPrefix(rest, "ssh://") {
		return "", false
	}
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(rest, scheme) {
			return prefix + "ssh://git@" + strings.TrimPrefix(rest, scheme), true
		}
	}
	return "", false
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

// normalizeGitModuleSource applies all git source normalizations used by resolvers.
func normalizeGitModuleSource(source string) (string, bool) {
	if source == "" {
		return "", false
	}
	original := source
	if normalized, ok := normalizeGitModuleSourceForGetter(source); ok {
		source = normalized
	}
	if strings.HasPrefix(source, "git::") {
		if normalized, ok := normalizeHTTPGitToSSH(source); ok {
			source = normalized
		}
	}
	return source, source != original
}

// parseGitGetterSource parses a go-getter git source into its canonical components.
// Sources are normalized via normalizeGitModuleSource before parsing.
//
//	"git::https://github.com/org/repo.git//path/to/mod?ref=abc123"
//	→ repoURL="ssh://git@github.com/org/repo.git", subdir="path/to/mod", ref="abc123"
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
