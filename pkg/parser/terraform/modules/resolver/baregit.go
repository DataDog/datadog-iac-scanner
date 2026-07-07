/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// dirPerm is the permission mode used for all directories created by resolvers.
const dirPerm = 0o750

// BareGitResolver keeps one bare clone per repo and extracts refs via git archive.
type BareGitResolver struct {
	// Defaults to <user-cache-dir>/datadog-iac-scanner/git-bare.
	CacheDir string

	mu    sync.Mutex
	repos map[string]*bareRepo
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

func NewBareGitResolver(cacheDir string) *BareGitResolver {
	return &BareGitResolver{
		CacheDir: cacheDir,
		repos:    make(map[string]*bareRepo),
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
		if info, err := os.Stat(repo.barePath); err == nil && info.IsDir() {
			// Validate that the directory is a real bare repo, not a partial clone
			// left by a killed process. This is a local-only read (no network, no
			// pack-file I/O) so it intentionally bypasses the acquireGitProc semaphore,
			// which is reserved for operations that meaningfully consume system resources.
			if gitInDir(ctx, repo.barePath, "rev-parse", "--git-dir").Run() == nil {
				repo.cloneOK.Store(true)
				return nil, nil
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
					return nil, ctx.Err()
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
				return nil, nil
			}
			_ = os.RemoveAll(repo.barePath)
			lastErr = fmt.Errorf("git clone --bare %s: %w\n%s", repo.cloneURL, cloneErr, bytes.TrimSpace(out))
		}
		repo.setCloneError(lastErr)
		log := logger.FromContext(ctx)
		log.Warn().Err(lastErr).Msgf("BareGitResolver: failed to clone %s after %d attempts", repo.cloneURL, bareCloneAttempts)
		return nil, lastErr
	})
	return err
}

// fetchRef ensures ref is present and returns its canonical commit SHA.
func (repo *bareRepo) fetchRef(ctx context.Context, ref string) (string, error) {
	if looksLikeSHA(ref) {
		// Fast path: SHA is stable; check locally first.
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
			check := gitInDir(ctx, repo.barePath, "cat-file", "-t", safeRef)
			if check.Run() == nil {
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

	// Branch/tag ref: fetch and resolve to SHA. Key on "ref:<name>" so it
	// doesn't conflict with SHA keys.
	v, err, _ := repo.fetchSF.Do("ref:"+ref, func() (interface{}, error) {
		// Fast path: return the cached SHA from a previous run, skipping the network entirely.
		// The archive extraction has its own on-disk cache keyed by SHA, so the result is stable.
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
		resolve := gitInDir(ctx, repo.barePath, "rev-parse", "FETCH_HEAD")
		sha, revErr := resolve.Output()
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

func archiveCacheKey(sha, subdir string) string {
	h := sha256.Sum256([]byte(sha + ":" + subdir))
	// sha[:8] prefix makes the directory human-readable during debugging.
	return sha[:8] + "-" + fmt.Sprintf("%x", h[:4])
}

func archiveCacheDir(extractBase, sha, subdir string) string {
	return filepath.Join(extractBase, archiveCacheKey(sha, subdir))
}

func cachedArchiveDir(extractBase, sha, subdir string) (string, bool) {
	dest := archiveCacheDir(extractBase, sha, subdir)
	info, err := os.Stat(dest)
	return dest, err == nil && info.IsDir()
}

// archiveExtract materializes sha:subdir into a persistent local directory.
// It extracts into a temp dir and renames atomically so a partial extraction
// from a prior crash is never mistaken for a complete cache entry.
func archiveExtract(ctx context.Context, gitDir, extractBase, sha, subdir string) error {
	key := archiveCacheKey(sha, subdir)
	dest := filepath.Join(extractBase, key)

	if info, err := os.Stat(dest); err == nil && info.IsDir() {
		return nil // cache hit from a previous scan
	}

	if err := os.MkdirAll(extractBase, dirPerm); err != nil {
		return err
	}

	// Extract into a sibling temp dir; rename to dest only on full success.
	tmp, err := os.MkdirTemp(extractBase, ".tmp-extract-")
	if err != nil {
		return fmt.Errorf("creating extract temp dir: %w", err)
	}

	release, err := acquireGitProc(ctx)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	defer release()

	archiveArg, argErr := gitSafeArg(sha)
	if subdir != "" {
		archiveArg, argErr = gitSafeArg(sha + ":" + subdir)
	}
	if argErr != nil {
		_ = os.RemoveAll(tmp)
		return argErr
	}
	archive := gitInDir(ctx, gitDir, "archive", "--format=tar", archiveArg)
	untar := tarExtract(ctx, tmp)

	pr, pw := io.Pipe()
	archive.Stdout = pw
	untar.Stdin = pr

	var archiveErr, untarErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		archiveErr = archive.Run()
		pw.CloseWithError(archiveErr)
	}()
	go func() {
		defer wg.Done()
		untarErr = untar.Run()
	}()
	wg.Wait()

	if archiveErr != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("git archive %s: %w", archiveArg, archiveErr)
	}
	if untarErr != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("tar extract: %w", untarErr)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.RemoveAll(tmp)
		// Another process may have won the race; accept if dest is now present.
		if info, statErr := os.Stat(dest); statErr == nil && info.IsDir() {
			return nil
		}
		return fmt.Errorf("publishing extract cache entry: %w", err)
	}
	return nil
}

func (repo *bareRepo) extract(ctx context.Context, sha, subdir string) (string, error) {
	key := archiveCacheKey(sha, subdir)
	_, err, _ := repo.extractSF.Do(key, func() (interface{}, error) {
		return nil, archiveExtract(ctx, repo.barePath, repo.extractBase, sha, subdir)
	})
	if err != nil {
		return "", err
	}
	return archiveCacheDir(repo.extractBase, sha, subdir), nil
}

// Resolve implements Resolver for any git:: source that carries a ref= parameter.
func (r *BareGitResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	repoURL, subdir, ref, ok := parseGitGetterSource(mod.Source)
	if !ok || ref == "" {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: "BareGitResolver: not a git:: source with a ref= parameter",
		}
	}

	contextLogger := logger.FromContext(ctx)
	repo := r.getOrInitRepo(repoURL)

	// SHA refs have stable extraction keys; branch/tag refs must be re-resolved.
	if looksLikeSHA(ref) {
		if dest, ok := cachedArchiveDir(repo.extractBase, ref, subdir); ok {
			return Resolution{LocalPath: dest}, nil
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

	dir, err := repo.extract(ctx, sha, subdir)
	if err != nil {
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: archive %s:%s failed", sha, subdir)
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	return Resolution{LocalPath: dir}, nil
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

// normalizeGitModuleSource applies all git source normalizations used by resolvers.
func normalizeGitModuleSource(source string) (string, bool) {
	if source == "" {
		return "", false
	}
	original := source
	if normalized, ok := normalizeSCPGitSource(source); ok {
		source = normalized
	} else if normalized, ok := normalizeImplicitGitHubSource(source); ok {
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
