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
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

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

type bareRepo struct {
	barePath    string // path to the bare clone on disk
	extractBase string // base dir for per-(sha,subdir) extracted trees

	cloneOK   atomic.Bool
	cloneSF   singleflight.Group
	fetchSF   singleflight.Group
	extractSF singleflight.Group
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

func repoURLKey(rawURL string) string {
	h := sha256.Sum256([]byte(rawURL))
	return fmt.Sprintf("%x", h[:12])
}

func (r *BareGitResolver) getOrInitRepo(repoURL string) *bareRepo {
	r.mu.Lock()
	defer r.mu.Unlock()
	if repo, ok := r.repos[repoURL]; ok {
		return repo
	}
	base := filepath.Join(r.effectiveCacheDir(), repoURLKey(repoURL))
	repo := &bareRepo{
		barePath:    filepath.Join(base, "repo.git"),
		extractBase: filepath.Join(base, "extracted"),
	}
	r.repos[repoURL] = repo
	return repo
}

func (repo *bareRepo) ensureClone(ctx context.Context, repoURL string) error {
	if repo.cloneOK.Load() {
		return nil
	}
	_, err, _ := repo.cloneSF.Do("clone", func() (interface{}, error) {
		if repo.cloneOK.Load() {
			return nil, nil
		}
		if info, err := os.Stat(repo.barePath); err == nil && info.IsDir() {
			repo.cloneOK.Store(true)
			return nil, nil
		}
		if err := os.MkdirAll(repo.barePath, dirPerm); err != nil {
			return nil, err
		}
		release, err := acquireGitProc(ctx)
		if err != nil {
			_ = os.RemoveAll(repo.barePath)
			return nil, err
		}
		defer release()
		cmd := exec.CommandContext(ctx, "git", "clone", "--bare", "--filter=blob:none", repoURL, repo.barePath) //nolint:gosec
		if out, cloneErr := cmd.CombinedOutput(); cloneErr != nil {
			_ = os.RemoveAll(repo.barePath)
			return nil, fmt.Errorf("git clone --bare %s: %w\n%s", repoURL, cloneErr, bytes.TrimSpace(out))
		}
		repo.cloneOK.Store(true)
		return nil, nil
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
			check := exec.CommandContext(ctx, "git", "--git-dir="+repo.barePath, "cat-file", "-t", ref) //nolint:gosec
			if check.Run() == nil {
				return ref, nil // already present
			}
			cmd := exec.CommandContext(ctx, "git", "--git-dir="+repo.barePath, //nolint:gosec
				"fetch", "--filter=blob:none", "origin", ref)
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
		release, acqErr := acquireGitProc(ctx)
		if acqErr != nil {
			return "", acqErr
		}
		defer release()
		// Shallow fetch the named ref.
		cmd := exec.CommandContext(ctx, "git", "--git-dir="+repo.barePath, //nolint:gosec
			"fetch", "--filter=blob:none", "--depth=1", "origin", ref)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Retry without --depth in case the server rejects shallow fetches.
			cmd2 := exec.CommandContext(ctx, "git", "--git-dir="+repo.barePath, //nolint:gosec
				"fetch", "--filter=blob:none", "origin", ref)
			if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
				return "", fmt.Errorf("git fetch origin %s: %w\n%s\n%s", ref, err2, bytes.TrimSpace(out), bytes.TrimSpace(out2))
			}
		}
		// Resolve FETCH_HEAD to the commit SHA.
		resolve := exec.CommandContext(ctx, "git", "--git-dir="+repo.barePath, "rev-parse", "FETCH_HEAD") //nolint:gosec
		sha, revErr := resolve.Output()
		if revErr != nil {
			return "", fmt.Errorf("git rev-parse FETCH_HEAD: %w", revErr)
		}
		resolved := strings.TrimSpace(string(sha))
		if !looksLikeSHA(resolved) {
			return "", fmt.Errorf("unexpected FETCH_HEAD value %q for ref %s", resolved, ref)
		}
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
func archiveExtract(ctx context.Context, gitDir, extractBase, sha, subdir string) error {
	key := archiveCacheKey(sha, subdir)

	dest := filepath.Join(extractBase, key)
	if info, err := os.Stat(dest); err == nil && info.IsDir() {
		return nil // cache hit from previous scan
	}

	if err := os.MkdirAll(dest, dirPerm); err != nil {
		return err
	}

	release, err := acquireGitProc(ctx)
	if err != nil {
		_ = os.RemoveAll(dest)
		return err
	}
	defer release()

	// Stream to tar to avoid buffering the archive in memory.
	archiveArg := sha
	if subdir != "" {
		archiveArg = sha + ":" + subdir
	}
	archive := exec.CommandContext(ctx, "git", "--git-dir="+gitDir, "archive", "--format=tar", archiveArg) //nolint:gosec
	untar := exec.CommandContext(ctx, "tar", "-x", "-C", dest)                                             //nolint:gosec

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
		_ = os.RemoveAll(dest)
		return fmt.Errorf("git archive %s: %w", archiveArg, archiveErr)
	}
	if untarErr != nil {
		_ = os.RemoveAll(dest)
		return fmt.Errorf("tar extract: %w", untarErr)
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

	if err := repo.ensureClone(ctx, repoURL); err != nil {
		contextLogger.Warn().Err(err).Msgf("BareGitResolver: failed to clone %s", repoURL)
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

// parseGitGetterSource parses a go-getter git source into its canonical components.
//
//	"git::https://github.com/org/repo.git//path/to/mod?ref=abc123"
//	→ repoURL="https://github.com/org/repo.git", subdir="path/to/mod", ref="abc123"
func parseGitGetterSource(source string) (repoURL, subdir, ref string, ok bool) {
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
