/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// LocalGitRefResolver extracts self-referential git modules from the local checkout.
type LocalGitRefResolver struct {
	ScanRoots []string

	// Defaults to <user-cache-dir>/datadog-iac-scanner/git-local.
	CacheDir string
	Budget   *ModuleCacheBudget

	initOnce sync.Once
	repos    []*localRepoInfo // scan roots that are git repos

	extractSF singleflight.Group
}

type localRepoInfo struct {
	gitDir      string          // <root>/.git (or the root itself for bare repos)
	normalURLs  map[string]bool // set of normalized remote URLs for this repo
	extractBase string

	refSHA map[string]string // refs/tags|heads → object SHA from one for-each-ref
}

func (info *localRepoInfo) lookupRefSHA(ref string) (string, bool) {
	if info.refSHA == nil {
		return "", false
	}
	for _, full := range []string{ref, "refs/" + ref, "refs/tags/" + ref, "refs/heads/" + ref} {
		if sha, ok := info.refSHA[full]; ok {
			return sha, true
		}
	}
	return "", false
}

func NewLocalGitRefResolver(scanRoots []string, cacheDir string) *LocalGitRefResolver {
	return &LocalGitRefResolver{
		ScanRoots: scanRoots,
		CacheDir:  cacheDir,
	}
}

func (r *LocalGitRefResolver) effectiveCacheDir() string {
	if r.CacheDir != "" {
		return r.CacheDir
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "datadog-iac-scanner", "git-local")
}

// localRefInitTimeout bounds the local git reads that discover the scan roots'
// repositories.
const localRefInitTimeout = time.Minute

func (r *LocalGitRefResolver) init(ctx context.Context) {
	r.initOnce.Do(func() {
		// Every later caller shares this result, so it must not inherit the
		// first caller's deadline or cancellation.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), localRefInitTimeout)
		defer cancel()
		contextLogger := logger.FromContext(ctx)
		seen := make(map[string]bool) // deduplicate gitDirs
		var worktrees []string
		for _, root := range r.ScanRoots {
			if insideKnownWorktree(worktrees, root) {
				continue
			}
			gitDir, err := detectGitDir(ctx, root)
			if err != nil {
				continue
			}
			if top, ok := plainWorktreeTop(gitDir); ok {
				worktrees = append(worktrees, top)
			}
			if seen[gitDir] {
				continue
			}
			seen[gitDir] = true
			if !localReadsStayLocal() && isPartialClone(ctx, gitDir) {
				contextLogger.Debug().Msgf("LocalGitRefResolver: skipping partial clone %s, git is too old to read it without fetching", root)
				continue
			}

			urls, err := listRemoteURLs(ctx, gitDir)
			if err != nil {
				contextLogger.Debug().Err(err).Msgf("LocalGitRefResolver: could not read remotes for %s", root)
				continue
			}
			if len(urls) == 0 {
				continue
			}

			repoKey := repoURLKey(gitDir)
			info := &localRepoInfo{
				gitDir:      gitDir,
				normalURLs:  make(map[string]bool, len(urls)),
				extractBase: filepath.Join(r.effectiveCacheDir(), repoKey),
				refSHA:      loadRefMap(ctx, gitDir),
			}
			for _, u := range urls {
				info.normalURLs[normalizeGitRepoURL(u)] = true
			}
			r.repos = append(r.repos, info)
		}
	})
}

// isPartialClone reports whether objects missing from gitDir would be fetched
// from a promisor remote on read.
func isPartialClone(ctx context.Context, gitDir string) bool {
	out, err := gitInDir(ctx, gitDir, "config", "--get", "extensions.partialClone").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

func loadRefMap(ctx context.Context, gitDir string) map[string]string {
	// %(*objectname) is the commit an annotated tag points to, so a tag and a
	// SHA pin of the same commit share one extracted package.
	cmd := gitInDir(ctx, gitDir, "for-each-ref",
		"--format=%(objectname) %(*objectname) %(refname)", "refs/tags", "refs/heads")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	refs := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(line, " ", 3)
		if len(fields) != 3 {
			continue
		}
		sha := fields[0]
		if fields[1] != "" {
			sha = fields[1]
		}
		if !looksLikeSHA(sha) {
			continue
		}
		refs[fields[2]] = sha
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

func detectGitDir(ctx context.Context, root string) (string, error) {
	cmd := gitInWorktree(ctx, root, "rev-parse", "--git-dir")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repo: %w", err)
	}
	gitDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	return gitDir, nil
}

// plainWorktreeTop returns the worktree root when gitDir is a regular <top>/.git
// directory. Bare repositories and .git files (submodules, linked worktrees) are
// not reported so their roots keep going through detectGitDir.
func plainWorktreeTop(gitDir string) (string, bool) {
	if filepath.Base(gitDir) != ".git" {
		return "", false
	}
	info, err := os.Lstat(gitDir)
	if err != nil || !info.IsDir() {
		return "", false
	}
	top, err := filepath.EvalSymlinks(filepath.Dir(gitDir))
	if err != nil {
		return "", false
	}
	return top, true
}

// insideKnownWorktree reports whether root belongs to one of worktrees without
// crossing a nested repository boundary, so detectGitDir would return the same
// git dir again.
func insideKnownWorktree(worktrees []string, root string) bool {
	if len(worktrees) == 0 {
		return false
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return false
	}
	for _, top := range worktrees {
		rel, err := filepath.Rel(top, resolved)
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		nested := false
		for dir := resolved; dir != top; dir = filepath.Dir(dir) {
			if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
				nested = true
				break
			}
		}
		if !nested {
			return true
		}
	}
	return false
}

func listRemoteURLs(ctx context.Context, gitDir string) ([]string, error) {
	cmd := gitInDir(ctx, gitDir, "remote", "-v")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var urls []string
	for _, line := range strings.Split(string(out), "\n") {
		// Format: "origin\thttps://... (fetch)"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		u := fields[1]
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls, nil
}

func (r *LocalGitRefResolver) findRepo(normSource string) *localRepoInfo {
	for _, info := range r.repos {
		if info.normalURLs[normSource] {
			return info
		}
	}
	return nil
}

func resolveLocalRef(ctx context.Context, info *localRepoInfo, ref string) (sha string, ok bool) {
	if !looksLikeSHA(ref) {
		if resolved, found := info.lookupRefSHA(ref); found {
			return resolved, true
		}
	}

	// Local-only reads, so they bypass acquireGitProc.
	if looksLikeSHA(ref) {
		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", false
		}
		cmd := gitLocalInDir(ctx, info.gitDir, "cat-file", "-t", safeRef)
		if cmd.Run() == nil {
			return ref, true
		}
		return "", false
	}
	safeRef, refErr := gitSafeArg(ref)
	if refErr != nil {
		return "", false
	}
	// Ref not in the prebuilt map (e.g. remote-tracking ref): ask git directly.
	cmd := gitLocalInDir(ctx, info.gitDir, "rev-parse", "--verify", safeRef+"^{commit}")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	resolved := strings.TrimSpace(string(out))
	return resolved, looksLikeSHA(resolved)
}

func (r *LocalGitRefResolver) Screen(ctx context.Context, mod *tfmodules.ParsedModule) error {
	_, err := r.admit(ctx, mod)
	return err
}

// localGitSource is a git:: source with a ref that points at a scanned checkout.
type localGitSource struct {
	info        *localRepoInfo
	subdir, ref string
}

func (r *LocalGitRefResolver) admit(ctx context.Context, mod *tfmodules.ParsedModule) (localGitSource, error) {
	repoURL, subdir, ref, ok := parseGitGetterSource(mod.Source)
	if !ok || ref == "" {
		return localGitSource{}, notApplicable("LocalGitRefResolver: not a git:: source with a ref= parameter")
	}
	r.init(ctx)
	normSource := normalizeGitRepoURL(repoURL)
	info := r.findRepo(normSource)
	if info == nil {
		return localGitSource{}, notApplicable(fmt.Sprintf("LocalGitRefResolver: no local clone matches %q", normSource))
	}
	return localGitSource{info: info, subdir: subdir, ref: ref}, nil
}

// Resolve implements Resolver for git:: sources that reference the local checkout.
func (r *LocalGitRefResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	source, err := r.admit(ctx, mod)
	if err != nil {
		return Resolution{}, err
	}
	info, subdir, ref := source.info, source.subdir, source.ref

	// Warm-cache fast path for pinned SHA refs.
	if looksLikeSHA(ref) {
		if packageRoot, ok := cachedArchiveDir(info.extractBase, ref, subdir); ok {
			release := r.Budget.Lease(info.extractBase)
			if err := r.Budget.EnsureEntryFits(info.extractBase); err != nil {
				release()
				return Resolution{}, unresolvedResourceError(err)
			}
			resolution, err := ConfineResolution(ctx, &Resolution{
				LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
				Origin:      "git_local",
				PackageRoot: packageRoot,
				Usage:       archiveUsageHint(packageRoot),
				ResolvedRef: ref,
			})
			if err != nil {
				release()
				return Resolution{}, err
			}
			return withResolutionCleanup(&resolution, release), nil
		}
	}

	contextLogger := logger.FromContext(ctx)
	release := r.Budget.Lease(info.extractBase)
	sha, present := resolveLocalRef(ctx, info, ref)
	if !present {
		release()
		contextLogger.Debug().Msgf("LocalGitRefResolver: ref %q not in local clone %s (shallow checkout?)", ref, info.gitDir)
		return Resolution{}, notApplicable(fmt.Sprintf("LocalGitRefResolver: ref %q not present locally", ref))
	}

	key := archiveCacheKey(sha) + "\x00" + filepath.Clean(subdir)
	_, err, _ = r.extractSF.Do(key, func() (interface{}, error) {
		written, extractErr := archiveExtract(
			ctx, info.gitDir, info.extractBase, sha, subdir,
			localCloneArchiveCommand(info.gitDir), nil,
		)
		if extractErr != nil {
			r.Budget.Invalidate(info.extractBase)
		} else {
			r.Budget.Grow(info.extractBase, written)
		}
		return nil, extractErr
	})
	if err != nil {
		release()
		contextLogger.Warn().Err(err).Msgf("LocalGitRefResolver: archive %s:%s failed", sha, subdir)
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	if err := r.Budget.EnsureEntryFits(info.extractBase); err != nil {
		release()
		return Resolution{}, unresolvedResourceError(err)
	}
	r.Budget.Admit(info.extractBase)
	packageRoot := archiveCacheDir(info.extractBase, sha)
	resolution, err := ConfineResolution(ctx, &Resolution{
		LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
		PackageRoot: packageRoot,
		Usage:       archiveUsageHint(packageRoot),
		ResolvedRef: sha,
		Origin:      "git_local",
	})
	if err != nil {
		release()
		return Resolution{}, err
	}
	return withResolutionCleanup(&resolution, release), nil
}
