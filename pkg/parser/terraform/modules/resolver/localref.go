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

	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// LocalGitRefResolver extracts self-referential git modules from the local checkout.
type LocalGitRefResolver struct {
	ScanRoots []string

	// Defaults to <user-cache-dir>/datadog-iac-scanner/git-local.
	CacheDir string

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

func (r *LocalGitRefResolver) init(ctx context.Context) {
	r.initOnce.Do(func() {
		contextLogger := logger.FromContext(ctx)
		seen := make(map[string]bool) // deduplicate gitDirs
		for _, root := range r.ScanRoots {
			gitDir, err := detectGitDir(ctx, root)
			if err != nil || seen[gitDir] {
				continue
			}
			seen[gitDir] = true

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

func loadRefMap(ctx context.Context, gitDir string) map[string]string {
	cmd := gitInDir(ctx, gitDir, "for-each-ref", "--format=%(objectname) %(refname)", "refs/tags", "refs/heads")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	refs := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		sha, refName, found := strings.Cut(line, " ")
		if !found || !looksLikeSHA(sha) {
			continue
		}
		refs[refName] = sha
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

	release, err := acquireGitProc(ctx)
	if err != nil {
		return "", false
	}
	defer release()
	if looksLikeSHA(ref) {
		safeRef, refErr := gitSafeArg(ref)
		if refErr != nil {
			return "", false
		}
		cmd := gitInDir(ctx, info.gitDir, "cat-file", "-t", safeRef)
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
	cmd := gitInDir(ctx, info.gitDir, "rev-parse", "--verify", safeRef)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	resolved := strings.TrimSpace(string(out))
	return resolved, looksLikeSHA(resolved)
}

// Resolve implements Resolver for git:: sources that reference the local checkout.
func (r *LocalGitRefResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	repoURL, subdir, ref, ok := parseGitGetterSource(mod.Source)
	if !ok || ref == "" {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: "LocalGitRefResolver: not a git:: source with a ref= parameter",
		}
	}

	r.init(ctx)

	normSource := normalizeGitRepoURL(repoURL)
	info := r.findRepo(normSource)
	if info == nil {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("LocalGitRefResolver: no local clone matches %q", normSource),
		}
	}

	// Warm-cache fast path for pinned SHA refs.
	if looksLikeSHA(ref) {
		if packageRoot, ok := cachedArchiveDir(info.extractBase, ref, subdir); ok {
			return ConfineResolution(ctx, Resolution{
				LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
				PackageRoot: packageRoot,
			})
		}
	}

	contextLogger := logger.FromContext(ctx)
	sha, present := resolveLocalRef(ctx, info, ref)
	if !present {
		contextLogger.Debug().Msgf("LocalGitRefResolver: ref %q not in local clone %s (shallow checkout?)", ref, info.gitDir)
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("LocalGitRefResolver: ref %q not present locally", ref),
		}
	}

	key := archiveCacheKey(sha) + "\x00" + filepath.Clean(subdir)
	_, err, _ := r.extractSF.Do(key, func() (interface{}, error) {
		return nil, archiveExtract(
			ctx, info.gitDir, info.extractBase, sha, subdir,
			localCloneArchiveCommand(info.gitDir),
		)
	})
	if err != nil {
		contextLogger.Warn().Err(err).Msgf("LocalGitRefResolver: archive %s:%s failed", sha, subdir)
		return Resolution{}, &tfmodules.UnresolvedError{Reason: err.Error()}
	}

	packageRoot := archiveCacheDir(info.extractBase, sha)
	return ConfineResolution(ctx, Resolution{
		LocalPath:   filepath.Join(packageRoot, filepath.FromSlash(subdir)),
		PackageRoot: packageRoot,
	})
}
