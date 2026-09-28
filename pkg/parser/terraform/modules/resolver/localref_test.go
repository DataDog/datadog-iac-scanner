/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_TERMINAL_PROMPT=0", "EDITOR=true",
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

func initRepoWithRefs(t *testing.T) (workTree, gitDir string) {
	t.Helper()
	workTree = t.TempDir()
	runGit(t, workTree, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(workTree, "main.tf"), []byte("# m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, workTree, "add", ".")
	runGit(t, workTree, "commit", "-q", "-m", "init")
	runGit(t, workTree, "branch", "feature")
	runGit(t, workTree, "tag", "v1.0.0")                    // lightweight
	runGit(t, workTree, "tag", "-a", "v2.0.0", "-m", "two") // annotated
	return workTree, filepath.Join(workTree, ".git")
}

func TestIsPartialCloneReadsThePromisorExtension(t *testing.T) {
	workTree, gitDir := initRepoWithRefs(t)
	if isPartialClone(context.Background(), gitDir) {
		t.Fatal("a full clone is not a partial clone")
	}
	runGit(t, workTree, "config", "extensions.partialClone", "origin")
	if !isPartialClone(context.Background(), gitDir) {
		t.Fatal("a clone with a promisor remote is a partial clone")
	}
}

func TestLoadRefMapMatchesRevParse(t *testing.T) {
	workTree, gitDir := initRepoWithRefs(t)
	info := &localRepoInfo{gitDir: gitDir, refSHA: loadRefMap(context.Background(), gitDir)}
	unmapped := &localRepoInfo{gitDir: gitDir}
	commit := runGit(t, workTree, "rev-parse", "--verify", "main")

	for _, ref := range []string{"v1.0.0", "v2.0.0", "main", "feature"} {
		got, ok := info.lookupRefSHA(ref)
		if !ok {
			t.Fatalf("ref %q not found in map", ref)
		}
		if got != commit {
			t.Fatalf("ref %q: map sha %q, want commit %q", ref, got, commit)
		}
		for _, repo := range []*localRepoInfo{info, unmapped} {
			if resolved, present := resolveLocalRef(context.Background(), repo, ref); !present || resolved != commit {
				t.Fatalf("resolveLocalRef(%q) = (%q,%v), want (%q,true)", ref, resolved, present, commit)
			}
		}
	}
	if tagObject := runGit(t, workTree, "rev-parse", "--verify", "v2.0.0"); tagObject == commit {
		t.Fatal("fixture must use an annotated tag")
	}
}

func TestResolveLocalRefSHAAndMissing(t *testing.T) {
	workTree, gitDir := initRepoWithRefs(t)
	info := &localRepoInfo{gitDir: gitDir, refSHA: loadRefMap(context.Background(), gitDir)}

	sha := runGit(t, workTree, "rev-parse", "--verify", "main")
	if got, ok := resolveLocalRef(context.Background(), info, sha); !ok || got != sha {
		t.Fatalf("resolveLocalRef(sha) = (%q,%v), want (%q,true)", got, ok, sha)
	}
	if _, ok := resolveLocalRef(context.Background(), info, "does-not-exist"); ok {
		t.Fatal("expected missing ref to be unresolved")
	}
}

func TestLocalGitResolverInitReusesWorktreeAcrossRootsButNotNestedRepos(t *testing.T) {
	outer := t.TempDir()
	runGit(t, outer, "init", "-q", "-b", "main")
	runGit(t, outer, "remote", "add", "origin", "https://example.com/acme/outer.git")
	nested := filepath.Join(outer, "vendor", "nested")
	for _, dir := range []string{filepath.Join(outer, "a", "b"), filepath.Join(nested, "x")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, nested, "init", "-q", "-b", "main")
	runGit(t, nested, "remote", "add", "origin", "https://example.com/acme/nested.git")

	worktrees := []string{}
	if top, ok := plainWorktreeTop(filepath.Join(outer, ".git")); ok {
		worktrees = append(worktrees, top)
	}
	if !insideKnownWorktree(worktrees, filepath.Join(outer, "a", "b")) {
		t.Fatal("subdirectory of a known worktree must reuse its git dir")
	}
	if insideKnownWorktree(worktrees, filepath.Join(nested, "x")) {
		t.Fatal("nested repository must not reuse the outer git dir")
	}

	resolver := NewLocalGitRefResolver([]string{
		outer, filepath.Join(outer, "a"), filepath.Join(outer, "a", "b"), filepath.Join(nested, "x"),
	}, t.TempDir())
	resolver.init(t.Context())
	if len(resolver.repos) != 2 {
		t.Fatalf("got %d repos, want outer and nested", len(resolver.repos))
	}
	for _, source := range []string{"https://example.com/acme/outer.git", "https://example.com/acme/nested.git"} {
		if resolver.findRepo(normalizeGitRepoURL(source)) == nil {
			t.Fatalf("repo %s was not registered", source)
		}
	}
}

func TestLocalGitResolverInitIgnoresFirstCallersCancellation(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q", "-b", "main")
	runGit(t, root, "remote", "add", "origin", "https://example.com/acme/repo.git")

	resolver := NewLocalGitRefResolver([]string{root}, t.TempDir())
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	resolver.init(cancelled)
	if resolver.findRepo(normalizeGitRepoURL("https://example.com/acme/repo.git")) == nil {
		t.Fatal("a cancelled first caller must not leave the shared repository list empty")
	}
}

func TestLocalGitResolverRejectsAndRemovesOversizedCacheEntry(t *testing.T) {
	workTree, gitDir := initRepoWithRefs(t)
	root := testCacheRoot(t)
	budget, err := NewModuleCacheBudget(root, 1)
	if err != nil {
		t.Fatal(err)
	}
	repoURL := "https://example.com/acme/repo.git"
	extractBase := filepath.Join(root, CacheSubdirGitLocal, "repo")
	resolver := NewLocalGitRefResolver(nil, filepath.Join(root, CacheSubdirGitLocal))
	resolver.Budget = budget
	resolver.repos = []*localRepoInfo{{
		gitDir:      gitDir,
		normalURLs:  map[string]bool{normalizeGitRepoURL(repoURL): true},
		extractBase: extractBase,
		refSHA:      loadRefMap(t.Context(), gitDir),
	}}

	sha := runGit(t, workTree, "rev-parse", "HEAD")
	_, err = resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "git::" + repoURL + "?ref=" + sha,
	})
	if !tfmodules.IsUnresolved(err) || !strings.Contains(err.Error(), errCacheEntryTooLarge.Error()) {
		t.Fatalf("resolving oversized local git module: %v", err)
	}
	if _, err := os.Stat(extractBase); !os.IsNotExist(err) {
		t.Fatalf("oversized local git cache entry remained on disk: %v", err)
	}
}

func TestLocalArchiveBudgetRejectionKeepsCheckoutObjects(t *testing.T) {
	workTree := t.TempDir()
	runGit(t, workTree, "init", "-q", "-b", "main")
	dir := filepath.Join(workTree, "modules", "big")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(strings.Repeat("#", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, workTree, "add", ".")
	runGit(t, workTree, "commit", "-q", "-m", "big")
	sha := runGit(t, workTree, "rev-parse", "HEAD")
	gitDir := filepath.Join(workTree, ".git")

	concurrent := filepath.Join(gitDir, "objects", "pack", "concurrent-user-fetch.pack")
	runArchive := func(ctx context.Context, args []string) ([]archivePrep, error) {
		if err := os.WriteFile(concurrent, []byte("pack"), 0o644); err != nil {
			return nil, err
		}
		return localCloneArchiveCommand(gitDir)(ctx, args)
	}
	ctx := WithResourceBudget(t.Context(), NewResourceBudget(ResourceLimits{MaxPackageBytes: 1024}))
	if _, err := archiveExtract(ctx, gitDir, t.TempDir(), sha, "modules/big", runArchive, nil); err == nil {
		t.Fatal("expected the oversized module to be rejected")
	}
	if _, err := os.Stat(concurrent); err != nil {
		t.Fatalf("object written to the scanned checkout during extraction was removed: %v", err)
	}
}

func TestArchiveExtractMaterializesLocalModuleClosure(t *testing.T) {
	workTree := t.TempDir()
	runGit(t, workTree, "init", "-q", "-b", "main")
	for _, module := range []string{"selected", "shared", "unrelated"} {
		dir := filepath.Join(workTree, "modules", module)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		content := "# " + module + "\n"
		if module == "selected" {
			content += "module \"shared\" { source = \"../shared\" }\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, workTree, "add", ".")
	runGit(t, workTree, "commit", "-q", "-m", "modules")
	sha := runGit(t, workTree, "rev-parse", "HEAD")
	extractBase := t.TempDir()

	gitDir := filepath.Join(workTree, ".git")
	if _, err := archiveExtract(
		t.Context(), gitDir, extractBase, sha, "modules/selected",
		localCloneArchiveCommand(gitDir), nil,
	); err != nil {
		t.Fatalf("archiveExtract: %v", err)
	}

	packageRoot := archiveCacheDir(extractBase, sha)
	for _, module := range []string{"selected", "shared"} {
		if _, err := os.Stat(filepath.Join(packageRoot, "modules", module, "main.tf")); err != nil {
			t.Fatalf("package module %q was not extracted: %v", module, err)
		}
	}
	if _, err := os.Stat(filepath.Join(packageRoot, "modules", "unrelated")); !os.IsNotExist(err) {
		t.Fatalf("unrelated module was extracted: %v", err)
	}
}

func TestLocalGitResolverPartialCheckoutFallsThroughWithoutLazyFetch(t *testing.T) {
	upstream := t.TempDir()
	runGit(t, upstream, "init", "-q", "-b", "main")
	runGit(t, upstream, "config", "uploadpack.allowFilter", "true")
	moduleFile := filepath.Join(upstream, "modules", "x", "main.tf")
	if err := os.MkdirAll(filepath.Dir(moduleFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(moduleFile, []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, upstream, "add", ".")
	runGit(t, upstream, "commit", "-q", "-m", "old")
	oldSHA := runGit(t, upstream, "rev-parse", "HEAD")
	oldBlob := runGit(t, upstream, "rev-parse", "HEAD:modules/x/main.tf")
	if err := os.WriteFile(moduleFile, []byte("# new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, upstream, "commit", "-q", "-am", "new")

	checkout := filepath.Join(t.TempDir(), "checkout")
	runGit(t, filepath.Dir(checkout), "clone", "-q", "--filter=blob:none", "file://"+upstream, checkout)
	gitDir := filepath.Join(checkout, ".git")
	blobMissing := func() bool {
		cmd := exec.Command("git", "cat-file", "-e", oldBlob)
		cmd.Dir = checkout
		cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
		return cmd.Run() != nil
	}
	if !blobMissing() {
		t.Fatal("fixture must be a partial clone missing the old module's blob")
	}

	repoURL := "https://example.com/acme/repo.git"
	local := NewLocalGitRefResolver(nil, t.TempDir())
	local.repos = []*localRepoInfo{{
		gitDir:      gitDir,
		normalURLs:  map[string]bool{normalizeGitRepoURL(repoURL): true},
		extractBase: filepath.Join(t.TempDir(), "repo"),
		refSHA:      loadRefMap(t.Context(), gitDir),
	}}
	var nextCalled bool
	next := fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
		nextCalled = true
		return Resolution{LocalPath: "/bare", Origin: "git"}, nil
	})

	res, err := NewChainResolver(local, next).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "git::" + repoURL + "//modules/x?ref=" + oldSHA,
	})
	if err != nil {
		t.Fatalf("chain did not fall through to the next resolver: %v", err)
	}
	if !nextCalled || res.Origin != "git" {
		t.Fatalf("expected the next resolver to serve the module, got %+v", res)
	}
	if !blobMissing() {
		t.Fatal("local resolver lazily fetched from the checkout's remote")
	}
}
