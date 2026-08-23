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

func TestLoadRefMapMatchesRevParse(t *testing.T) {
	workTree, gitDir := initRepoWithRefs(t)
	info := &localRepoInfo{gitDir: gitDir, refSHA: loadRefMap(context.Background(), gitDir)}

	for _, ref := range []string{"v1.0.0", "v2.0.0", "main", "feature"} {
		want := runGit(t, workTree, "rev-parse", "--verify", ref)
		got, ok := info.lookupRefSHA(ref)
		if !ok {
			t.Fatalf("ref %q not found in map", ref)
		}
		if got != want {
			t.Fatalf("ref %q: map sha %q != rev-parse %q", ref, got, want)
		}
		if resolved, present := resolveLocalRef(context.Background(), info, ref); !present || resolved != want {
			t.Fatalf("resolveLocalRef(%q) = (%q,%v), want (%q,true)", ref, resolved, present, want)
		}
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

	if err := archiveExtract(
		t.Context(), filepath.Join(workTree, ".git"), extractBase, sha, "modules/selected",
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
