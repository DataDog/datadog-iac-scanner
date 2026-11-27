/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package analyzer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyze_SkipsRepositoryGitMetadata(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	worktree := filepath.Join(dir, "worktree")
	parent := filepath.Join(dir, "parent")
	submodule := filepath.Join(parent, "submodule")
	git := func(dir string, args ...string) {
		t.Helper()
		config := []string{"-c", "core.hooksPath=/dev/null", "-c", "init.templateDir=",
			"-c", "commit.gpgsign=false", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"}
		cmd := exec.CommandContext(t.Context(), "git", append(config, args...)...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}

	const fixture = "bucket.yaml"
	template := []byte("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n")
	git(dir, "init", repo)
	require.NoError(t, os.WriteFile(filepath.Join(repo, fixture), template, 0o600))
	git(repo, "add", fixture)
	git(repo, "commit", "-m", "Add CloudFormation fixture")
	git(repo, "worktree", "add", "--detach", worktree)
	git(dir, "init", parent)
	git(parent, "-c", "protocol.file.allow=always", "submodule", "add", repo, "submodule")
	require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", fixture), template, 0o600))

	for _, root := range []string{repo, worktree, submodule} {
		t.Run(filepath.Base(root), func(t *testing.T) {
			a := &Analyzer{
				RepoPath:    root,
				Paths:       []string{root},
				Types:       []string{"CloudFormation"},
				MaxFileSize: -1,
			}
			got, err := Analyze(t.Context(), a)
			require.NoError(t, err)
			require.Equal(t, []string{filepath.ToSlash(filepath.Join(root, fixture))}, got.Inventory)
			require.Equal(t, 1, got.TotalFiles)
			require.Contains(t, a.Exc, filepath.ToSlash(filepath.Join(root, ".git")))
		})
	}
}
