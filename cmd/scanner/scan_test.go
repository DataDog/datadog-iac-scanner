package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v3"
)

func TestGetRepositoryCommitInfoWithRefStorage(t *testing.T) {
	repoDir := filepath.Join(t.TempDir(), "repo")
	initCommand := exec.Command("git", "init", "--ref-format=reftable", "--initial-branch=main", repoDir)
	if output, err := initCommand.CombinedOutput(); err != nil {
		t.Skipf("Git does not support reftable: %s", strings.TrimSpace(string(output)))
	}

	runTestGit(t, repoDir, "config", "user.name", "Test User")
	runTestGit(t, repoDir, "config", "user.email", "test@example.com")
	runTestGit(t, repoDir, "config", "commit.gpgsign", "false")
	runTestGit(t, repoDir, "remote", "add", "origin", "https://example.com/repository.git")
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "main.tf"), []byte("resource \"test\" \"example\" {}\n"), 0o600))
	runTestGit(t, repoDir, "add", "main.tf")
	runTestGit(t, repoDir, "commit", "-m", "initial commit")
	wantSHA := runTestGit(t, repoDir, "rev-parse", "HEAD")
	for _, name := range []string{
		"GIT_DIR",
		"GIT_WORK_TREE",
		"GIT_COMMON_DIR",
		"GIT_INDEX_FILE",
		"GIT_OBJECT_DIRECTORY",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"GIT_NAMESPACE",
	} {
		t.Setenv(name, filepath.Join(t.TempDir(), "override"))
	}

	info, gotRepoDir, err := getRepositoryCommitInfo([]string{filepath.Join(repoDir, "main.tf")})

	require.NoError(t, err)
	resolvedRepoDir, err := filepath.EvalSymlinks(repoDir)
	require.NoError(t, err)
	assert.Equal(t, resolvedRepoDir, gotRepoDir)
	assert.Equal(t, "https://example.com/repository.git", info.RepositoryUrl)
	assert.Equal(t, wantSHA, info.CommitSHA)
	assert.Equal(t, "main", info.Branch)
}

func TestTrimGitOutputTerminator(t *testing.T) {
	assert.Equal(t, "/tmp/repo ", trimGitOutputTerminator("/tmp/repo \n"))
	assert.Equal(t, "/tmp/repo ", trimGitOutputTerminator("/tmp/repo \r\n"))
	assert.Equal(t, " value ", trimGitOutputTerminator(" value "))
}

func runTestGit(t *testing.T, repoDir string, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{"-C", repoDir}, args...)
	output, err := exec.Command("git", cmdArgs...).CombinedOutput()
	require.NoError(t, err, strings.TrimSpace(string(output)))
	return strings.TrimSpace(string(output))
}

func TestApplyPlatformFilters(t *testing.T) {
	all := []string{"Ansible", "CICD", "CloudFormation", "Dockerfile", "Kubernetes", "Terraform"}

	tests := []struct {
		name            string
		cliPlatforms    []string
		onlyPlatforms   []string
		ignorePlatforms []string
		want            []string
	}{
		{
			name:         "no filters returns cli platforms unchanged",
			cliPlatforms: all,
			want:         all,
		},
		{
			name:          "only-platforms restricts to subset",
			cliPlatforms:  all,
			onlyPlatforms: []string{"Terraform", "Kubernetes"},
			want:          []string{"Terraform", "Kubernetes"},
		},
		{
			name:            "ignore-platforms removes entries",
			cliPlatforms:    all,
			ignorePlatforms: []string{"Dockerfile"},
			want:            []string{"Ansible", "CICD", "CloudFormation", "Kubernetes", "Terraform"},
		},
		{
			name:          "case-insensitive only-platforms",
			cliPlatforms:  all,
			onlyPlatforms: []string{"terraform"},
			want:          []string{"Terraform"},
		},
		{
			name:            "case-insensitive ignore-platforms",
			cliPlatforms:    all,
			ignorePlatforms: []string{"kubernetes"},
			want:            []string{"Ansible", "CICD", "CloudFormation", "Dockerfile", "Terraform"},
		},
		{
			name:            "only and ignore combined",
			cliPlatforms:    all,
			onlyPlatforms:   []string{"Terraform", "Kubernetes", "Dockerfile"},
			ignorePlatforms: []string{"Dockerfile"},
			want:            []string{"Kubernetes", "Terraform"},
		},
		{
			name:          "only-platforms not in cli list returns empty",
			cliPlatforms:  []string{"Terraform"},
			onlyPlatforms: []string{"Kubernetes"},
			want:          []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scan.ApplyPlatformFilters(tt.cliPlatforms, tt.onlyPlatforms, tt.ignorePlatforms)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestTerraformPlanFlag(t *testing.T) {
	tests := []struct {
		name     string
		flagSet  bool
		expected bool
	}{
		{
			name:     "flag is present in command definition",
			flagSet:  false,
			expected: false,
		},
		{
			name:     "flag defaults to false",
			flagSet:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify flag exists in scanAction command
			var foundFlag *cli.BoolFlag
			for _, flag := range scanAction.Flags {
				if boolFlag, ok := flag.(*cli.BoolFlag); ok && boolFlag.Name == "x-terraform-plan" {
					foundFlag = boolFlag
					break
				}
			}

			assert.NotNil(t, foundFlag, "x-terraform-plan flag should be defined")
			assert.True(t, foundFlag.Hidden, "x-terraform-plan flag should be hidden")
			assert.Equal(t, false, foundFlag.Value, "x-terraform-plan flag should default to false")
			assert.Contains(t, foundFlag.Usage, "experimental", "flag usage should indicate experimental status")
		})
	}
}

func TestValidateQueriesPaths(t *testing.T) {
	tmp := t.TempDir()

	validDir := filepath.Join(tmp, "queries")
	require.NoError(t, os.Mkdir(validDir, 0o755))

	missingPath := filepath.Join(tmp, "missing")

	filePath := filepath.Join(tmp, "queries.rego")
	require.NoError(t, os.WriteFile(filePath, []byte("package test"), 0o644))

	tests := []struct {
		name    string
		paths   []string
		wantErr string
	}{
		{
			name:  "valid dir",
			paths: []string{validDir},
		},
		{
			name:    "non-existent path",
			paths:   []string{missingPath},
			wantErr: "invalid queries path",
		},
		{
			name:    "path is a file",
			paths:   []string{filePath},
			wantErr: "is not a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateQueriesPaths(tt.paths)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, got, len(tt.paths))
			assert.True(t, filepath.IsAbs(got[0]))
		})
	}
}
