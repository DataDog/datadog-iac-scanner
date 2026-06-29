package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v3"
)

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

func TestCollectTerraformFilesAcceptsSingleFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.tf")
	err := os.WriteFile(file, []byte(`module "x" { source = local.module_source }`), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, "locals.tf"), []byte(`locals { module_source = "example/x/aws" }`), 0o644)
	require.NoError(t, err)
	nested := filepath.Join(dir, "nested")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	err = os.WriteFile(filepath.Join(nested, "child.tf"), []byte(`locals { module_source = "wrong/x/aws" }`), 0o644)
	require.NoError(t, err)

	files, err := collectTerraformFiles([]string{file})

	require.NoError(t, err)
	require.Len(t, files, 2)
}

func TestAllowedModuleFilesForSingleFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.tf")
	err := os.WriteFile(file, []byte(`module "x" { source = "example/x/aws" }`), 0o644)
	require.NoError(t, err)

	files, err := collectTerraformFiles([]string{file})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{file: true}, allowedModuleFiles([]string{file}, files))
}

func TestAllowedModuleFilesIncludesDirectoryInputs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.tf")
	other := filepath.Join(dir, "other.tf")
	err := os.WriteFile(file, []byte(`module "x" { source = "example/x/aws" }`), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(other, []byte(`module "y" { source = "example/y/aws" }`), 0o644)
	require.NoError(t, err)

	files, err := collectTerraformFiles([]string{dir, file})
	require.NoError(t, err)
	got := allowedModuleFiles([]string{dir, file}, files)

	require.Equal(t, true, got[file])
	require.Equal(t, true, got[other])
}

func TestModuleTuningFlagsHidden(t *testing.T) {
	for _, name := range []string{"module-fetch-timeout", "max-module-bytes-total"} {
		var found *cli.IntFlag
		for _, flag := range scanAction.Flags {
			if intFlag, ok := flag.(*cli.IntFlag); ok && intFlag.Name == name {
				found = intFlag
				break
			}
		}
		require.NotNil(t, found, "flag %q should be defined", name)
		require.True(t, found.Hidden, "flag %q should be hidden", name)
	}

	var allowlist *cli.StringSliceFlag
	for _, flag := range scanAction.Flags {
		if sliceFlag, ok := flag.(*cli.StringSliceFlag); ok && sliceFlag.Name == "module-host-allowlist" {
			allowlist = sliceFlag
			break
		}
	}
	require.NotNil(t, allowlist)
	require.True(t, allowlist.Hidden)

	var maxDepth *cli.IntFlag
	for _, flag := range scanAction.Flags {
		if intFlag, ok := flag.(*cli.IntFlag); ok && intFlag.Name == "module-max-depth" {
			maxDepth = intFlag
			break
		}
	}
	require.NotNil(t, maxDepth)
	require.False(t, maxDepth.Hidden)
	require.Contains(t, maxDepth.Usage, "traversing nested module calls")
	require.NotContains(t, maxDepth.Usage, "disables remote modules")

	var noRemote *cli.BoolFlag
	for _, flag := range scanAction.Flags {
		if boolFlag, ok := flag.(*cli.BoolFlag); ok && boolFlag.Name == "no-remote-modules" {
			noRemote = boolFlag
			break
		}
	}
	require.NotNil(t, noRemote)
	require.False(t, noRemote.Hidden)
	require.Contains(t, noRemote.Usage, "network module fetches")
}
