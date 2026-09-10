/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadTFFilesFromDirSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`resource "x" "main" {}`), 0o644))
	outside := filepath.Join(t.TempDir(), "outside.tf")
	require.NoError(t, os.WriteFile(outside, []byte(`resource "x" "outside" {}`), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "linked.tf")))

	files, err := LoadTFFilesFromDir(t.Context(), dir, "")
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, mainPath, files[0].FilePath)
}

func TestLoadTFFilesFromDirIncludesConfinedPackageSymlinks(t *testing.T) {
	packageRoot := t.TempDir()
	selected := filepath.Join(packageRoot, "modules", "selected")
	shared := filepath.Join(packageRoot, "modules", "shared")
	require.NoError(t, os.MkdirAll(selected, 0o755))
	require.NoError(t, os.MkdirAll(shared, 0o755))
	sharedMain := filepath.Join(shared, "main.tf")
	require.NoError(t, os.WriteFile(sharedMain, []byte(`resource "x" "shared" {}`), 0o644))
	require.NoError(t, os.Symlink(sharedMain, filepath.Join(selected, "linked.tf")))

	files, err := LoadTFFilesFromDir(t.Context(), selected, packageRoot)
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, filepath.Join(selected, "linked.tf"), files[0].FilePath)
}

func TestLoadTFFilesFromDir_KeepsTofuAndTf(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "shadowed" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu"), []byte(`resource "x" "live" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.tf"), []byte(`resource "x" "other" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf.json"), []byte(`{"resource":{}}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu.json"), []byte(`{"resource":{}}`), 0o644))

	files, err := LoadTFFilesFromDir(t.Context(), dir, "")
	require.NoError(t, err)
	got := make([]string, 0, len(files))
	for _, f := range files {
		got = append(got, filepath.Base(f.FilePath))
	}
	require.ElementsMatch(t, []string{"main.tf", "main.tofu", "other.tf", "main.tf.json", "main.tofu.json"}, got)
}

func TestSelectHCLConfigNamesRespectsMergeAllow(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "tf" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu"), []byte(`resource "x" "tofu" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tf"), []byte(`variable "name" {}`), 0o644))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	allow := map[string]struct{}{
		filepath.ToSlash(filepath.Join(dir, "main.tf")): {},
	}
	require.Equal(t, []string{"main.tf", "variables.tf"}, SelectHCLConfigNames(entries, dir, allow, ""))
	require.Equal(t, []string{"main.tofu", "variables.tf"}, SelectHCLConfigNames(entries, dir, nil, ""))

	both := map[string]struct{}{
		filepath.ToSlash(filepath.Join(dir, "main.tf")):   {},
		filepath.ToSlash(filepath.Join(dir, "main.tofu")): {},
	}
	require.Equal(t, []string{"variables.tf", "main.tf"}, SelectHCLConfigNames(entries, dir, both, "main.tf"))
	require.Equal(t, []string{"main.tofu", "variables.tf"}, SelectHCLConfigNames(entries, dir, both, "main.tofu"))
	require.Equal(t, []string{"main.tofu", "variables.tf"}, SelectHCLConfigNames(entries, dir, both, ""))
}
