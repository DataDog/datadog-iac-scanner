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

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
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

func TestSelectConfigNamesIncludesJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "tf" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu"), []byte(`resource "x" "tofu" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.tf.json"), []byte(`{"resource":{}}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.tofu.json"), []byte(`{"resource":{}}`), 0o644))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	got := SelectConfigNames(entries, dir, nil, "")
	require.ElementsMatch(t, []string{"main.tofu", "extra.tofu.json"}, got)
}

func TestPlaceholderTarget(t *testing.T) {
	for _, data := range []string{
		"", "true", "false", "123", "1.2", "null", `"../shared.tf"`, `{"path":"../shared.tf"}`,
		"# ../shared.tf", "// ../shared.tf", "//shared.tf", "/* ../shared.tf */", "path = \"../shared.tf\"", "locals {}",
		" ../shared.tf", "../shared.tf ", "../shared.tf\nextra", "../shared.tf\n\n", "../shared file.tf", "notes.txt",
	} {
		t.Run(data, func(t *testing.T) {
			_, ok := placeholderTarget([]byte(data), false)
			require.False(t, ok)
		})
	}
	for _, data := range []string{
		"main.tf", "./main.tf", "../shared/main.tf\n", "../shared/main.tofu\r\n", "main.tf.json", "../RUNNER~1/shared.tf",
	} {
		_, ok := placeholderTarget([]byte(data), false)
		require.True(t, ok, data)
	}
}

func TestConfigPlaceholderConfinement(t *testing.T) {
	// Exercise Windows short path components on every platform.
	repo := filepath.Join(t.TempDir(), "CHECKO~1")
	require.NoError(t, os.Symlink(t.TempDir(), repo))
	canonicalRepo, err := filepath.EvalSymlinks(repo)
	require.NoError(t, err)
	ctx := WithLinkPlaceholderRoot(t.Context(), canonicalRepo)
	require.NoError(t, os.Mkdir(filepath.Join(repo, ".git"), 0o755))
	dir := filepath.Join(repo, "stack")
	require.NoError(t, os.Mkdir(dir, 0o755))
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.tf"), []byte("outside = true"), 0o644))
	relOutside, err := filepath.Rel(dir, filepath.Join(outside, "secret.tf"))
	require.NoError(t, err)
	require.NoError(t, os.Symlink(outside, filepath.Join(repo, "escape")))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "target.tf"), []byte("inside = true"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "chain.tf"), []byte("target.tf"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(repo, "stack.tf"), 0o755))
	for _, tt := range []struct {
		name, target, want string
	}{
		{"chain", "../chain.tf", "inside = true"},
		{"absolute alias", filepath.Join(repo, "target.tf"), "inside = true"},
		{"missing", "../missing.tf", ""},
		{"escape", filepath.ToSlash(relOutside), ""},
		{"absolute escape", filepath.Join(filepath.VolumeName(repo)+string(os.PathSeparator), "outside.tf"), ""},
		{"native escape", "../escape/secret.tf", ""},
		{"cycle", "./linked.tf", ""},
		{"directory", "../stack.tf", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, "linked.tf")
			require.NoError(t, os.WriteFile(path, []byte(tt.target), 0o644))
			data, err := ReadConfigFile(ctx, vfs.DiskFS{}, path, "")
			if tt.want != "" {
				require.NoError(t, err)
				require.Equal(t, tt.want, string(data))
			} else {
				require.ErrorIs(t, err, ErrSkippedLinkPlaceholder)
			}
		})
	}
}

func TestConfigPlaceholdersRespectBoundaryAndSize(t *testing.T) {
	repo := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(repo, ".git"), 0o755))
	pkg := filepath.Join(repo, "package")
	require.NoError(t, os.Mkdir(pkg, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "target.tf"), []byte("inside = true"), 0o644))
	path := filepath.Join(pkg, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte("../target.tf"), 0o644))
	_, err := ReadConfigFile(t.Context(), vfs.DiskFS{}, path, pkg)
	require.ErrorIs(t, err, ErrSkippedLinkPlaceholder, "explicit package root must override the outer repository")
	canonicalPkg, err := filepath.EvalSymlinks(pkg)
	require.NoError(t, err)
	ctx := WithLinkPlaceholderPackages(WithLinkPlaceholderRoot(t.Context(), repo), []string{repo, canonicalPkg})
	_, err = ReadConfigFile(ctx, vfs.DiskFS{}, path, "")
	require.ErrorIs(t, err, ErrSkippedLinkPlaceholder, "registered package must override the context root and .git discovery")
	alias := filepath.Join(repo, "alias")
	require.NoError(t, os.Symlink(pkg, alias))
	_, err = ReadConfigFile(ctx, vfs.DiskFS{}, filepath.Join(alias, "main.tf"), "")
	require.ErrorIs(t, err, ErrSkippedLinkPlaceholder, "package aliases must keep the narrowest registered boundary")
	_, err = ReadConfigFile(WithMaxConfigFileBytes(t.Context(), 5), vfs.DiskFS{}, path, repo)
	require.ErrorIs(t, err, ErrSkippedLinkPlaceholder)
	data, err := ReadConfigFile(t.Context(), vfs.NewMemFS(map[string][]byte{path: []byte("../target.tf")}), path, repo)
	require.NoError(t, err)
	require.Equal(t, "../target.tf", string(data), "pushed content must never follow host files")
}
