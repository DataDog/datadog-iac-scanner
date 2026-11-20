/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

	files, err := LoadTFFilesFromDir(t.Context(), nil, dir, LoadOptions{})
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

	files, err := LoadTFFilesFromDir(t.Context(), nil, selected, LoadOptions{PackageRoot: packageRoot})
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, filepath.Join(selected, "linked.tf"), files[0].FilePath)
}

func TestLoadTFFilesFromDirSelectsActiveDialect(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "shadowed" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu"), []byte(`resource "x" "live" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.tf"), []byte(`resource "x" "other" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf.json"), []byte(`{"resource":{}}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu.json"), []byte(`{"resource":{}}`), 0o644))

	files, err := LoadTFFilesFromDir(t.Context(), nil, dir, LoadOptions{})
	require.NoError(t, err)
	got := make([]string, 0, len(files))
	for _, f := range files {
		got = append(got, filepath.Base(f.FilePath))
	}
	require.ElementsMatch(t, []string{"main.tofu", "other.tf", "main.tofu.json"}, got)
}

func TestSelectHCLConfigEntriesRespectsMergeAllow(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "tf" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu"), []byte(`resource "x" "tofu" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tf"), []byte(`variable "name" {}`), 0o644))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := func(entries []fs.DirEntry) []string {
		out := make([]string, len(entries))
		for i, entry := range entries {
			out[i] = entry.Name()
		}
		return out
	}

	allow := map[string]struct{}{
		filepath.ToSlash(filepath.Join(dir, "main.tf")): {},
	}
	require.Equal(t, []string{"main.tf", "variables.tf"}, names(SelectHCLConfigEntries(entries, dir, allow, "")))
	require.Equal(t, []string{"main.tofu", "variables.tf"}, names(SelectHCLConfigEntries(entries, dir, nil, "")))

	both := map[string]struct{}{
		filepath.ToSlash(filepath.Join(dir, "main.tf")):   {},
		filepath.ToSlash(filepath.Join(dir, "main.tofu")): {},
	}
	require.Equal(t, []string{"variables.tf", "main.tf"}, names(SelectHCLConfigEntries(entries, dir, both, "main.tf")))
	require.Equal(t, []string{"main.tofu", "variables.tf"}, names(SelectHCLConfigEntries(entries, dir, both, "main.tofu")))
	require.Equal(t, []string{"main.tofu", "variables.tf"}, names(SelectHCLConfigEntries(entries, dir, both, "")))
}

func TestSelectConfigEntriesIncludesJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "tf" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tofu"), []byte(`resource "x" "tofu" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.tf.json"), []byte(`{"resource":{}}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.tofu.json"), []byte(`{"resource":{}}`), 0o644))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	got := SelectConfigEntries(entries, dir, nil, "")
	names := make([]string, len(got))
	for i, entry := range got {
		names[i] = entry.Name()
	}
	require.ElementsMatch(t, []string{"main.tofu", "extra.tofu.json"}, names)
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

func TestLoadTFFilesFromDirFilesystemAuthority(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	host := `resource "x" "host" {}`
	owned := `resource "x" "owned" {}`
	require.NoError(t, os.WriteFile(path, []byte(host), 0o600))
	for _, tc := range []struct {
		name    string
		fs      vfs.FS
		dir     string
		limit   int64
		want    string
		count   int
		wantErr bool
	}{
		{name: "owned conflict", fs: vfs.NewMemFS(map[string][]byte{path: []byte(owned)}), dir: dir, want: owned, count: 1},
		{name: "owned size admits", fs: vfs.NewMemFS(map[string][]byte{path: []byte("{}")}), dir: dir, limit: 2, want: "{}", count: 1},
		{name: "owned size", fs: vfs.NewMemFS(map[string][]byte{path: []byte(owned)}), dir: dir, limit: 1, count: 0},
		{name: "missing never host", fs: vfs.NewMemFS(nil), dir: dir, wantErr: true},
		{name: "relative owned", fs: vfs.NewMemFS(map[string][]byte{"pushed/main.tf": []byte(owned)}), dir: "pushed", want: owned, count: 1},
		{name: "default disk", dir: dir, want: host, count: 1},
		{name: "explicit disk", fs: vfs.DiskFS{}, dir: dir, want: host, count: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, err := LoadTFFilesFromDir(t.Context(), tc.fs, tc.dir, LoadOptions{MaxBytes: tc.limit})
			if tc.wantErr {
				require.Error(t, err)
				require.Empty(t, files)
				return
			}
			require.NoError(t, err)
			require.Len(t, files, tc.count)
			if tc.count > 0 {
				require.Equal(t, tc.want, files[0].OriginalData)
				require.Equal(t, filepath.Join(tc.dir, "main.tf"), files[0].FilePath)
			}
		})
	}
}

func TestLoadTFFilesFromDirSelectionBeforeAdmission(t *testing.T) {
	const maxBytes int64 = 64
	const oversizedPadding = 2 * int(maxBytes)
	for _, tc := range []struct {
		name       string
		large      string
		skipped    string
		profile    string
		jsonSyntax bool
		limit      int64
		want       []string
	}{
		{name: "default healthy", want: []string{"main.tofu", "variables.tf"}},
		{name: "explicit TF normalized profile", profile: "normalized Terraform", want: []string{"main.tf", "variables.tf"}},
		{name: "explicit TF healthy", profile: "Terraform", want: []string{"main.tf", "variables.tf"}},
		{name: "empty module-call profile", profile: "empty", want: []string{"main.tofu", "variables.tf"}},
		{name: "unmatched module-call profile", profile: "unmatched", want: []string{"main.tofu", "variables.tf"}},
		{name: "default oversized winner", large: "main.tofu", limit: maxBytes, want: []string{"variables.tf"}},
		{name: "explicit TF oversized winner", large: "main.tf", profile: "Terraform", limit: maxBytes, want: []string{"variables.tf"}},
		{name: "default oversized inactive", large: "main.tf", limit: maxBytes, want: []string{"main.tofu", "variables.tf"}},
		{name: "explicit TF oversized inactive", large: "main.tofu", profile: "Terraform", limit: maxBytes, want: []string{"main.tf", "variables.tf"}},
		{name: "default oversized JSON winner", jsonSyntax: true, large: "main.tofu.json", limit: maxBytes, want: []string{"variables.tf"}},
		{name: "explicit TF oversized JSON winner", jsonSyntax: true, large: "main.tf.json", profile: "Terraform", limit: maxBytes, want: []string{"variables.tf"}},
		{name: "default outside symlink winner", skipped: "symlink", want: []string{"variables.tf"}},
		{name: "explicit TF outside symlink winner", profile: "Terraform", skipped: "symlink", want: []string{"variables.tf"}},
		{name: "default unavailable placeholder winner", skipped: "placeholder", want: []string{"variables.tf"}},
		{name: "explicit TF unavailable placeholder winner", profile: "Terraform", skipped: "placeholder", want: []string{"variables.tf"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			preferTF := tc.profile == "Terraform" || tc.profile == "normalized Terraform"
			tfName, tofuName := "main.tf", "main.tofu"
			if tc.jsonSyntax {
				tfName += ".json"
				tofuName += ".json"
			}
			winner := tofuName
			if preferTF {
				winner = tfName
			}
			for _, name := range []string{tfName, tofuName, "variables.tf"} {
				path := filepath.Join(dir, name)
				src := `module "n" {source="acme/network/aws"}`
				if tc.jsonSyntax && name != "variables.tf" {
					src = `{"module":{"n":{"source":"acme/network/aws"}}}`
				}
				if name == "variables.tf" {
					src = `variable "sibling" {default="visible"}`
				}
				if name == tc.large {
					src += "\n" + strings.Repeat(" ", oversizedPadding)
				}
				if name == winner {
					switch tc.skipped {
					case "symlink":
						outside := filepath.Join(t.TempDir(), name)
						require.NoError(t, os.WriteFile(outside, []byte(src), 0o600))
						require.NoError(t, os.Symlink(outside, path))
						continue
					case "placeholder":
						src = "./unavailable.tf"
					}
				}
				require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
			}
			var profile map[string]bool
			switch {
			case preferTF:
				path := filepath.Join(dir, tfName)
				if tc.profile == "normalized Terraform" {
					path = dir + string(filepath.Separator) + "." + string(filepath.Separator) + tfName
				}
				profile = map[string]bool{path: true, filepath.Join(dir, tofuName): false}
			case tc.profile == "empty":
				profile = map[string]bool{}
			case tc.profile == "unmatched":
				profile = map[string]bool{filepath.Join(dir, "unselected.tf"): true}
			}
			files, err := LoadTFFilesFromDir(t.Context(), nil, dir, LoadOptions{PackageRoot: dir, ModuleCallFiles: profile, MaxBytes: tc.limit})
			require.NoError(t, err)
			names := make([]string, 0, len(files))
			for _, file := range files {
				names = append(names, filepath.Base(file.FilePath))
			}
			require.ElementsMatch(t, tc.want, names)
			if tc.profile == "empty" || tc.profile == "unmatched" || tc.profile == "normalized Terraform" {
				calls, err := ParseTerraformModulesFromFiles(t.Context(), nil, files, profile)
				require.NoError(t, err)
				if tc.profile == "normalized Terraform" {
					require.Len(t, calls, 1, "loader and parser must normalize the same module-call profile")
				} else {
					require.Empty(t, calls, "an empty or unmatched module-call profile must never broaden to all calls")
				}
			}
		})
	}
}
