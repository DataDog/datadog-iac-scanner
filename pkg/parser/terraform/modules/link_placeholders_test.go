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
	for _, data := range []string{"main.tf", "./main.tf", "../shared/main.tf\n", "../shared/main.tofu\r\n", "main.tf.json"} {
		_, ok := placeholderTarget([]byte(data), false)
		require.True(t, ok, data)
	}
}

func TestConfigPlaceholderConfinement(t *testing.T) {
	repo := t.TempDir()
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
			data, err := ReadConfigFile(t.Context(), vfs.DiskFS{}, path, "")
			if tt.want != "" {
				require.NoError(t, err)
				require.Equal(t, tt.want, string(data))
			} else {
				require.ErrorIs(t, err, ErrSkippedLinkPlaceholder)
			}
		})
	}
}

func TestModuleDirectoryPlaceholders(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	require.NoError(t, os.Symlink(t.TempDir(), repo))
	actual := filepath.Join(repo, "actual", "nested")
	require.NoError(t, os.MkdirAll(actual, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "alias"), []byte("./actual"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "chain"), []byte("alias"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "missing"), []byte("./gone"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "escape"), []byte("../outside"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "cycle"), []byte("./cycle"), 0o644))
	for _, tt := range []struct {
		source, want string
	}{
		{"./chain/nested", actual},
		{"./missing", ""}, {"./escape", ""}, {"./cycle", ""},
	} {
		t.Run(tt.source, func(t *testing.T) {
			resolved, err := ResolveModuleDir(t.Context(), vfs.DiskFS{}, repo, filepath.Join(repo, tt.source), repo)
			if tt.want != "" {
				require.NoError(t, err)
				require.Equal(t, tt.want, resolved)
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
	_, err = ReadConfigFile(WithMaxConfigFileBytes(t.Context(), 5), vfs.DiskFS{}, path, repo)
	require.ErrorIs(t, err, ErrSkippedLinkPlaceholder)
	data, err := ReadConfigFile(t.Context(), vfs.NewMemFS(map[string][]byte{path: []byte("../target.tf")}), path, repo)
	require.NoError(t, err)
	require.Equal(t, "../target.tf", string(data), "pushed content must never follow host files")
}
