/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputePackageDigestIsStableAndContentSensitive(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "nested"), 0o755))
	file := filepath.Join(root, "nested", "main.tf")
	require.NoError(t, os.WriteFile(file, []byte("first"), 0o644))

	first, err := ComputePackageDigest(t.Context(), root)
	require.NoError(t, err)
	again, err := ComputePackageDigest(t.Context(), root)
	require.NoError(t, err)
	require.Equal(t, first, again)

	require.NoError(t, os.WriteFile(file, []byte("second"), 0o644))
	second, err := ComputePackageDigest(t.Context(), root)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}

func TestWalkPackageDigestMatchesComputeWhateverTheVisitorReads(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte("resource {}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a", "b", "vars.tf"), []byte("variable {}"), 0o644))
	want, err := ComputePackageDigest(t.Context(), root)
	require.NoError(t, err)

	var dirs, files []string
	contents := map[string]string{}
	got, err := WalkPackageDigest(t.Context(), root, PackageVisitor{
		Dir: func(relative string) error {
			dirs = append(dirs, relative)
			return nil
		},
		File: func(relative, _ string, _ fs.FileInfo, content io.Reader) error {
			files = append(files, relative)
			prefix := make([]byte, 3)
			n, readErr := io.ReadFull(content, prefix)
			require.NoError(t, readErr)
			contents[relative] = string(prefix[:n])
			return nil
		},
	})
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, []string{".", "a", filepath.Join("a", "b")}, dirs)
	require.Equal(t, []string{filepath.Join("a", "b", "vars.tf"), "main.tf"}, files)
	require.Equal(t, "var", contents[filepath.Join("a", "b", "vars.tf")])

	fullRead, err := WalkPackageDigest(t.Context(), root, PackageVisitor{
		File: func(_, _ string, _ fs.FileInfo, content io.Reader) error {
			_, copyErr := io.Copy(io.Discard, content)
			return copyErr
		},
	})
	require.NoError(t, err)
	require.Equal(t, want, fullRead)
}

func TestWalkPackageDigestStopsOnVisitorError(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte("x"), 0o644))
	_, err := WalkPackageDigest(t.Context(), root, PackageVisitor{
		File: func(string, string, fs.FileInfo, io.Reader) error {
			return errors.New("visitor failed")
		},
	})
	require.ErrorContains(t, err, "visitor failed")
}
