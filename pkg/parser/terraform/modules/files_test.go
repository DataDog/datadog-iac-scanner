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

	files, err := LoadTFFilesFromDir(dir, "")
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

	files, err := LoadTFFilesFromDir(selected, packageRoot)
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, filepath.Join(selected, "linked.tf"), files[0].FilePath)
}
