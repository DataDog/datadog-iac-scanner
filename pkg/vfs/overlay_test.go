/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package vfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOverlay(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte("base"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vars.tf"), []byte("vars"), 0o644))

	o := NewOverlay(DiskFS{}, map[string][]byte{
		filepath.Join(dir, "main.tf"):  []byte("replaced"),
		filepath.Join(dir, "extra.tf"): []byte("added"),
	})

	got, err := o.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, "replaced", string(got))
	got, err = o.ReadFile(filepath.Join(dir, "vars.tf"))
	require.NoError(t, err)
	require.Equal(t, "vars", string(got))

	info, err := o.Stat(filepath.Join(dir, "extra.tf"))
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	require.Equal(t, int64(5), info.Size())

	entries, err := o.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		require.True(t, entry.Type().IsRegular())
		names = append(names, entry.Name())
	}
	require.Equal(t, []string{"extra.tf", "main.tf", "vars.tf"}, names)

	matches, err := o.Glob(filepath.Join(dir, "*.tf"))
	require.NoError(t, err)
	require.Len(t, matches, 3)

	// Base is never written.
	onDisk, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, "base", string(onDisk))
	_, err = os.Stat(filepath.Join(dir, "extra.tf"))
	require.True(t, os.IsNotExist(err))
}
