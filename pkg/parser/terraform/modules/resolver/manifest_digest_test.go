/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
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
