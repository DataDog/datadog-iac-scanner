/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDefaultChainAnchorsRelativeCacheRootToWorkingDirectory(t *testing.T) {
	workDir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	t.Chdir(workDir)

	chain, err := NewDefaultChain(t.Context(), &DefaultChainConfig{FetchRemote: true, CacheRoot: "module-cache"})
	require.NoError(t, err)

	want := filepath.Join(workDir, "module-cache")
	var checked int
	for _, r := range chain.resolvers {
		switch typed := r.(type) {
		case *BareGitResolver:
			require.Equal(t, ModuleCacheSubdir(want, CacheSubdirGitBare), typed.CacheDir)
			checked++
		case *LocalGitRefResolver:
			require.Equal(t, ModuleCacheSubdir(want, CacheSubdirGitLocal), typed.CacheDir)
			checked++
		}
	}
	require.Equal(t, 2, checked)
}
