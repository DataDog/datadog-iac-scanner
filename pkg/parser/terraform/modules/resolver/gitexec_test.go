/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitProcConcurrencyIsNetworkSizedAndOverridable(t *testing.T) {
	t.Setenv("IAC_MODULE_GIT_CONCURRENCY", "")
	require.Equal(t, max(defaultGitProcConcurrency, runtime.GOMAXPROCS(0)), gitProcConcurrency())

	t.Setenv("IAC_MODULE_GIT_CONCURRENCY", "3")
	require.Equal(t, 3, gitProcConcurrency())

	for _, invalid := range []string{"0", "-1", "many"} {
		t.Setenv("IAC_MODULE_GIT_CONCURRENCY", invalid)
		require.Equal(t, max(defaultGitProcConcurrency, runtime.GOMAXPROCS(0)), gitProcConcurrency())
	}
}

func TestGitLocalInDirDisablesLazyFetch(t *testing.T) {
	cmd := gitLocalInDir(t.Context(), "/repo.git", "cat-file", "-t", "HEAD")
	require.Contains(t, cmd.Env, "GIT_NO_LAZY_FETCH=1")
	require.Equal(t, "git", filepath.Base(cmd.Args[0]))
	require.Equal(t, []string{"--git-dir", gitSafePath("/repo.git"), "cat-file", "-t", "HEAD"}, cmd.Args[1:])
}
