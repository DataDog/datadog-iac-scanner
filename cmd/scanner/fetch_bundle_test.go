package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/stretchr/testify/require"
)

func TestFetchBundleInvalidLocalConfigExitCode(t *testing.T) {
	repoPath := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(repoPath, "code-security.datadog.yaml"),
		[]byte("schema-version: [invalid"),
		0600,
	))

	err := fetchBundleAction.Run(t.Context(), []string{
		"fetch-bundle",
		"--repo-path", repoPath,
		"--repo-url", "https://example.com/repo",
		"--output-dir", t.TempDir(),
	})

	var exitErr *withExitCodeError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, constants.InvalidConfigErrorCode, exitErr.code)
}
