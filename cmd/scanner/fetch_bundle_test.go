package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestFetchBundleInvalidLocalConfigExitCode(t *testing.T) {
	repoPath := t.TempDir()
	configPath := filepath.Join(repoPath, config.ConfigFileNameBase+".yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("schema-version: v1.4\niac: [\n"), 0644))

	err := fetchBundleAction.Run(t.Context(), []string{
		"fetch-bundle",
		"--repo-path", repoPath,
		"--repo-url", "https://example.com/repo",
		"--output-dir", t.TempDir(),
	})

	var exitErr *withExitCodeError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, constants.InvalidConfigErrorCode, exitErr.code)
	require.ErrorContains(t, err, "error reading the configuration")
}
