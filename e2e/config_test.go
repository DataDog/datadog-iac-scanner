package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/e2e/utils"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_E2E_Config - Verifies that only local IaC configuration parse errors cause
// the scanner to exit with InvalidConfigErrorCode (127). Remote API errors (e.g.,
// unreachable Datadog backend) must not be misclassified as config errors and must
// exit with the generic engine error code (126).
func Test_E2E_Config(t *testing.T) {
	localBin := utils.GetScannerLocalBin()
	// Make sure that the scanner binary is available.
	if _, err := os.Stat(localBin); os.IsNotExist(err) {
		t.Skip("E2E local execution must have a scanner binary in the 'bin' folder.\nPath not found: " + localBin)
	}

	if testing.Short() {
		t.Skip("skipping E2E tests in short mode.")
	}

	tests := []struct {
		name       string
		configFile string // empty = no config written
		content    string
		wantStatus int
	}{
		// Local parse errors → 127
		{
			name:       "invalid new format - unknown field",
			configFile: "code-security.datadog.yaml",
			content:    "schema-version: v1.2\niac:\n  xinvalid: abc",
			wantStatus: 127,
		},
		{
			name:       "invalid new format - future major schema version",
			configFile: "code-security.datadog.yaml",
			content:    "schema-version: v2.1\niac:",
			wantStatus: 127,
		},
		{
			name:       "invalid new format - malformed YAML",
			configFile: "code-security.datadog.yaml",
			content:    "schema-version: [invalid",
			wantStatus: 127,
		},
		{
			name:       "invalid legacy format - malformed YAML",
			configFile: "dd-iac-scan.config",
			content:    "bad: [yaml:",
			wantStatus: 127,
		},
		{
			name:       "invalid new format - path escaping repo root",
			configFile: "code-security.datadog.yaml",
			content:    "schema-version: v1.2\niac:\n  global-config:\n    ignore-paths:\n      - ../../outside",
			wantStatus: 127,
		},
		// Valid / absent configs → 0
		{
			name:       "valid new format",
			configFile: "code-security.datadog.yaml",
			content:    "schema-version: v1.2\niac:\n  ignore-rules: []",
			wantStatus: 0,
		},
		{
			name:       "valid legacy format",
			configFile: "dd-iac-scan.config",
			content:    "exclude-categories: []",
			wantStatus: 0,
		},
		{
			name:       "no config file",
			configFile: "",
			content:    "",
			wantStatus: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			repoDir := createTempRepo(t)

			if tt.configFile != "" {
				cfgPath := filepath.Join(repoDir, tt.configFile)
				require.NoError(t, os.WriteFile(cfgPath, []byte(tt.content), 0600))
			}

			out, err := utils.RunCommand([]string{"scan", "-p", repoDir, "-o", repoDir})
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, out.Status)
		})
	}
}

// Test_E2E_Config_RemoteError - Verifies that a Datadog API failure (network error
// when credentials are present) does NOT produce InvalidConfigErrorCode (127). It
// must exit with the generic engine error code (126) instead.
func Test_E2E_Config_RemoteError(t *testing.T) {
	localBin := utils.GetScannerLocalBin()
	// Make sure that the scanner binary is available.
	if _, err := os.Stat(localBin); os.IsNotExist(err) {
		t.Skip("E2E local execution must have a scanner binary in the 'bin' folder.\nPath not found: " + localBin)
	}

	if testing.Short() {
		t.Skip("skipping E2E tests in short mode.")
	}

	repoDir := createTempRepo(t)
	// A syntactically valid config so the local parse step succeeds.
	cfgPath := filepath.Join(repoDir, "code-security.datadog.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("schema-version: v1.2\niac:\n  ignore-rules: []\n"), 0600))

	// Pass credentials so GetRemoteConfig fires, pointed at a port that refuses
	// connections so it errors immediately without touching any real Datadog endpoint.
	cmd := exec.Command(localBin, "scan", "-p", repoDir, "-o", repoDir)
	cmd.Env = append(os.Environ(),
		"DD_API_KEY=test-key",
		"DD_APP_KEY=test-app-key",
		"DD_SITE=127.0.0.1:1", // nothing listens on port 1 → instant connection refused
	)
	_, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			require.NoError(t, err)
		}
	}

	assert.Equal(t, 126, exitCode, "Datadog API network error must not be misclassified as an invalid config error")
}

// createTempRepo initialises an isolated git repository in a temp directory.
// The repo has one commit and a fake origin remote, satisfying the scanner's
// requirement for HEAD, branch, and remote URL.
func createTempRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://example.com/test-repo.git"},
	})
	require.NoError(t, err)

	// A comment-only Terraform file produces no violations, so valid-config
	// tests reliably exit 0.
	tfPath := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(tfPath, []byte("# no resources\n"), 0600))

	w, err := repo.Worktree()
	require.NoError(t, err)

	_, err = w.Add("main.tf")
	require.NoError(t, err)

	_, err = w.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com"},
	})
	require.NoError(t, err)

	return dir
}
