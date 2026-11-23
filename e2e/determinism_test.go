package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/e2e/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const namespaceRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some document in input.document
	document.kind == "Namespace"

	result := {
		"documentId": document.id,
		"resourceType": "Namespace",
		"resourceName": document.metadata.name,
		"searchKey": "metadata.name",
	}
}
`

var (
	driverVersion = regexp.MustCompile(`("name"\s*:\s*"Datadog IaC Scanning",\s*"version"\s*:\s*)"[^"]*"`)
	sarifDuration = regexp.MustCompile(`"DATADOG_EXECUTION_TIME_SECS:[^"]*"`)
)

func Test_E2E_ScanOutputDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E tests in short mode")
	}
	scanner, err := filepath.Abs(utils.GetScannerLocalBin())
	require.NoError(t, err)
	if _, err := os.Stat(scanner); os.IsNotExist(err) {
		t.Skip("build the scanner binary in bin/ to run CLI e2e tests")
	} else {
		require.NoError(t, err)
	}

	fixture := filepath.Join("fixtures", "determinism")
	// Add worker counts here to repeat the same scan with more schedules.
	workers := []string{"1", "8"}
	repo := createTempRepo(t)
	input := filepath.Join(repo, "inputs")
	require.NoError(t, os.CopyFS(input, os.DirFS(fixture)))
	bundle := writeDeterminismBundle(t)

	var wantPayload, wantSARIF []byte
	for _, count := range workers {
		payload, sarif := scanDeterminismFixture(t, scanner, repo, input, bundle, count)
		if wantPayload == nil {
			// Require each fixture to reach the payload and the pinned rule
			// to produce findings, so an empty scan cannot satisfy the test.
			for _, marker := range []string{"multi-first", "multi-second", "alpha-team", "beta-team", "checksum/config", "groupadd"} {
				require.Contains(t, string(payload), marker)
			}
			require.Contains(t, string(sarif), "Namespace fixture finding")
			wantPayload, wantSARIF = payload, sarif
			continue
		}
		assert.True(t, bytes.Equal(wantPayload, payload),
			"payload bytes differ with GOMAXPROCS=%s (first %x, got %x)", count, sha256.Sum256(wantPayload), sha256.Sum256(payload))
		assert.True(t, bytes.Equal(wantSARIF, sarif),
			"SARIF bytes differ with GOMAXPROCS=%s (first %x, got %x)", count, sha256.Sum256(wantSARIF), sha256.Sum256(sarif))
	}
}

func scanDeterminismFixture(t *testing.T, scanner, repo, input, bundle, workers string) ([]byte, []byte) {
	t.Helper()
	output := t.TempDir()
	payloadPath := filepath.Join(output, "payload.json")
	const sarifName = "result.sarif"
	// The binary and paths are built by the test.
	//nolint:gosec
	cmd := exec.CommandContext(t.Context(), scanner, "scan", "--path", input, "--type", "Kubernetes,Dockerfile",
		"--offline-bundle-path", bundle, "--payload-path", payloadPath, "--output-path", output, "--output-name", sarifName)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+workers)
	log, err := cmd.CombinedOutput()
	var status *exec.ExitError
	require.ErrorAs(t, err, &status, "%s", log)
	require.Equal(t, 40, status.ExitCode(), "%s", log) // The pinned rule reports medium findings.

	payload, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	sarif, err := os.ReadFile(filepath.Join(output, sarifName))
	require.NoError(t, err)
	// Remove the two volatile SARIF values while preserving the remaining
	// bytes, including the order in which the scanner emitted results.
	sarif = driverVersion.ReplaceAll(sarif, []byte(`${1}""`))
	sarif = sarifDuration.ReplaceAll(sarif, []byte(`"DATADOG_EXECUTION_TIME_SECS:"`))
	return payload, sarif
}

func writeDeterminismBundle(t *testing.T) string {
	t.Helper()
	bundle := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bundle, "config.yaml"), nil, 0o600))
	const ruleName = "Namespace fixture finding"
	rules := &datadog.Ruleset{
		ID:   "default-ruleset",
		Name: "Default",
		Rules: []*datadog.Rule{{
			ID:               "kubernetes-fixture-namespace",
			Name:             ruleName,
			ShortDescription: ruleName,
			Description:      ruleName,
			Platform:         "Kubernetes",
			Type:             "rego",
			RegoQuery:        []byte(namespaceRule),
			Severity:         "MEDIUM",
			Category:         "Best Practices",
			IsPublished:      true,
		}},
	}
	libraries := map[string]datadog.Library{
		"common":     {ID: "common", RegoCode: "package generic.common\n"},
		"k8s":        {ID: "k8s", RegoCode: "package generic.k8s\n"},
		"dockerfile": {ID: "dockerfile", RegoCode: "package generic.dockerfile\n"},
	}
	for file, value := range map[string]any{"rules.json": rules, "libraries.json": libraries} {
		data, err := json.Marshal(value)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(bundle, file), data, 0o600))
	}
	return bundle
}
