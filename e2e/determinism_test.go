package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/e2e/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	determinismFixtureDir    = "determinism"
	determinismRunsPerWorker = 4

	namespaceFinding  = "Namespace fixture finding"
	dockerfileFinding = "Dockerfile fixture finding"
	helmFinding       = "Helm fixture finding"
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

const dockerfileRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some document in input.document
	some image, instructions in document.command
	some instruction in instructions
	instruction.Cmd == "run"
	words := split(instruction.Value[0], " ")
	words[0] == "groupadd"
	words[1] == "--gid"

	result := {
		"documentId": document.id,
		"resourceType": "dockerfile_container",
		"resourceName": words[2],
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [image, instruction.Original]),
	}
}
`

const helmRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some document in input.document
	document.kind == "Service"
	document.metadata.annotations["checksum/config"]

	result := {
		"documentId": document.id,
		"resourceType": "Service",
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

	fixture := filepath.Join("fixtures", determinismFixtureDir)
	workers := []string{"1", "8"}
	repo := createTempRepo(t)
	input := filepath.Join(repo, "inputs")
	require.NoError(t, os.CopyFS(input, os.DirFS(fixture)))
	bundle := writeDeterminismBundle(t)

	var wantPayload, wantSARIF []byte
	for round := 1; round <= determinismRunsPerWorker; round++ {
		for _, count := range workers {
			payload, sarif := scanDeterminismFixture(t, scanner, repo, input, bundle, count)
			if wantPayload == nil {
				requireDeterminismPayload(t, payload)
				requireDeterminismFindings(t, sarif)
				wantPayload, wantSARIF = payload, sarif
				continue
			}
			// Compare the emitted payload directly, including document IDs and order.
			assert.True(t, bytes.Equal(wantPayload, payload),
				"payload bytes differ with GOMAXPROCS=%s in round %d (first %x, got %x)",
				count, round, sha256.Sum256(wantPayload), sha256.Sum256(payload))
			assert.True(t, bytes.Equal(wantSARIF, sarif),
				"SARIF bytes differ with GOMAXPROCS=%s in round %d (first %x, got %x)",
				count, round, sha256.Sum256(wantSARIF), sha256.Sum256(sarif))
		}
	}
}

func requireDeterminismPayload(t *testing.T, payload []byte) {
	t.Helper()
	for _, marker := range []string{
		"multi-first", "multi-second", "alpha-team", "beta-team",
		"checksum/config", "order-alpha", "order-theta", "groupadd --gid 1000",
	} {
		require.Contains(t, string(payload), marker)
	}

	var parsed struct {
		Documents []struct {
			ID   string `json:"id"`
			File string `json:"file"`
		} `json:"document"`
	}
	require.NoError(t, json.Unmarshal(payload, &parsed))
	require.NotEmpty(t, parsed.Documents)
	ids := make(map[string]string, len(parsed.Documents))
	for _, doc := range parsed.Documents {
		require.NotEmpty(t, doc.ID, "missing document ID for %s", doc.File)
		require.NotContains(t, ids, doc.ID, "duplicate document ID for %s and %s", ids[doc.ID], doc.File)
		ids[doc.ID] = doc.File
	}
}

func requireDeterminismFindings(t *testing.T, sarif []byte) {
	t.Helper()
	var report struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(sarif, &report))
	require.Len(t, report.Runs, 1)

	want := map[string]string{
		namespaceFinding:  "multi.yaml",
		dockerfileFinding: "Dockerfile",
		helmFinding:       "first/templates/service.yaml",
	}
	for _, result := range report.Runs[0].Results {
		suffix, expected := want[result.RuleID]
		for _, location := range result.Locations {
			if expected && strings.HasSuffix(location.PhysicalLocation.ArtifactLocation.URI, suffix) {
				delete(want, result.RuleID)
			}
		}
	}
	require.Empty(t, want, "SARIF must contain findings at the Kubernetes, Dockerfile and Helm fixture paths")
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
	require.Equal(t, 40, status.ExitCode(), "%s", log) // The pinned rules report medium findings.

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
	rules := &datadog.Ruleset{
		ID:   "default-ruleset",
		Name: "Default",
		Rules: []*datadog.Rule{
			determinismRule("kubernetes-fixture-namespace", namespaceFinding, "Kubernetes", namespaceRule),
			determinismRule("dockerfile-fixture-group-id", dockerfileFinding, "Dockerfile", dockerfileRule),
			determinismRule("kubernetes-fixture-helm", helmFinding, "Kubernetes", helmRule),
		},
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

func determinismRule(id, name, platform, query string) *datadog.Rule {
	return &datadog.Rule{
		ID:               id,
		Name:             name,
		ShortDescription: name,
		Description:      name,
		Platform:         platform,
		Type:             "rego",
		RegoQuery:        []byte(query),
		Severity:         "MEDIUM",
		Category:         "Best Practices",
		IsPublished:      true,
	}
}
