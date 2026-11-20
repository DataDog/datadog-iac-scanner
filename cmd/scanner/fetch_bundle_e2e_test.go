package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/DataDog/jsonapi"
	"github.com/stretchr/testify/require"
)

// fetchBundleE2ERule flags an aws_s3_bucket resource with versioning explicitly
// disabled, matching the fixture at test/e2e/fixtures/no-exclusions.tf.
const fetchBundleE2ERule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.versioning.enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].versioning", [name]),
	}
}
`

// Test_E2EFetchBundleThenOfflineScan exercises the full network-isolated
// workflow end to end: it runs the real `fetch-bundle` command against a stub
// Datadog server, then runs the real `scan` command with
// `--offline-bundle-path` pointing at the files fetch-bundle wrote, and
// asserts the offline scan reproduces the expected violation. Unlike
// pkg/datadog/local_file_client_test.go, this drives the actual CLI commands
// instead of constructing a datadog.Client and QueriesSource by hand.
func Test_E2EFetchBundleThenOfflineScan(t *testing.T) {
	for _, name := range []string{
		"DD_API_KEY", "DATADOG_API_KEY",
		"DD_APP_KEY", "DATADOG_APP_KEY",
		"DD_JWT_TOKEN", "DATADOG_JWT_TOKEN",
		"DD_SITE", "DATADOG_SITE",
		"DD_HOSTNAME", "DATADOG_HOSTNAME",
	} {
		t.Setenv(name, "")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/static-analysis/iac/rulesets/default-ruleset":
			ruleset := datadog.Ruleset{
				ID:   "default-ruleset",
				Name: "Default",
				Rules: []*datadog.Rule{
					{
						ID: "kubernetes-outcome", Name: "pod-outcome", ShortDescription: "Pod outcome", Description: "Pod outcome",
						Platform: "Kubernetes", Type: "rego", Severity: "HIGH", Category: "Best Practices", IsPublished: true,
						RegoQuery: []byte(`package datadog
import rego.v1
DatadogPolicy contains result if {some doc in input.document;doc.kind=="Pod";result:={"documentId":doc.id,"resourceType":"Pod","resourceName":"retained","searchKey":"kind"}}`),
					},
					{
						ID:               "terraform-s3-bucket-versioning-disabled",
						Name:             "s3-bucket-versioning-disabled",
						ShortDescription: "S3 bucket versioning disabled",
						Description:      "S3 bucket versioning disabled",
						Platform:         "Terraform",
						Type:             "rego",
						RegoQuery:        []byte(fetchBundleE2ERule),
						Severity:         "HIGH",
						Category:         "Best Practices",
						IsPublished:      true,
					},
				},
			}
			body, err := jsonapi.Marshal(ruleset)
			require.NoError(t, err)
			w.Header().Add("content-type", "application/json")
			_, err = w.Write(body)
			require.NoError(t, err)
		case "/api/v2/static-analysis/iac/libraries":
			libraries := []*datadog.Library{
				{ID: "common", RegoCode: "package generic.common\n"},
				{ID: "terraform", RegoCode: "package generic.terraform\n"},
				{ID: "k8s", RegoCode: "package generic.k8s\n"},
			}
			body, err := jsonapi.Marshal(libraries)
			require.NoError(t, err)
			w.Header().Add("content-type", "application/json")
			_, err = w.Write(body)
			require.NoError(t, err)
		case "/api/v2/static-analysis/iac/rulesets/custom-ruleset":
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("DD_HOSTNAME", server.URL)

	repoPath := t.TempDir()
	// This is one Terraform configuration, not the directory of independent
	// examples that happen to share its resource names.
	fixture, err := os.ReadFile(filepath.Join("..", "..", "test", "e2e", "fixtures", "no-exclusions.tf"))
	require.NoError(t, err)
	fixturePath := filepath.Join(repoPath, "main.tf")
	require.NoError(t, os.WriteFile(fixturePath, fixture, 0600))
	runTestGit(t, repoPath, "init", "--initial-branch=main")
	runTestGit(t, repoPath, "remote", "add", "origin", "https://example.com/repo")
	runTestGit(t, repoPath, "add", "main.tf")
	runTestGit(t, repoPath, "-c", "user.name=Test User", "-c", "user.email=test@example.com",
		"-c", "commit.gpgsign=false", "commit", "-m", "fixture")
	bundleDir := t.TempDir()

	err = fetchBundleAction.Run(t.Context(), []string{
		"fetch-bundle",
		"--repo-path", repoPath,
		"--repo-url", "https://example.com/repo",
		"--output-dir", bundleDir,
	})
	require.NoError(t, err)

	for _, f := range []string{"config.yaml", "rules.json", "libraries.json", "manifest.json"} {
		require.FileExists(t, filepath.Join(bundleDir, f))
	}

	outputDir := t.TempDir()
	metadataPath := filepath.Join(outputDir, "metadata.json")

	err = scanAction.Run(t.Context(), []string{
		"scan",
		"--path", fixturePath,
		"--type", "terraform",
		"--output-path", outputDir,
		"--offline-bundle-path", bundleDir,
		"--metadata-path", metadataPath,
	})
	// runScan intentionally returns a non-nil error carrying a severity-based
	// exit code (here 50, for the HIGH violation) even on a successful scan;
	// see getExitCode. The metadata file is what confirms the scan succeeded.
	var exitErr *withExitCodeError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 50, exitErr.code)

	metadataBytes, err := os.ReadFile(filepath.Clean(metadataPath))
	require.NoError(t, err)
	var metadata scan.ScanMetadata
	require.NoError(t, json.Unmarshal(metadataBytes, &metadata))

	require.Equal(t, 1, metadata.Stats.Files, "the fixture file should have been scanned")
	require.Equal(t, 1, metadata.Stats.Violations, "the offline bundle's rule should have fired exactly once")
	require.Contains(t, metadata.Stats.ViolationBreakdowns["HIGH"], "terraform-s3-bucket-versioning-disabled")
	// The same CLI must persist a failed evaluation even when no trustworthy
	// finding can be produced from the now-invalid Terraform input domain.
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "invalid_override.tf"), []byte(`locals {`), 0600))
	failedOutput := t.TempDir()
	failedMetadata := filepath.Join(failedOutput, "metadata.json")
	err = scanAction.Run(t.Context(), []string{"scan", "--path", repoPath, "--type", "terraform", "--output-path", failedOutput, "--offline-bundle-path", bundleDir, "--metadata-path", failedMetadata})
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 126, exitErr.code)
	failedBytes, readErr := os.ReadFile(failedMetadata)
	require.NoError(t, readErr)
	var failed scan.ScanMetadata
	require.NoError(t, json.Unmarshal(failedBytes, &failed))
	require.Equal(t, 1, failed.FailedCoverage().Len())
	require.Zero(t, failed.Stats.Violations)
	reports, readErr := filepath.Glob(filepath.Join(failedOutput, "*.sarif"))
	require.NoError(t, readErr)
	require.Len(t, reports, 1)
	reportBytes, readErr := os.ReadFile(reports[0])
	require.NoError(t, readErr)
	var report struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool  `json:"executionSuccessful"`
				Notifications       []any `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(reportBytes, &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Invocations, 1)
	require.False(t, report.Runs[0].Invocations[0].ExecutionSuccessful)
	require.NotEmpty(t, report.Runs[0].Invocations[0].Notifications)

	for _, knownWitness := range []bool{false, true} {
		for _, formats := range []string{"simple-json", "simple-json,sarif", "sarif,simple-json"} {
			t.Run(fmt.Sprintf("witness=%t/formats=%s", knownWitness, formats), func(t *testing.T) {
				kind := "Service"
				if knownWitness {
					kind = "Pod"
				}
				require.NoError(t, os.WriteFile(filepath.Join(repoPath, "known.yaml"), []byte("apiVersion: v1\nkind: "+kind+"\nmetadata:\n  name: retained\n"), 0600))
				output := t.TempDir()
				metadataFile := filepath.Join(output, "metadata.json")
				err := scanAction.Run(t.Context(), []string{
					"scan", "--path", repoPath, "--type", "terraform,kubernetes", "--output-path", output,
					"--offline-bundle-path", bundleDir, "--metadata-path", metadataFile, "--report-format", formats,
				})
				var failedExit *withExitCodeError
				require.ErrorAs(t, err, &failedExit)
				require.Equal(t, 126, failedExit.code)
				body, readErr := os.ReadFile(metadataFile)
				require.NoError(t, readErr)
				var metadata scan.ScanMetadata
				require.NoError(t, json.Unmarshal(body, &metadata))
				require.Equal(t, 1, metadata.FailedCoverage().Len())
				expected := 0
				if knownWitness {
					expected = 1
				}
				require.Equal(t, expected, metadata.Stats.Violations)
				unsafeReports, readErr := filepath.Glob(filepath.Join(output, "*.simple.json"))
				require.NoError(t, readErr)
				require.Empty(t, unsafeReports)
				safeReports, readErr := filepath.Glob(filepath.Join(output, "*.sarif"))
				require.NoError(t, readErr)
				if strings.Contains(formats, "sarif") {
					require.Len(t, safeReports, 1)
					body, readErr := os.ReadFile(safeReports[0])
					require.NoError(t, readErr)
					var emitted struct {
						Runs []struct {
							Invocations []struct {
								ExecutionSuccessful bool `json:"executionSuccessful"`
							} `json:"invocations"`
						} `json:"runs"`
					}
					require.NoError(t, json.Unmarshal(body, &emitted))
					require.Len(t, emitted.Runs, 1)
					require.Len(t, emitted.Runs[0].Invocations, 1)
					require.False(t, emitted.Runs[0].Invocations[0].ExecutionSuccessful)
				} else {
					require.Empty(t, safeReports)
				}
			})
		}
	}

}
