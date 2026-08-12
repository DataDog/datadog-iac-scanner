package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	bundleDir := t.TempDir()

	err := fetchBundleAction.Run(t.Context(), []string{
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
		"--path", filepath.Join("..", "..", "test", "e2e", "fixtures", "no-exclusions.tf"),
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
}
