package test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/require"
)

// offlineBundleRule is a self-contained rule (no library helpers) that flags an
// aws_s3_bucket resource with versioning explicitly disabled.
const offlineBundleRule = `package datadog

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

// Test_E2EOfflineBundle exercises the same code path as `scan
// --offline-bundle-path`: it writes stub rules.json/libraries.json files in the
// format `fetch-bundle` produces, loads them via datadog.NewLocalFileClient, and
// runs a scan against them through a DatadogSource, asserting the offline
// pipeline finds the expected violation without any network access.
func Test_E2EOfflineBundle(t *testing.T) {
	dir := t.TempDir()

	ruleset := &datadog.Ruleset{
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
				RegoQuery:        []byte(offlineBundleRule),
				Severity:         "HIGH",
				Category:         "Best Practices",
				IsPublished:      true,
			},
		},
	}
	libraries := map[string]datadog.Library{
		"common":    {ID: "common", RegoCode: "package generic.common\n"},
		"terraform": {ID: "terraform", RegoCode: "package generic.terraform\n"},
	}

	rulesPath := filepath.Join(dir, "rules.json")
	librariesPath := filepath.Join(dir, "libraries.json")
	writeJSON(t, rulesPath, ruleset)
	writeJSON(t, librariesPath, libraries)

	client, err := datadog.NewLocalFileClient(rulesPath, librariesPath)
	require.NoError(t, err)

	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{filepath.Join("fixtures", "no-exclusions.tf")}
	params.OutputPath = t.TempDir()
	params.Platform = []string{"terraform"}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
	}

	metadata, err := console.ExecuteScan(ctx, params, scan.WithQuerySourceFactory(
		func(_ context.Context, paramsPlatforms []string) (source.QueriesSource, error) {
			return source.NewDatadogSource(client, source.WithWantedPlatforms(paramsPlatforms))
		},
	))
	require.NoError(t, err)

	require.Equal(t, 1, metadata.Stats.Files, "the fixture file should have been scanned")
	require.Equal(t, 1, metadata.Stats.Violations, "the offline bundle's rule should have fired exactly once")
	require.Contains(t, metadata.Stats.ViolationBreakdowns["HIGH"], "terraform-s3-bucket-versioning-disabled")
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, 0o600))
}
