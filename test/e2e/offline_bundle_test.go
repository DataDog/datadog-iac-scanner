package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	testhelpers "github.com/DataDog/datadog-iac-scanner/test"
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
	metadata := scanWithOfflineBundle(t, filepath.Join("fixtures", "no-exclusions.tf"), "Terraform", "terraform",
		&datadog.Rule{
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
		})

	require.Equal(t, 1, metadata.Stats.Files, "the fixture file should have been scanned")
	require.Equal(t, 1, metadata.Stats.Violations, "the offline bundle's rule should have fired exactly once")
	require.Contains(t, metadata.Stats.ViolationBreakdowns["HIGH"], "terraform-s3-bucket-versioning-disabled")
}

// templateConditionRule flags the jobs of a document that have a condition.
const templateConditionRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some i, j
	input.document[i].jobs[j].condition == "succeeded()"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "job",
		"resourceName": sprintf("%d", [j]),
		"searchKey": sprintf("jobs[%d].condition", [j]),
	}
}
`

// Test_E2ETemplateReferences scans the reproduction of scans that ran out of
// memory: templates that each include the previous one ten times, six levels
// deep, so that a million paths lead to the innermost template. Copying the
// content of each reference made the scan grow with the number of paths.
func Test_E2ETemplateReferences(t *testing.T) {
	const fanout, depth = 10, 6
	for name, tt := range map[string]struct {
		header         string
		wantFiles      int
		wantViolations int
	}{
		// condition: once matched the on: of a workflow.
		"azure pipelines templates are not workflows": {},
		"workflow templates": {
			header: "on: push\n",
			// Every template, and the root that includes the outermost one.
			wantFiles:      depth + 2,
			wantViolations: depth + 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			outermost, err := testhelpers.WriteTemplateChain(dir, fanout, depth, tt.header)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "pipeline.yml"),
				[]byte(fmt.Sprintf("%sjobs:\n  - template: %s\n", tt.header, filepath.Base(outermost))), 0o600))

			metadata := scanWithOfflineBundle(t, dir, "CICD", "cicd", &datadog.Rule{
				ID:               "cicd-job-condition",
				Name:             "job-condition",
				ShortDescription: "Job with a condition",
				Description:      "Job with a condition",
				Platform:         "CICD",
				Type:             "rego",
				RegoQuery:        []byte(templateConditionRule),
				Severity:         "LOW",
				Category:         "Best Practices",
				IsPublished:      true,
			})

			require.Equal(t, tt.wantFiles, metadata.Stats.Files)
			require.Equal(t, tt.wantViolations, metadata.Stats.Violations)
		})
	}
}

// scanWithOfflineBundle scans path, restricted to the platform of the rule,
// with a bundle made of that rule and stub libraries (the common one and
// library), as `fetch-bundle` would write, with no network access.
func scanWithOfflineBundle(t *testing.T, path, rulePlatform, library string, rule *datadog.Rule) scan.ScanMetadata {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	librariesPath := filepath.Join(dir, "libraries.json")
	writeJSON(t, rulesPath, &datadog.Ruleset{ID: "default-ruleset", Name: "Default", Rules: []*datadog.Rule{rule}})
	writeJSON(t, librariesPath, map[string]datadog.Library{
		"common": {ID: "common", RegoCode: "package generic.common\n"},
		library:  {ID: library, RegoCode: "package generic." + library + "\n"},
	})

	client, err := datadog.NewLocalFileClient(rulesPath, librariesPath)
	require.NoError(t, err)

	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{path}
	params.OutputPath = t.TempDir()
	params.Platform = []string{strings.ToLower(rulePlatform)}
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
	return metadata
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, 0o600))
}

// Failed source domains must remain visible after independent findings cross
// storage, metadata and every report boundary used by the scanner CLI.
func Test_E2EEvaluationOutcomes(t *testing.T) {
	for _, test := range []struct {
		name                      string
		failed, knownPod, unknown bool
	}{
		{name: "failed domain retains independent findings", failed: true, knownPod: true},
		{name: "failed domain with zero findings is not clean", failed: true},
		{name: "successful domains", knownPod: true},
		{name: "normal unknown is not a producer failure", unknown: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			tfDir := filepath.Join(root, "terraform")
			require.NoError(t, os.Mkdir(tfDir, 0700))
			tf := `resource "aws_s3_bucket" "same" {acl="private"}`
			if test.unknown {
				tf = "variable \"acl\" {}\nresource \"aws_s3_bucket\" \"same\" {acl=var.acl}"
			}
			require.NoError(t, os.WriteFile(filepath.Join(tfDir, "main.tf"), []byte(tf), 0600))
			if test.failed {
				require.NoError(t, os.WriteFile(filepath.Join(tfDir, "invalid_override.tf"), []byte(`locals {`), 0600))
			}
			kind := "Service"
			if test.knownPod {
				kind = "Pod"
			}
			require.NoError(t, os.WriteFile(filepath.Join(root, "main.yaml"), []byte("apiVersion: v1\nkind: "+kind+"\nmetadata:\n  name: retained\n"), 0600))
			query := func(platform, id, body string) *datadog.Rule {
				return &datadog.Rule{ID: id, Name: id, ShortDescription: id, Platform: platform, Type: "rego", RegoQuery: []byte(body), Severity: "HIGH", Category: "Best Practices", IsPublished: true}
			}
			rules := []*datadog.Rule{
				query("Terraform", "terraform-outcome", `package datadog
import rego.v1
DatadogPolicy contains result if {some doc in input.document;some name;doc.resource.aws_s3_bucket[name].acl=="public";result:={"documentId":doc.id,"resourceType":"aws_s3_bucket","resourceName":name,"searchKey":"acl"}}`),
				query("Kubernetes", "kubernetes-outcome", `package datadog
import rego.v1
DatadogPolicy contains result if {some doc in input.document;doc.kind=="Pod";result:={"documentId":doc.id,"resourceType":"Pod","resourceName":"retained","searchKey":"kind"}}`),
			}
			bundle := t.TempDir()
			rulesPath := filepath.Join(bundle, "rules.json")
			libsPath := filepath.Join(bundle, "libraries.json")
			writeJSON(t, rulesPath, &datadog.Ruleset{ID: "outcomes", Name: "outcomes", Rules: rules})
			writeJSON(t, libsPath, map[string]datadog.Library{"common": {ID: "common", RegoCode: "package generic.common\n"}, "terraform": {ID: "terraform", RegoCode: "package generic.terraform\n"}, "k8s": {ID: "k8s", RegoCode: "package generic.k8s\n"}})
			client, err := datadog.NewLocalFileClient(rulesPath, libsPath)
			require.NoError(t, err)
			params, ctx := scan.GetDefaultParameters(context.Background(), "")
			params.Path = []string{root}
			params.RepoPath = root
			params.OutputPath = t.TempDir()
			params.OutputName = "outcomes"
			params.ReportFormats = []string{"json", "sarif"}
			params.Platform = []string{"terraform", "kubernetes"}
			params.FlagEvaluator = featureflags.NewLocalEvaluator()
			params.SCIInfo = model.SCIInfo{RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"}}
			metadata, err := console.ExecuteScan(ctx, params, scan.WithQuerySourceFactory(func(_ context.Context, platforms []string) (source.QueriesSource, error) {
				return source.NewDatadogSource(client, source.WithWantedPlatforms(platforms))
			}))
			if test.failed {
				var incomplete *scan.IncompleteScanError
				require.ErrorAs(t, err, &incomplete)
				require.Equal(t, 1, metadata.FailedCoverage().Len())
			} else {
				require.NoError(t, err)
				require.Zero(t, metadata.FailedCoverage().Len())
			}
			expected := 0
			if test.knownPod {
				expected = 1
			}
			require.Equal(t, expected, metadata.Stats.Violations)
			jsonBody, readErr := os.ReadFile(filepath.Join(params.OutputPath, "outcomes.json"))
			require.NoError(t, readErr)
			var summary model.Summary
			require.NoError(t, json.Unmarshal(jsonBody, &summary))
			require.Equal(t, metadata.FailedCoverage().Len(), summary.FailedCoverage().Len())
			metadataBytes, marshalErr := json.Marshal(metadata)
			require.NoError(t, marshalErr)
			var roundtrip scan.ScanMetadata
			require.NoError(t, json.Unmarshal(metadataBytes, &roundtrip))
			require.Equal(t, metadata.FailedCoverage().Len(), roundtrip.FailedCoverage().Len())
			for _, report := range []any{metadata, &metadata, summary, &summary} {
				encoded, encodeErr := json.Marshal(report)
				require.NoError(t, encodeErr)
				var wire map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(encoded, &wire))
				if test.failed {
					require.Contains(t, wire, "evaluation")
				} else {
					require.NotContains(t, wire, "evaluation", "healthy report shape must remain unchanged")
				}
			}
			sarifBytes, readErr := os.ReadFile(filepath.Join(params.OutputPath, "outcomes.sarif"))
			require.NoError(t, readErr)
			var sarif struct {
				Runs []struct {
					Invocations []struct {
						ExecutionSuccessful bool  `json:"executionSuccessful"`
						Notifications       []any `json:"toolExecutionNotifications"`
					} `json:"invocations"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal(sarifBytes, &sarif))
			require.Len(t, sarif.Runs, 1)
			if test.failed {
				require.Len(t, sarif.Runs[0].Invocations, 1)
				require.False(t, sarif.Runs[0].Invocations[0].ExecutionSuccessful)
				require.NotEmpty(t, sarif.Runs[0].Invocations[0].Notifications)
			} else {
				require.Empty(t, sarif.Runs[0].Invocations)
			}
		})
	}
}
