package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// stubQuerySource serves a fixed query slice and a trivial Rego library.
type stubQuerySource struct {
	queries []model.QueryMetadata
}

func (s *stubQuerySource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *stubQuerySource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	return source.RegoLibraries{
		LibraryCode:      "package generic." + platform + "\n",
		LibraryInputData: "{}",
	}, nil
}

// Test_ExecuteScan runs the scan pipeline against a synthetic in-memory rule
// so the assertions are decoupled from the rule corpus.
func Test_ExecuteScan(t *testing.T) {
	const ruleID = "test-execute-scan-rule"
	rego := `package datadog

DatadogPolicy contains result if {
	input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
`
	query := model.QueryMetadata{
		Query:     ruleID,
		Content:   rego,
		InputData: "{}",
		Platform:  "terraform",
		Metadata: map[string]interface{}{
			"id":        ruleID,
			"legacyId":  ruleID,
			"queryName": "Synthetic Execute-Scan Rule",
			"severity":  "HIGH",
			"platform":  "Terraform",
			"category":  "Encryption",
		},
	}

	scanParams := Parameters{
		Path:                    []string{filepath.Join("test", "sample.tf")},
		QueriesPath:             []string{"."},
		LibrariesPath:           "assets/libraries",
		PreviewLines:            3,
		CloudProvider:           []string{"aws"},
		Platform:                []string{"Terraform"},
		ChangedDefaultQueryPath: false,
		MaxFileSizeFlag:         100,
		ScanID:                  "console",
		MaxResolverDepth:        15,
		FlagEvaluator:           featureflags.NewLocalEvaluator(),
	}

	ctx := context.Background()
	c, err := NewClient(ctx, &scanParams, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
	}

	r, err := c.executeScan(ctx)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.NotEmpty(t, r.Results, "expected at least one synthetic violation")

	for i, result := range r.Results {
		require.Equalf(t, model.Severity("HIGH"), model.Severity(result.Severity), "result[%d] severity", i)
		require.Equalf(t, ruleID, result.QueryID, "result[%d] query id", i)
	}
}

func TestScanSymlinkPlaceholdersWithoutGitMetadata(t *testing.T) {
	// Exercise the same aliased root as macOS's /var -> /private/var.
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(t.TempDir(), alias))
	repo := filepath.Join(alias, "repo")
	require.NoError(t, os.Mkdir(repo, 0o755))
	for path, content := range map[string]string{
		"shared.tf":          `variable "acl" { default = "public-read" }`,
		"stack/variables.tf": "../shared.tf",
		"stack/missing.tf":   "./unavailable.tf",
		"stack/comment.tf":   "//variables.tf",
		"stack/main.tf": `module "linked" {
  source = "../alias"
  acl = var.acl
}
module "missing" { source = "../unavailable" }`,
		"alias":       "./actual",
		"unavailable": "./gone",
		"actual/main.tf": `variable "acl" {}
resource "aws_s3_bucket" "this" { acl = var.acl }`,
	} {
		full := filepath.Join(repo, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	query := model.QueryMetadata{
		Query: "placeholder-rule", InputData: "{}", Platform: "terraform",
		Content: `package datadog
DatadogPolicy contains result if {
  some name, i
  bucket := input.document[i].resource.aws_s3_bucket[name]
  bucket.acl == "public-read"
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_s3_bucket",
    "resourceName": name,
    "searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
  }
}`,
		Metadata: map[string]interface{}{
			"id": "placeholder-rule", "legacyId": "placeholder-rule", "queryName": "Placeholder test",
			"severity": "HIGH", "platform": "Terraform", "category": "Encryption",
			"descriptionUrl": "https://example.com/rule", "descriptionText": "Test rule",
			"descriptionID": "placeholder-test", "cwe": "284",
		},
		Aggregation: 1,
	}
	params := Parameters{
		RepoPath: repo, Path: []string{repo}, QueriesPath: []string{"."},
		Platform: []string{"Terraform"}, CloudProvider: []string{"aws"},
		MaxFileSizeFlag: 5, ScanID: "placeholder-test", MaxResolverDepth: 15,
		PreviewLines:  3,
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}
	var logs bytes.Buffer
	log := zerolog.New(zerolog.SyncWriter(&logs)).Level(zerolog.DebugLevel)
	ctx := log.WithContext(t.Context())
	client, err := NewClient(ctx, &params, &consolePrinter.Printer{})
	require.NoError(t, err)
	client.querySourceFactory = func(context.Context, []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
	}
	result, err := client.Scan(ctx)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Results, 1, logs.String())
	require.Equal(t, filepath.ToSlash(filepath.Join(repo, "actual", "main.tf")), filepath.ToSlash(result.Results[0].FileName))
	require.NotNil(t, result.Results[0].ModuleAttribution)
	require.Equal(t, "stack/main.tf", result.Results[0].ModuleAttribution.CallSite.Filename)
	require.NotContains(t, logs.String(), `"level":"error"`)
}

func TestScanPlaceholderUsesTargetSourceAtLogicalPath(t *testing.T) {
	for _, tt := range []struct {
		name, header string
		suppressed   bool
	}{
		{"source", "# Shared configuration", false},
		{"file directive", "# dd-iac-scan disable=remote-module-vpc-rule", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			content := tt.header + `

resource "aws_vpc" "this" {
  cidr_block = "10.0.0.0/16"
}
`
			config := filepath.Join(root, "stack", "main.tf")
			require.NoError(t, os.Mkdir(filepath.Dir(config), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(root, "shared.hcl"), []byte(content), 0o644))
			require.NoError(t, os.WriteFile(config, []byte("../shared.hcl"), 0o644))

			params := remoteModuleScanParams(root)
			params.LineInfoPayload = true
			results := executeRemoteModuleScan(t, params)
			require.Len(t, results.Results, 1)
			finding := results.Results[0]
			require.Equal(t, filepath.ToSlash(config), filepath.ToSlash(finding.FileName))
			require.Equal(t, 3, finding.Line)
			require.Equal(t, tt.suppressed, finding.IsSuppressed)
			require.NotNil(t, finding.VulnLines)
			require.Contains(t, *finding.VulnLines, model.CodeLine{Position: 3, Line: `resource "aws_vpc" "this" {`})
			require.Len(t, results.Files, 1)
			require.Equal(t, content, results.Files[0].OriginalData)
		})
	}
}

func Test_CreateQueryFilter(t *testing.T) {
	tests := []struct {
		name           string
		scanParams     Parameters
		expectedOutput source.QueryInspectorParameters
	}{
		{
			name: "test empty filter",
			scanParams: Parameters{
				Config:          config.IacConfig{},
				InputData:       "",
				BillOfMaterials: false,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.QueryFilter{},
				IncludeQueries: source.QueryFilter{},
				InputDataPath:  "",
				BomQueries:     false,
			},
		},
		{
			name: "test query filter with some fields and BoM",
			scanParams: Parameters{
				Config: config.IacConfig{
					IgnoreRules:      []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
					IgnoreSeverities: []string{"info"},
					OnlyCategories:   []string{"Accessibility"},
				},
				InputData:       "",
				BillOfMaterials: true,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.QueryFilter{
					ByIDs:        []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
					BySeverities: []string{"info"},
				},
				IncludeQueries: source.QueryFilter{
					ByCategories: []string{"Accessibility"},
				},
				InputDataPath: "",
				BomQueries:    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}
			c.ScanParams = &tt.scanParams

			v := c.createQueryFilter()

			require.Equal(t, tt.expectedOutput, *v)
		})
	}
}

func TestTerraformPreparationKeepsDocumentConsumers(t *testing.T) {
	modern := model.QueryMetadata{Platform: "Terraform", Content: `package datadog
import rego.v1
import data.generic.terraform as tf
DatadogPolicy contains result if { some block in tf.blocks("aws_s3_bucket"); result := block }
`}
	legacy := model.QueryMetadata{Platform: "Terraform", Content: `package datadog
import rego.v1
DatadogPolicy contains result if { result := input.document[_] }
`}
	other := modern
	other.Platform = "Kubernetes"
	forcedLegacy := modern
	forcedLegacy.Metadata = map[string]interface{}{"contract": "legacy"}
	malformed := modern
	malformed.Content = "not valid Rego"
	for _, tc := range []struct {
		name         string
		params       Parameters
		queries      []model.QueryMetadata
		wantMetadata bool
	}{
		{name: "only modern Terraform", queries: []model.QueryMetadata{modern}, wantMetadata: true},
		{name: "no queries"},
		{name: "legacy", queries: []model.QueryMetadata{legacy}},
		{name: "explicit legacy", queries: []model.QueryMetadata{forcedLegacy}},
		{name: "mixed contract", queries: []model.QueryMetadata{modern, legacy}},
		{name: "other platform", queries: []model.QueryMetadata{other}},
		{name: "mixed platforms", queries: []model.QueryMetadata{modern, other}},
		{name: "invalid rule", queries: []model.QueryMetadata{malformed}},
		{name: "payload export", params: Parameters{PayloadPath: "payload.json"}, queries: []model.QueryMetadata{modern}},
		{name: "line info export", params: Parameters{LineInfoPayload: true}, queries: []model.QueryMetadata{modern}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prepared := terraformPreparationContext(ctx, &tc.params, tc.queries)
			require.Equal(t, tc.wantMetadata, parser.IsTerraformMetadataOnly(prepared))
			cancel()
			require.ErrorIs(t, prepared.Err(), context.Canceled)
		})
	}
}
