package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/open-policy-agent/opa/rego"
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

func requireOPAEvaluationConflict(t *testing.T, query, content string, input any) {
	t.Helper()
	prepared, err := rego.New(
		rego.Query(query),
		rego.Module("runtime-error.rego", content),
		rego.Input(input),
	).PrepareForEval(t.Context())
	require.NoError(t, err)
	_, err = prepared.Eval(t.Context())
	require.ErrorContains(t, err, "eval_conflict_error")
}

func TestPerformScanClassifiesRuleFailuresByOriginAndPhase(t *testing.T) {
	failureQueries := map[string]string{
		"legacy-compile": `package datadog
DatadogPolicy contains result if {
    missing_value == true
    result := {"resourceType": "aws_s3_bucket"}
}`,
		"contract-v2-compile": `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    missing_value == true
    result := dd_output.format(bucket, {})
}`,
		"legacy-runtime": `package datadog
import rego.v1
selection := "first" if { input.document[_] }
selection := "second" if { input.document[_] }
DatadogPolicy contains result if {
    input.document[_]
    selection == "first"
    result := {"resourceType": "aws_s3_bucket"}
}`,
		"contract-v2-runtime": `package datadog
import rego.v1
selection := "first" if { some bucket in input.resources.aws_s3_bucket }
selection := "second" if { some bucket in input.resources.aws_s3_bucket }
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    selection == "first"
    result := {"resourceType": "aws_s3_bucket"}
}
`,
		"decode": `package datadog
DatadogPolicy contains result if {
    result := {"documentId": "missing-document", "resourceType": "aws_s3_bucket", "resourceName": "example", "searchKey": "bucket"}
}`,
		"invalid-path": `package datadog
import rego.v1
import data.datadog.output as dd_output
results contains result if {
    some bucket in input.resources.aws_s3_bucket
    result := dd_output.format(bucket, {"path": 42})
}`,
	}
	for _, origin := range []struct {
		name    string
		source  model.QuerySource
		offline bool
	}{
		{name: "default", source: model.QuerySourceDefault},
		{name: "custom API", source: model.QuerySourceCustom},
		{name: "custom offline bundle", source: model.QuerySourceCustom, offline: true},
	} {
		for failure, content := range failureQueries {
			t.Run(origin.name+"/"+failure, func(t *testing.T) {
				repo := t.TempDir()
				terraformFile := filepath.Join(repo, "main.tf")
				require.NoError(t, os.WriteFile(terraformFile, []byte(`resource "aws_s3_bucket" "example" { bucket = "target" }`), 0o600))
				queryName := failure + "-rule"
				query := model.QueryMetadata{
					Query: queryName, Platform: "terraform", Source: origin.source, Content: content, InputData: "{}", Aggregation: 1,
					Metadata: map[string]any{"id": queryName, "queryName": queryName, "severity": "HIGH", "platform": "Terraform"},
				}
				params := Parameters{
					RepoPath: repo, Path: []string{terraformFile}, QueriesPath: []string{"."},
					Platform: []string{"Terraform"}, CloudProvider: []string{"aws"},
					LibrariesPath: "assets/libraries", MaxFileSizeFlag: 5, ScanID: "failure-classification",
					MaxResolverDepth: 15, PreviewLines: 3, FlagEvaluator: featureflags.NewLocalEvaluator(),
				}
				client, err := NewClient(t.Context(), &params, &consolePrinter.Printer{})
				require.NoError(t, err)
				client.querySourceFactory = func(context.Context, []string) (source.QueriesSource, error) {
					if !origin.offline {
						return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
					}
					bundle := t.TempDir()
					rules, err := json.Marshal(&datadog.Ruleset{Rules: []*datadog.Rule{{
						ID: queryName, Name: queryName, Platform: "Terraform", Type: "rego", RegoQuery: []byte(content),
						IsPublished: true, Origin: datadog.RuleOriginCustom,
					}}})
					require.NoError(t, err)
					libraries, err := json.Marshal(map[string]datadog.Library{
						"terraform": {ID: "terraform", RegoCode: "package generic.terraform\n"},
						"common":    {ID: "common", RegoCode: "package generic.common\n"},
					})
					require.NoError(t, err)
					rulesPath, librariesPath := filepath.Join(bundle, "rules.json"), filepath.Join(bundle, "libraries.json")
					require.NoError(t, os.WriteFile(rulesPath, rules, 0o600))
					require.NoError(t, os.WriteFile(librariesPath, libraries, 0o600))
					localClient, err := datadog.NewLocalFileClient(rulesPath, librariesPath)
					require.NoError(t, err)
					return source.NewDatadogSource(localClient)
				}
				if failure == "legacy-runtime" {
					requireOPAEvaluationConflict(t, "data.datadog.DatadogPolicy", content, map[string]any{
						"document": []any{map[string]any{}},
					})
				} else if failure == "contract-v2-runtime" {
					requireOPAEvaluationConflict(t, "data.datadog.results", content, map[string]any{
						"resources": map[string]any{"aws_s3_bucket": []any{map[string]any{"bucket": "target"}}},
					})
				}
				metadata, err := client.PerformScan(t.Context())
				require.NoError(t, err)
				compileFailure := failure == "legacy-compile" || failure == "contract-v2-compile"
				if compileFailure {
					require.Equal(t, []string{queryName}, metadata.RuleStats.FailedToCompile)
					require.Empty(t, metadata.RuleStats.FailedToEvaluate)
				} else {
					require.Empty(t, metadata.RuleStats.FailedToCompile)
					require.Equal(t, []string{queryName}, metadata.RuleStats.FailedToEvaluate)
				}
				require.Equal(t, compileFailure && origin.source == model.QuerySourceDefault,
					metadata.RuleStats.DefaultRuleCompileFailed)
			})
		}
	}
}

func TestPerformScanClassifiesFilesystemRuleFailuresByRoot(t *testing.T) {
	repo := t.TempDir()
	t.Chdir(repo)
	tfPath := filepath.Join(repo, "main.tf")
	require.NoError(t, os.WriteFile(tfPath, []byte(`resource "aws_s3_bucket" "example" { bucket = "target" }`), 0o600))
	for _, rule := range []struct {
		root    string
		id      string
		content string
	}{
		{
			root: "assets/queries/default-rule", id: "default-rule",
			content: `package datadog
DatadogPolicy contains result if { result := {"resourceType": "aws_s3_bucket"} }`,
		},
		{
			root: "custom/broken-rule", id: "custom-broken-rule",
			content: `package datadog
DatadogPolicy contains result if {
    missing_value == true
    result := {"resourceType": "aws_s3_bucket"}
}`,
		},
	} {
		path := filepath.Join(repo, rule.root)
		require.NoError(t, os.MkdirAll(path, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(path, source.QueryFileName), []byte(rule.content), 0o600))
		metadata := `{"id":"` + rule.id + `","queryName":"` + rule.id + `","severity":"HIGH","platform":"Terraform"}`
		require.NoError(t, os.WriteFile(filepath.Join(path, source.MetadataFileName), []byte(metadata), 0o600))
	}

	queryRoots := []string{"assets/queries", "custom"}
	params := Parameters{
		RepoPath: repo, Path: []string{tfPath}, QueriesPath: queryRoots,
		Platform: []string{"Terraform"}, CloudProvider: []string{"aws"},
		LibrariesPath: "assets/libraries", MaxFileSizeFlag: 5, ScanID: "filesystem-failure-classification",
		MaxResolverDepth: 15, PreviewLines: 3, FlagEvaluator: featureflags.NewLocalEvaluator(),
	}
	client, err := NewClient(t.Context(), &params, &consolePrinter.Printer{})
	require.NoError(t, err)
	client.querySourceFactory = func(ctx context.Context, _ []string) (source.QueriesSource, error) {
		filesystem := source.NewFilesystemSource(ctx, queryRoots, []string{""}, []string{""}, "", false)
		return source.NewFilesystemSourceWithLibraryOverride(filesystem, &stubQuerySource{}), nil
	}
	metadata, err := client.PerformScan(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"broken-rule"}, metadata.RuleStats.FailedToCompile)
	require.False(t, metadata.RuleStats.DefaultRuleCompileFailed)
}

func TestHelmSprigKeysProduceStableDocumentIDsAndPayload(t *testing.T) {
	for field, orderingField := range map[string]string{
		"name":               "name: {{ $name }}",
		"generateName":       "generateName: {{ $name }}-",
		"sharedGenerateName": "generateName: shared-",
		"unnamed":            "namespace: default",
	} {
		t.Run(field, func(t *testing.T) {
			testHelmSprigDocumentOrder(t, orderingField)
		})
	}
}

func testHelmSprigDocumentOrder(t *testing.T, orderingField string) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 1.0.0\n"), 0o644))
	const template = `{{- $configmaps := dict "gamma" "4" "alpha" "1" "beta" "2" "delta" "3" }}
{{- range $name := keys $configmaps }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  ORDERING_FIELD
data:
  value: {{ index $configmaps $name | quote }}
{{- end }}
`
	manifest := strings.Replace(template, "ORDERING_FIELD", orderingField, 1)
	require.NoError(t, os.WriteFile(filepath.Join(root, "templates", "configmaps.yaml"), []byte(manifest), 0o644))
	payloadPath := filepath.Join(t.TempDir(), "payload.json")
	var baseline []byte
	for i := range 8 {
		ctx := t.Context()
		params := &Parameters{
			Path: []string{root}, Platform: []string{"Kubernetes"}, QueriesPath: []string{"."}, LibrariesPath: "assets/libraries",
			ScanID: "stable-helm-documents", PayloadPath: payloadPath, MaxFileSizeFlag: 5, MaxResolverDepth: 15,
			PreviewLines: 3, FlagEvaluator: featureflags.NewLocalEvaluator(),
		}
		client, err := NewClient(ctx, params, &consolePrinter.Printer{})
		require.NoError(t, err)
		client.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
			return &stubQuerySource{}, nil
		}
		_, err = client.PerformScan(ctx)
		require.NoError(t, err)
		payload, err := os.ReadFile(payloadPath)
		require.NoError(t, err)
		if i == 0 {
			baseline = payload
		}
		require.Equal(t, baseline, payload, "render %d changed the payload or document IDs", i)
	}
	var payload struct {
		Document []struct {
			ID   string
			Data struct{ Value string }
		}
	}
	require.NoError(t, json.Unmarshal(baseline, &payload))
	var values, ids []string
	for _, document := range payload.Document {
		values = append(values, document.Data.Value)
		require.NotEmpty(t, document.ID)
		require.NotContains(t, ids, document.ID)
		ids = append(ids, document.ID)
	}
	require.Equal(t, []string{"1", "2", "3", "4"}, values)
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
