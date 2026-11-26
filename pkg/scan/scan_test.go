package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
	for _, limit := range []int{1, 2, -1} {
		t.Run(fmt.Sprintf("GitLab/max-file-size=%d", limit), func(t *testing.T) {
			root := writeRepo(t, map[string]string{
				".gitlab-ci.yml":       "include: [.gitlab/ci/large.yml]\n",
				".gitlab/ci/large.yml": "#" + strings.Repeat("x", 1<<20) + "\nincluded: {script: [echo included]}\n",
			})
			params := scanParams
			params.Path, params.RepoPath = []string{root}, root
			params.Platform, params.CloudProvider = []string{"CICD"}, []string{""}
			params.MaxFileSizeFlag = limit
			params.DisableSecrets = true
			query := model.QueryMetadata{Query: "gitlab-size-policy", Platform: "cicd", InputData: "{}",
				Content: `package datadog
DatadogPolicy contains result if {
 some doc in input.document
 _ := doc.gitlab.included.script[0]
 result := {"documentId": doc.id, "searchKey": "gitlab.included.script.0", "resourceType": "gitlab_ci_job", "resourceName": "included"}
}`,
				Metadata: map[string]interface{}{"id": "gitlab-size-policy", "platform": "CICD", "severity": "HIGH"}}
			client, err := NewClient(ctx, &params, &consolePrinter.Printer{}, WithQuerySourceFactory(func(context.Context, []string) (source.QueriesSource, error) {
				return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
			}))
			require.NoError(t, err)
			results, err := client.executeScan(ctx)
			require.NoError(t, err)
			require.NotNil(t, results)
			if limit == 1 {
				require.True(t, results.Incomplete())
				require.Empty(t, results.Results)
			} else {
				require.False(t, results.Incomplete())
				require.Len(t, results.Results, 1)
			}
		})
	}
}

func TestGitLabProviderRoutingAndConditionalIncludes(t *testing.T) {
	for _, name := range []string{".gitlab-ci.YML", ".gitlab/ci/jobs.YAML", "pipelines/check.GitLab-CI.YmL"} {
		for _, singleFile := range []bool{false, true} {
			for _, conditional := range []string{"none", "exists", "unknown absent", "unknown override", "status mirror", "boolean", "invalid later document", "invalid root scalar", "invalid root sequence", "invalid root null", "invalid root quoted empty", "invalid later null", "invalid later tilde", "invalid later quoted empty"} {
				if strings.HasPrefix(conditional, "invalid root") && strings.HasPrefix(name, ".gitlab/ci/") {
					continue
				}
				t.Run(fmt.Sprintf("%s/file=%t/conditional=%s", name, singleFile, conditional), func(t *testing.T) {
					body := "included: {script: [echo root]}\n"
					if conditional == "exists" {
						body = "include: [{local: optional.yml, rules: [{exists: [optional.yml]}]}]\n" + body
					} else if strings.HasPrefix(conditional, "unknown") {
						body = "include: [{local: optional.yml, rules: [{if: '$UNKNOWN'}]}]\n" + body
					}
					switch conditional {
					case "status mirror":
						body = "included: {needs: {pipeline: group/project}}\n"
					case "boolean":
						body = "included: {script: [echo root], allow_failure: yes}\n"
					case "invalid later document":
						body += "---\nincluded: [unterminated\n"
					case "invalid root scalar":
						body = "value\n"
					case "invalid root sequence":
						body = "- invalid\n"
					case "invalid root null":
						body = "null\n"
					case "invalid root quoted empty":
						body = "\"\"\n"
					case "invalid later null":
						body += "---\nnull\n"
					case "invalid later tilde":
						body += "---\n~\n"
					case "invalid later quoted empty":
						body += "---\n\"\"\n"
					}
					files := map[string]string{name: body}
					if conditional == "unknown override" {
						files["optional.yml"] = "included: {script: [echo conditional]}\n"
					}
					repo := writeRepo(t, files)
					path := repo
					if singleFile {
						path = filepath.Join(repo, filepath.FromSlash(name))
					}
					params, ctx := GetDefaultParameters(t.Context(), repo)
					require.NotNil(t, params)
					params.Path, params.RepoPath = []string{path}, repo
					params.Platform, params.ScanID = []string{"CICD"}, "gitlab-routing"
					params.FlagEvaluator = featureflags.NewLocalEvaluator()
					query := model.QueryMetadata{Query: "gitlab-routing", Platform: "cicd", InputData: "{}", Metadata: map[string]interface{}{"id": "gitlab-routing", "platform": "CICD", "severity": "HIGH"}, Content: `package datadog
DatadogPolicy contains {"documentId":doc.id,"searchKey":"gitlab.included.script.0"} if {some doc in input.document;doc.gitlab.included.script[0] == "echo root"}`}
					if conditional == "status mirror" {
						query.Content = `package datadog
DatadogPolicy contains {"documentId":doc.id,"searchKey":"gitlab.included.needs.pipeline"} if {some doc in input.document;doc.gitlab.included.needs.pipeline == "group/project"}`
					} else if conditional == "boolean" {
						query.Content = strings.Replace(query.Content, `doc.gitlab.included.script[0] == "echo root"`, `doc.gitlab.included.allow_failure == true`, 1)
					}
					client, err := NewClient(ctx, params, &consolePrinter.Printer{}, WithQuerySourceFactory(func(context.Context, []string) (source.QueriesSource, error) {
						return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
					}))
					require.NoError(t, err)
					run := &inventoryRun{collector: inventory.NewCollector(repo)}
					client.inventory = run
					result, err := client.executeScan(t.Context())
					require.NoError(t, err)
					invalid := strings.HasPrefix(conditional, "invalid")
					require.Equal(t, strings.HasPrefix(conditional, "unknown") || invalid, result.Incomplete())
					if invalid {
						require.Empty(t, result.Results)
					} else {
						require.Len(t, result.Results, 1)
					}
					client.recordManifest(run, result.Files)
					manifest := run.collector.Build(&inventory.Metadata{Incomplete: result.Incomplete()})
					if conditional == "status mirror" {
						require.Len(t, manifest.Resources, 1)
						require.Equal(t, "gitlab_ci_job", manifest.Resources[0].ResourceType)
					}
					found := false
					for _, file := range manifest.Files {
						if file.Path != filepath.ToSlash(name) {
							continue
						}
						found = true
						if invalid {
							require.Equal(t, inventory.FileFailed, file.Status)
							require.Equal(t, model.ParseFailureInvalidPipeline, file.Reason)
							require.Equal(t, inventory.StatusPartial, manifest.Status)
						} else if strings.HasPrefix(conditional, "unknown") {
							require.Equal(t, inventory.FileFailed, file.Status)
							require.Equal(t, model.ParseFailureUnresolvedInclude, file.Reason)
							require.Equal(t, inventory.StatusPartial, manifest.Status)
						} else {
							require.Equal(t, inventory.FileScanned, file.Status)
						}
					}
					require.True(t, found)
				})
			}
		}
	}
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
