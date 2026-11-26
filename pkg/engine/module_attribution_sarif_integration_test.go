/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	reportModel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
	"github.com/stretchr/testify/require"
)

const displayNameAclRule = `package datadog

DatadogPolicy contains result if {
	some label, i
	bucket := input.document[i].resource.aws_s3_bucket[label]
	bucket.acl == "public-read"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": bucket.bucket,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [label]),
	}
}
`

func TestInspect_ModuleAttribution_EndToEndSARIF(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	modPath := filepath.Join(modDir, "main.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = "customer-bucket"
  acl    = var.acl
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	queries := []model.QueryMetadata{{
		Query:       "acl_rule",
		Content:     displayNameAclRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "acl-rule"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, "customer-bucket", vulns[0].ResourceName)

	summary := model.CreateSummary(context.Background(), model.Counters{}, vulns, "test", nil, root, model.SCIInfo{})
	require.Len(t, summary.Queries, 1)
	require.Len(t, summary.Queries[0].Files, 1)
	require.NotNil(t, summary.Queries[0].Files[0].ModuleAttribution)

	report := reportModel.NewSarifReport()
	_, err = report.BuildSarifIssue(context.Background(), &summary.Queries[0], model.SCIInfo{})
	require.NoError(t, err)

	raw, err := json.Marshal(report)
	require.NoError(t, err)

	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
							EndLine   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Len(t, doc.Runs, 1)
	require.Len(t, doc.Runs[0].Results, 1)

	result := doc.Runs[0].Results[0]
	require.Equal(t, "stack/main.tf", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	require.Equal(t, 4, result.Locations[0].PhysicalLocation.Region.StartLine, "narrowed to the acl argument")
	require.Equal(t, 4, result.Locations[0].PhysicalLocation.Region.EndLine)

	moduleRaw, ok := result.Properties["module"]
	require.True(t, ok)
	var module struct {
		Source         *string `json:"source"`
		SourceType     string  `json:"source_type"`
		DependencyType string  `json:"dependency_type"`
		CodeLocation   struct {
			Filename    string `json:"filename"`
			LineStart   int    `json:"line_start"`
			LineEnd     int    `json:"line_end"`
			ColumnStart int    `json:"column_start"`
			ColumnEnd   int    `json:"column_end"`
		} `json:"code_location"`
		ModulePath []struct {
			Name         string `json:"name"`
			Source       string `json:"source"`
			SourceType   string `json:"source_type"`
			CodeLocation struct {
				Filename  string `json:"filename"`
				LineStart int    `json:"line_start"`
				LineEnd   int    `json:"line_end"`
			} `json:"code_location"`
		} `json:"module_path"`
	}
	require.NoError(t, json.Unmarshal(moduleRaw, &module))
	require.Nil(t, module.Source, "local module files are named from the scanned repository")
	require.Equal(t, "local", module.SourceType)
	require.Equal(t, "direct", module.DependencyType)
	require.Equal(t, "modules/bucket/main.tf", module.CodeLocation.Filename)
	require.Equal(t, 8, module.CodeLocation.LineStart, "narrowed to the flagged attribute")
	require.Equal(t, 8, module.CodeLocation.LineEnd)
	require.Positive(t, module.CodeLocation.ColumnStart)
	require.Greater(t, module.CodeLocation.ColumnEnd, module.CodeLocation.ColumnStart)
	require.Len(t, module.ModulePath, 1)
	require.Equal(t, "bucket", module.ModulePath[0].Name)
	require.Equal(t, "modules/bucket", module.ModulePath[0].Source)
	require.Equal(t, "local", module.ModulePath[0].SourceType)
	require.Equal(t, "stack/main.tf", module.ModulePath[0].CodeLocation.Filename)
	require.Equal(t, 2, module.ModulePath[0].CodeLocation.LineStart)
	require.Equal(t, 5, module.ModulePath[0].CodeLocation.LineEnd)
}

// A downloaded package can contain entry points other than the //subdir the
// repository calls. Those directories must never instantiate resources on
// their own, even when they call another module in the same package.
func TestInspect_RemotePackageOnlyReportsReachableCalls(t *testing.T) {
	for _, uncalled := range []string{"", "gcp"} {
		t.Run("uncalled/"+uncalled, func(t *testing.T) {
			repo, pkg := t.TempDir(), t.TempDir()
			const source = "git::https://example.com/modules.git//selected?ref=v1"
			unusedSource := "../unused-child"
			if uncalled == "" {
				unusedSource = "./unused-child"
			}
			paths := []string{
				writeCallerFixture(t, pkg, "selected/main.tf", `module "child" { source = "./child" }`),
				writeCallerFixture(t, pkg, "selected/child/main.tf", `variable "name" {}
resource "aws_s3_bucket" "reachable" { acl = "public-read" }
`),
				writeCallerFixture(t, pkg, filepath.Join(uncalled, "main.tf"), `module "unused" { source = "`+unusedSource+`" }`),
				writeCallerFixture(t, pkg, "unused-child/main.tf", `resource "aws_s3_bucket" "unreachable" { acl = "public-read" }`),
			}
			ins := newTestInspector(t, inspectorOpts{
				queries: []model.QueryMetadata{
					{Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
						Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1},
					{Query: "variable_rule", Content: variableTypeRule, InputData: "{}", Platform: "terraform",
						Metadata: map[string]interface{}{"id": "variable-rule", "platform": "Terraform"}, Aggregation: 1},
				},
				repoPath: repo, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
			})
			dirs := map[string]RemoteModuleDirectory{}
			provenance := map[string]RemoteModuleProvenance{}
			for _, stack := range []string{"stack-a", "stack-b"} {
				caller := writeCallerFixture(t, repo, stack+"/main.tf", `module "selected" { source = "`+source+`" }`)
				paths = append(paths, caller)
				key := RemoteModuleKey(filepath.Dir(caller), source, "")
				dirs[key] = RemoteModuleDirectory{Path: filepath.Join(pkg, "selected"), PackageRoot: pkg}
				provenance[key] = RemoteModuleProvenance{
					Source: source, SourceType: moduleSourceTypeGit,
					ModuleRoot: filepath.Join(pkg, "selected"), PackageRoot: pkg,
				}
			}
			ins.SetRemoteModuleDirectories(dirs)
			ins.SetRemoteModuleProvenance(provenance)
			ins.SetExternalModulePaths([]string{pkg})
			var files model.FileMetadatas
			for _, path := range paths {
				files = append(files, parseTerraform(t, path)...)
			}
			ctx := context.Background()
			findings, err := ins.Inspect(ctx, "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, findings, 4, "one resource and one file finding per scanned call")
			summary := model.CreateSummary(ctx, model.Counters{}, findings, "test", nil, repo, model.SCIInfo{})
			report := reportModel.NewSarifReport()
			for i := range summary.Queries {
				_, err = report.BuildSarifIssue(ctx, &summary.Queries[i], model.SCIInfo{})
				require.NoError(t, err)
			}
			raw, err := json.Marshal(report)
			require.NoError(t, err)
			var doc struct {
				Runs []struct {
					Results []struct {
						Locations []struct {
							PhysicalLocation struct {
								ArtifactLocation struct{ URI string } `json:"artifactLocation"`
							} `json:"physicalLocation"`
						} `json:"locations"`
					} `json:"results"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal(raw, &doc))
			require.Len(t, doc.Runs[0].Results, 4)
			uris := map[string]int{}
			for _, result := range doc.Runs[0].Results {
				uris[result.Locations[0].PhysicalLocation.ArtifactLocation.URI]++
			}
			require.Equal(t, map[string]int{"stack-a/main.tf": 2, "stack-b/main.tf": 2}, uris)
			require.NotContains(t, string(raw), pkg, "the module cache never appears in SARIF")
		})
	}
}

// The reporting contract must survive syntax and path representation changes:
// the same instantiated resources reach the same repository calls.
func TestInspect_ModuleLocationsAcrossFormatsAndRoots(t *testing.T) {
	const hclModule = `variable "acl" { type = string }
resource "aws_s3_bucket" "first" {
  bucket = "display-first"
  acl = var.acl
}
resource "aws_s3_bucket" "second" {
  bucket = "display-second"
  acl = var.acl
}
data "aws_s3_bucket" "first" {
  bucket = "display-data"
  acl = var.acl
}
`
	const jsonModule = `{
  "variable": {"acl": {"type": "string"}},
  "resource": {
    "aws_s3_bucket": {
      "first": {"bucket": "display-first", "acl": "${var.acl}"},
      "second": {"bucket": "display-second", "acl": "${var.acl}"}
    }
  },
  "data": {"aws_s3_bucket": {"first": {"bucket": "display-data", "acl": "${var.acl}"}}}
}`
	const rule = `package datadog
DatadogPolicy contains result if {
  some i, name
  some kind in {"resource", "data"}
  bucket := input.document[i][kind].aws_s3_bucket[name]
  bucket.acl == "public-read"
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_s3_bucket",
    "resourceName": bucket.bucket,
    "searchKey": sprintf("%s.aws_s3_bucket[%s].acl", [kind, name]),
  }
}`
	keyFormats := []string{
		"%s.aws_s3_bucket[%s].acl",
		"%s.aws_s3_bucket.%s.acl",
		"%s.aws_s3_bucket[{{%s}}].acl",
		"%s.aws_s3_bucket.{{%s}}.acl",
		`%s.aws_s3_bucket["%s"].acl`,
	}
	var queries []model.QueryMetadata
	for i, format := range keyFormats {
		id := fmt.Sprintf("acl-%d", i)
		content := strings.Replace(rule, `"%s.aws_s3_bucket[%s].acl"`, strconv.Quote(format), 1)
		queries = append(queries, model.QueryMetadata{Query: id, Content: content, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": id, "platform": "Terraform"}, Aggregation: 1})
	}
	formats := []struct{ caller, module string }{
		{".tf", ".tf"}, {".tofu", ".tofu"}, {".tf.json", ".tf.json"}, {".tofu.json", ".tofu.json"},
		{".tf", ".tf.json"}, {".tf.json", ".tf"},
	}
	for _, format := range formats {
		for _, external := range []bool{false, true} {
			for _, rootForm := range []string{"absolute", "dot", "relative"} {
				name := format.caller + "-to-" + format.module + "/" + rootForm
				if external {
					name += "/fetched"
				}
				t.Run(name, func(t *testing.T) {
					base := t.TempDir()
					repo := filepath.Join(base, "repo")
					moduleDir := filepath.Join(repo, "modules", "bucket")
					source := "../modules/bucket"
					if external {
						moduleDir = filepath.Join(base, "cache", "bucket")
						source = "git::https://example.com/bucket.git"
					}
					body := hclModule
					if strings.HasSuffix(format.module, ".json") {
						body = jsonModule
					}
					moduleFile := writeCallerFixture(t, moduleDir, "main"+format.module, body)
					files := parseTerraform(t, moduleFile)
					dirs := map[string]RemoteModuleDirectory{}
					for _, stack := range []string{"stack-a", "stack-b"} {
						caller := `module "bucket" {
  source = "` + source + `"
  acl = "public-read"
}
resource "aws_s3_bucket" "root" {
  bucket = "display-root"
  acl = "public-read"
}`
						if strings.HasSuffix(format.caller, ".json") {
							caller = `{
  "module": {"bucket": {"source": "` + source + `", "acl": "public-read"}},
  "resource": {"aws_s3_bucket": {"root": {"bucket": "display-root", "acl": "public-read"}}}
}`
						}
						path := writeCallerFixture(t, repo, stack+"/main"+format.caller, caller)
						files = append(files, parseTerraform(t, path)...)
						dirs[RemoteModuleKey(filepath.Dir(path), source, "")] = RemoteModuleDirectory{Path: moduleDir, PackageRoot: moduleDir}
					}
					repoPath := repo
					switch rootForm {
					case "dot":
						t.Chdir(repo)
						repoPath = "."
					case "relative":
						t.Chdir(base)
						repoPath = "repo/../repo"
					}
					ins := newTestInspector(t, inspectorOpts{
						repoPath: repoPath, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
						queries: queries,
					})
					if external {
						ins.SetRemoteModuleDirectories(dirs)
						ins.SetExternalModulePaths([]string{moduleDir})
					}
					ctx := context.Background()
					findings, err := ins.Inspect(ctx, "test", files, []string{"terraform"})
					require.NoError(t, err)
					require.Empty(t, ins.GetFailedQueries())
					require.Equal(t, 8*len(queries), len(findings), "every key spelling retains three instantiated findings and one root finding per caller")
					counts := map[string]int{}
					for _, finding := range findings {
						counts[finding.ResourceName]++
						if finding.ModuleCallChain != "" {
							require.NotNil(t, finding.ReportLocation)
							require.Contains(t, []string{"stack-a/main" + format.caller, "stack-b/main" + format.caller}, finding.ReportLocation.Filename)
						}
					}
					require.Equal(t, map[string]int{
						"display-root": 2 * len(queries), "display-first": 2 * len(queries),
						"display-second": 2 * len(queries), "display-data": 2 * len(queries),
					}, counts)
					summary := model.CreateSummary(ctx, model.Counters{}, findings, "test", nil, repoPath, model.SCIInfo{})
					absolute := model.CreateSummary(ctx, model.Counters{}, findings, "test", nil, repo, model.SCIInfo{})
					require.Equal(t, absolute, summary, "report paths and fingerprints cannot depend on root spelling")
					report := reportModel.NewSarifReport()
					for i := range summary.Queries {
						_, err = report.BuildSarifIssue(ctx, &summary.Queries[i], model.SCIInfo{})
						require.NoError(t, err)
					}
					raw, err := json.Marshal(report)
					require.NoError(t, err)
					require.Equal(t, 8*len(queries), strings.Count(string(raw), `"partialFingerprints"`), "every retained finding reaches SARIF")
				})
			}
		}
	}
}

func TestInspect_ModuleAttributionNestedAttributeKeys(t *testing.T) {
	repo := t.TempDir()
	moduleFile := writeCallerFixture(t, repo, "modules/bucket/main.tf", `variable "name" { type = string }
resource "aws_s3_bucket" "this" {
  bucket = "display-name"
  tags = {
    Name = var.name
  }
}
`)
	files := parseTerraform(t, moduleFile)
	for _, stack := range []string{"stack-a", "stack-b"} {
		path := writeCallerFixture(t, repo, stack+"/main.tf", `module "bucket" {
  source = "../modules/bucket"
  name = "insecure"
}
`)
		files = append(files, parseTerraform(t, path)...)
	}
	var queries []model.QueryMetadata
	for i, key := range []string{"tags.Name", "tags.{{Name}}"} {
		id := fmt.Sprintf("nested-%d", i)
		queries = append(queries, model.QueryMetadata{
			Query: id, InputData: "{}", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": id, "platform": "Terraform"},
			Content: `package datadog
DatadogPolicy contains result if {
  some i, label
  bucket := input.document[i].resource.aws_s3_bucket[label]
  bucket.tags.Name == "insecure"
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_s3_bucket",
    "resourceName": bucket.bucket,
    "searchKey": "` + key + `",
  }
}`,
		})
	}
	ins := newTestInspector(t, inspectorOpts{
		repoPath: repo, queries: queries, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ctx := context.Background()
	findings, err := ins.Inspect(ctx, "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Equal(t, 4, len(findings), "both nested key spellings retain both deduplicated callers")
	callers := map[string]int{}
	for _, finding := range findings {
		require.Equal(t, "display-name", finding.ResourceName)
		require.NotNil(t, finding.ReportLocation)
		require.Equal(t, 3, finding.ReportLocation.LineStart, "the caller's name argument controls the value")
		callers[finding.ReportLocation.Filename]++
	}
	require.Equal(t, map[string]int{"stack-a/main.tf": 2, "stack-b/main.tf": 2}, callers)
	summary := model.CreateSummary(ctx, model.Counters{}, findings, "test", nil, repo, model.SCIInfo{})
	report := reportModel.NewSarifReport()
	for i := range summary.Queries {
		_, err = report.BuildSarifIssue(ctx, &summary.Queries[i], model.SCIInfo{})
		require.NoError(t, err)
	}
	raw, err := json.Marshal(report)
	require.NoError(t, err)
	require.Equal(t, 4, strings.Count(string(raw), `"partialFingerprints"`))
}
