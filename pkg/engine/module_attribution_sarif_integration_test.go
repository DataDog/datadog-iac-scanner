/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
		flagEvaluator: moduleEvalEnabled(),
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
	require.Equal(t, 2, result.Locations[0].PhysicalLocation.Region.StartLine)
	require.GreaterOrEqual(t, result.Locations[0].PhysicalLocation.Region.EndLine, 2)

	moduleRaw, ok := result.Properties["module"]
	require.True(t, ok)
	require.Contains(t, string(moduleRaw), `"name":"bucket"`)
	require.Contains(t, string(moduleRaw), `"source":"modules/bucket"`)
	require.Contains(t, string(moduleRaw), `"code_location"`)
	require.NotContains(t, string(moduleRaw), `"module_path"`)
}
