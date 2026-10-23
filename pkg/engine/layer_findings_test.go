/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestDropRepeatedLayerFindings(t *testing.T) {
	files := map[string]*model.FileMetadata{
		"a0": {FilePath: "a.tf", ExpansionLayer: 0},
		"a1": {FilePath: "a.tf", ExpansionLayer: 1},
		"a2": {FilePath: "a.tf", ExpansionLayer: 2},
		"b":  {FilePath: "b.tf"},
		"b2": {FilePath: "b.tf"},
	}
	vuln := func(fileID, resource string, line int) model.Vulnerability {
		return model.Vulnerability{FileID: fileID, QueryID: "q", ResourceType: "t", ResourceName: resource, Line: line}
	}
	in := []model.Vulnerability{
		vuln("a0", "static", 1),
		vuln("a0", "bucket-0", 5),
		vuln("a1", "static", 1),
		vuln("a1", "bucket-1", 5),
		vuln("a2", "static", 1),
		vuln("a2", "bucket-1", 5),
		vuln("b", "x", 1),
		vuln("b2", "x", 1),
	}
	out := dropRepeatedLayerFindings(in, files)

	var got []string
	for _, v := range out {
		got = append(got, v.FileID+":"+v.ResourceName)
	}
	require.Equal(t, []string{"a0:static", "a0:bucket-0", "a1:bucket-1", "b:x", "b2:x"}, got)
}

func TestDropRepeatedLayerFindings_NoLayers(t *testing.T) {
	files := map[string]*model.FileMetadata{"a": {FilePath: "a.tf"}, "b": {FilePath: "a.tf"}}
	in := []model.Vulnerability{{FileID: "a", Line: 1}, {FileID: "b", Line: 1}}
	require.Len(t, dropRepeatedLayerFindings(in, files), 2)
}

func TestDropRepeatedModuleContextUsesDefinitionLocation(t *testing.T) {
	files := map[string]*model.FileMetadata{
		"a0": {ID: "a0", FilePath: "a.tf"},
		"a1": {ID: "a1", FilePath: "a.tf", ExpansionContext: map[string]bool{
			moduleAttributionKey("t", 7, 1): true, moduleAttributionKey("t", 9, 1): false,
		}},
		"a2": {ID: "a2", FilePath: "a.tf", ExpansionContext: map[string]bool{
			moduleAttributionKey("t", 7, 1): true, moduleAttributionKey("t", 9, 1): false,
		}},
	}
	makeFinding := func(id string, line int) model.Vulnerability {
		return model.Vulnerability{FileID: id, QueryID: "q", ResourceType: "t", ResourceName: "display name",
			ModuleCallChain: "module.m", BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: line, Col: 1}}}
	}
	unique := makeFinding("a2", 7)
	unique.Remediation = "different evidence"
	got := dropRepeatedLayerFindings([]model.Vulnerability{
		makeFinding("a0", 7), makeFinding("a1", 7), makeFinding("a1", 9), makeFinding("a2", 9), unique,
	}, files)
	require.Len(t, got, 4, "drop copied context, keep actual instances and unique evidence even with the same display name")
}

func TestDropRepeatedLayerFindingsRetainsDifferentEvidence(t *testing.T) {
	files := map[string]*model.FileMetadata{
		"a0": {FilePath: "a.tf"},
		"a1": {FilePath: "a.tf", ExpansionLayer: 1},
		"a2": {FilePath: "a.tf", ExpansionLayer: 2},
	}
	value := "first"
	base := model.Vulnerability{FileID: "a0", QueryID: "q", ResourceType: "t", ResourceName: "same", Value: &value}
	for _, change := range []struct {
		name  string
		apply func(*model.Vulnerability)
	}{
		{"search value", func(v *model.Vulnerability) { v.SearchValue = "second" }},
		{"value", func(v *model.Vulnerability) { other := "second"; v.Value = &other }},
		{"nil value", func(v *model.Vulnerability) { v.Value = nil }},
		{"remediation", func(v *model.Vulnerability) { v.Remediation = "second" }},
		{"remediation type", func(v *model.Vulnerability) { v.RemediationType = "replacement" }},
		{"location", func(v *model.Vulnerability) { v.VulnerabilityLocation.Start.Line = 3 }},
		{"module caller", func(v *model.Vulnerability) { v.ModuleCallChain = "other" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			second := base
			second.FileID = "a1"
			change.apply(&second)
			repeat := second
			repeat.FileID = "a2"
			// Query result order need not match layer order.
			got := dropRepeatedLayerFindings([]model.Vulnerability{second, base, repeat}, files)
			require.Len(t, got, 2)
		})
	}
}

func TestInspectExpandedEvidenceAndCrossResourceContext(t *testing.T) {
	configs := map[string]string{
		"main.tf": `resource "aws_s3_bucket" "peer" { acl = "private" }
resource "aws_s3_bucket" "b" {
  count = 3
  acl = count.index == 1 ? "public-read-write" : "public-read"
}
`,
		"main.tf.json": `{
  "resource": {"aws_s3_bucket": {
    "peer": {"acl": "private"},
    "b": {
      "count": 3,
      "acl": "${count.index == 1 ? \"public-read-write\" : \"public-read\"}"
    }
  }}
}`,
	}
	rule := `package datadog
DatadogPolicy contains result if {
  some i
  doc := input.document[i]
  doc.resource.aws_s3_bucket.peer.acl == "private"
  bucket := doc.resource.aws_s3_bucket.b
  bucket.acl != "private"
  result := {
    "documentId": doc.id, "resourceType": "aws_s3_bucket", "resourceName": "b",
    "searchKey": "aws_s3_bucket[b].acl", "remediation": bucket.acl
  }
}`
	for filename, src := range configs {
		t.Run(filename, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filename)
			require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
			ins := newTestInspector(t, inspectorOpts{
				queries: []model.QueryMetadata{{Query: "evidence", Content: rule, InputData: "{}", Platform: "terraform",
					Metadata: map[string]interface{}{"id": "evidence"}, Aggregation: 1}},
				repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
			})
			got, err := ins.Inspect(context.Background(), "test", parseTerraform(t, path), []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, got, 2, "identical instances collapse, distinct evidence survives")
			var values []string
			for _, v := range got {
				values = append(values, v.Remediation)
				needle := "  acl = count.index"
				if strings.HasSuffix(filename, ".json") {
					needle = `      "acl":`
				}
				line := strings.Count(src[:strings.Index(src, needle)], "\n") + 1
				require.Equal(t, line, v.Line)
			}
			require.ElementsMatch(t, []string{"public-read", "public-read-write"}, values)

			caller := filepath.Join(root, "stack", "main.tf")
			require.NoError(t, os.MkdirAll(filepath.Dir(caller), 0o755))
			require.NoError(t, os.WriteFile(caller, []byte(`module "m" { source = "../" }`), 0o600))
			files := append(parseTerraform(t, caller), parseTerraform(t, path)...)
			got, err = ins.Inspect(context.Background(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, got, 3, "peer context must survive in every actual module instance")
			values = nil
			for _, finding := range got {
				require.NotNil(t, finding.ModuleAttribution)
				values = append(values, finding.Remediation)
			}
			require.ElementsMatch(t, []string{"public-read", "public-read-write", "public-read"}, values)
		})
	}
}

// Only the instances that are misconfigured are reported, and the blocks
// around an expanded one are reported once, not once per layer.
func TestInspect_PlainCountAndForEachInstancesReportedOnce(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(`
resource "aws_s3_bucket" "static" {
  acl = "public-read"
}

resource "aws_s3_bucket" "counted" {
  count = 3
  acl   = count.index == 1 ? "public-read" : "private"
}

resource "aws_s3_bucket" "each" {
  for_each = { a = "public-read", b = "private" }
  acl      = each.value
}

resource "aws_s3_bucket" "none" {
  count = 0
  acl   = "public-read"
}
`), 0o644))

	files := parseTerraform(t, path)
	require.Greater(t, len(files), 1, "the expanded blocks are layered")

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query:       "acl_rule",
			Content:     aclRule,
			InputData:   "{}",
			Platform:    "terraform",
			Metadata:    map[string]interface{}{"id": "acl-rule"},
			Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	names := map[string]int{}
	for _, v := range vulns {
		names[v.ResourceName]++
	}
	require.Equal(t, map[string]int{"static": 1, "counted": 1, "each": 1}, names)
}
