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
