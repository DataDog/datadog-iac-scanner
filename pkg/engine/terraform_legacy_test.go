/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// writtenExpansionRule fires only on a root block documented as written: once,
// under its label, with count or for_each and the iteration references as
// written.
const writtenExpansionRule = `package datadog

DatadogPolicy contains result if {
	some i, name
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.bucket == "${each.value}"
	count(bucket.for_each) == 2
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].for_each", [name]),
	}
}

DatadogPolicy contains result if {
	some i, name
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.bucket == "web-${count.index}"
	bucket.count == 2
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].count", [name]),
	}
}
`

// Legacy rules read a root block count or for_each expands once, as written,
// as the previous engine's documents carried it: one entry per instance would
// report the block once per instance and hide count, for_each and the
// iteration references the rules read. The finding keeps the address of the
// block's first instance.
func TestInspect_RootExpandedBlockKeepsItsWrittenEntry(t *testing.T) {
	root := t.TempDir()
	file := writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "each" {
  for_each = toset(["a", "b"])
  bucket   = each.value
}

resource "aws_s3_bucket" "counted" {
  count  = 2
  bucket = "web-${count.index}"
}
`)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "written_expansion", Content: writtenExpansionRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "written-expansion", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", parseTerraformWritten(t, file), []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "one finding per written block, not per instance")

	got := map[string]model.Vulnerability{}
	for i := range vulns {
		got[vulns[i].ResourceName] = vulns[i]
	}
	require.Equal(t, 3, got["each"].Line)
	require.Equal(t, `aws_s3_bucket.each["a"]`, got["each"].ResourceID)
	require.Equal(t, 8, got["counted"].Line)
	require.Equal(t, "aws_s3_bucket.counted[0]", got["counted"].ResourceID)
}

func TestSplitTerraformRules(t *testing.T) {
	const pkg = "package datadog\n"
	queries := []model.QueryMetadata{
		{Query: "finding", Content: pkg + "import data.generic.common as c\nDatadogPolicy contains c.finding(b, [], {}) if { some b in x }"},
		{Query: "blocks", Content: pkg + "import data.generic.terraform as t\nDatadogPolicy contains r if { some b in t.blocks(\"aws_s3_bucket\") }"},
		{Query: "qualified", Content: pkg + "DatadogPolicy contains data.generic.common.finding(b, [], {}) if { some b in x }"},
		{Query: "document", Content: pkg + "DatadogPolicy contains r if { input.document[i].resource }"},
		{Query: "comment", Content: pkg + "# common.finding( is only mentioned here\nDatadogPolicy contains r if { input.document[i].resource }"},
		{Query: "other_package", Content: pkg + "import data.generic.terraform as t\nDatadogPolicy contains r if { t.resource_type(\"x\") }"},
		{
			Query:    "forced",
			Content:  pkg + "import data.generic.common as common\nDatadogPolicy contains common.finding(b, [], {}) if { some b in x }",
			Metadata: map[string]interface{}{"contract": "legacy"},
		},
	}
	contract, legacy := splitTerraformRules(queries)
	names := func(qs []model.QueryMetadata) []string {
		out := make([]string, len(qs))
		for i := range qs {
			out[i] = qs[i].Query
		}
		return out
	}
	require.Equal(t, []string{"finding", "blocks", "qualified"}, names(contract))
	require.Equal(t, []string{"document", "comment", "other_package", "forced"}, names(legacy))
}
