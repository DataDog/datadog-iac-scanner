package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/ruletest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatMismatches(t *testing.T) {
	f := ruletest.Finding{QueryName: "q", Severity: "HIGH", Line: 3, FileName: "positive.tf"}
	assert.Equal(t, []string{
		`Missing expected: main.ruleFinding{QueryName:"q", Severity:"HIGH", Line:3, FileName:"positive.tf"}`,
		`Unexpected finding: main.ruleFinding{QueryName:"q", Severity:"HIGH", Line:3, FileName:"positive.tf"}`,
		`Result missing required field "searchKey"`,
		`case 2 with arguments: Unexpected finding: main.ruleFinding{QueryName:"q", Severity:"HIGH", Line:3, FileName:"positive.tf"}`,
		`case 1 without arguments: No argument test sample files found`,
	}, formatMismatches([]ruletest.Mismatch{
		{Kind: ruletest.MissingFinding, Finding: f},
		{Kind: ruletest.UnexpectedFinding, Finding: f},
		{Kind: ruletest.InvalidResult, Message: `Result missing required field "searchKey"`},
		{Kind: ruletest.UnexpectedFinding, Case: 2, Arguments: true, Finding: f},
		{Kind: ruletest.MissingFixtures, Case: 1, Message: "No argument test sample files found"},
	}))
}

func TestRuleTestOptionsKeepAPIGroupingOnlyForLegacyTerraform(t *testing.T) {
	assets := t.TempDir()
	writeRuleTestFiles(t, assets, map[string]string{
		"libraries/common.rego": `package generic.common
import rego.v1
finding(subject, path, details) := object.union(details, {"_dd_id": subject._dd_meta.id, "path": path})
`,
		"libraries/terraform.rego": `package generic.terraform
import rego.v1
blocks(type) := object.get(input._dd, ["blocks", "resource", type], [])
`,
		"queries/terraform/modern/metadata.json": `{"id":"modern","queryName":"Modern","platform":"Terraform","severity":"HIGH","category":"Best Practices"}`,
		"queries/terraform/modern/query.rego": `package datadog
import rego.v1
import data.generic.common as common
import data.generic.terraform as tf
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	result := common.finding(b, [], {})
}
`,
		"queries/terraform/modern/test/positive1.tf": `resource "aws_s3_bucket" "b" {}
`,
		"queries/terraform/modern/test/positive2.tf": `resource "aws_s3_bucket" "b" {}
`,
		"queries/terraform/modern/test/positive_expected_result.json": `[
  {"queryName":"Modern","severity":"HIGH","line":1,"fileName":"positive1.tf"},
  {"queryName":"Modern","severity":"HIGH","line":1,"fileName":"positive2.tf"}
]`,
		"queries/terraform/legacy/metadata.json": `{"id":"legacy","queryName":"Legacy","platform":"Terraform","severity":"HIGH","category":"Best Practices"}`,
		"queries/terraform/legacy/query.rego": `package datadog
import rego.v1
DatadogPolicy contains result if {
	some bucket in input.document
	bucket.resource.aws_s3_bucket.b
	some versioning in input.document
	versioning.resource.aws_s3_bucket_versioning.v
	result := {"documentId": bucket.id, "resourceType": "aws_s3_bucket", "resourceName": "b", "searchKey": "bucket"}
}
`,
		"queries/terraform/legacy/test/positive1.tf": `resource "aws_s3_bucket" "b" {}
`,
		"queries/terraform/legacy/test/positive2.tf": `resource "aws_s3_bucket_versioning" "v" {}
`,
		"queries/terraform/legacy/test/positive_expected_result.json": `[
  {"queryName":"Legacy","severity":"HIGH","line":1}
]`,
	})

	suite, err := ruletest.LoadDir(context.Background(), assets)
	require.NoError(t, err)
	require.Len(t, suite.Rules, 2)
	rules := make(map[string]*ruletest.Rule, len(suite.Rules))
	for _, rule := range suite.Rules {
		rules[rule.ID] = rule
	}

	apiOptions := ruletest.Options{LegacyRoots: true}
	modern := rules["modern"]
	require.NotNil(t, modern)
	// The backend can publish fixture files with the same name. They are
	// separate roots for contract rules, but LegacyRoots writes them to one
	// path, where the later fixture replaces the earlier one.
	modern.Tests.Files = []ruletest.File{
		{Name: "positive.tf", Content: []byte(`resource "aws_s3_bucket" "b" {}`)},
		{Name: "positive.tf", Content: []byte(`resource "aws_s3_bucket" "b" {}`)},
	}
	modern.Tests.Expected = []ruletest.Finding{
		{QueryName: "Modern", Severity: "HIGH", Line: 1, FileName: "positive.tf"},
		{QueryName: "Modern", Severity: "HIGH", Line: 1, FileName: "positive.tf"},
	}
	modernWithLegacyRoots, err := suite.Run(context.Background(), modern, apiOptions)
	require.NoError(t, err)
	assert.False(t, modernWithLegacyRoots.Passed(), "the two same-address fixtures collapse when evaluated as one legacy root")
	modernResult, err := suite.Run(context.Background(), modern, ruleTestOptions(modern, apiOptions))
	require.NoError(t, err)
	assert.True(t, modernResult.Passed(), "contract findings from independent roots must both be retained")

	legacy := rules["legacy"]
	require.NotNil(t, legacy)
	legacyResult, err := suite.Run(context.Background(), legacy, ruleTestOptions(legacy, apiOptions))
	require.NoError(t, err)
	assert.True(t, legacyResult.Passed(), "legacy API fixtures still need cross-file aggregation")
}

func writeRuleTestFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	}
}
