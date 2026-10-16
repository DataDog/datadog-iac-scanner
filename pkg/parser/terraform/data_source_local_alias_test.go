/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func Test_getDataSourcePolicy_localAliasOfDataJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  base_json = data.aws_iam_policy_document.base.json
}
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "combined" {
  source_policy_documents = [local.base_json]
  statement {
    sid     = "Own"
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	data := decodeData(t, result["data"])
	require.Equal(t,
		`{"Statement":[{"Actions":["sqs:*"],"Effect":"Allow","Sid":"Base"},{"Actions":["s3:GetObject"],"Effect":"Allow","Sid":"Own"}],"Version":"2012-10-17"}`+"\n",
		data["aws_iam_policy_document"]["combined"]["json"])
}

func Test_getDataSourcePolicy_localTryFallbackUpdatesWhenDataArrives(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  base_json = try(data.aws_iam_policy_document.base.json, data.aws_iam_policy_document.root.json)
}
data "aws_iam_policy_document" "root" {
  statement {
    sid     = "Root"
    actions = ["iam:GetUser"]
  }
}
data "aws_iam_policy_document" "leaf" {
  statement {
    sid     = "Leaf"
    actions = ["ec2:*"]
  }
}
data "aws_iam_policy_document" "base" {
  source_policy_documents = [data.aws_iam_policy_document.leaf.json]
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "combined" {
  source_policy_documents = [local.base_json]
  statement {
    sid     = "Own"
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	data := decodeData(t, result["data"])
	// base only renders on the second pass, so the first one falls back to root
	// and the local has to be overwritten once base exists.
	combined := data["aws_iam_policy_document"]["combined"]["json"]
	require.Contains(t, combined, `"Sid":"Base"`)
	require.Contains(t, combined, `"Sid":"Leaf"`)
	require.NotContains(t, combined, `"Sid":"Root"`)
}

func scanDataSourceDir(t *testing.T, files map[string]string) (before, after map[string]cty.Value) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	before = inputVars["local"].AsValueMap()
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	return before, result["local"].AsValueMap()
}

const unrelatedLocals = `
variable "env" {
  default = "prod"
}
locals {
  bucket = "logs-${var.env}"
}
`

func Test_getDataSourcePolicy_unrelatedLocalsDoNotDependOnPolicyDocuments(t *testing.T) {
	before, withoutDoc := scanDataSourceDir(t, map[string]string{"main.tf": unrelatedLocals})
	_, withDoc := scanDataSourceDir(t, map[string]string{
		"main.tf": unrelatedLocals,
		"policy.tf": `
data "aws_iam_policy_document" "x" {
  statement {
    actions = ["s3:*"]
  }
}
`,
	})
	require.NotContains(t, before, "bucket")
	require.NotContains(t, withoutDoc, "bucket")
	require.NotContains(t, withDoc, "bucket")
}

func Test_getDataSourcePolicy_localsReadingDataResolveThroughVariables(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{
		"main.tf": unrelatedLocals + `
locals {
  base_json = data.aws_iam_policy_document.base.json
  tagged    = "${var.env}:${local.base_json}"
  indirect  = local["tagged"]
}
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
`,
	})
	require.NotContains(t, locals, "bucket")
	for _, name := range []string{"tagged", "indirect"} {
		require.True(t, locals[name].IsKnown(), name)
		require.Contains(t, locals[name].AsString(), `prod:{"Statement"`, name)
		require.Contains(t, locals[name].AsString(), `"Sid":"Base"`, name)
	}
}

func Test_getDataSourcePolicy_lastDeclarationOfALocalWins(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{
		"main.tf": `
locals {
  base_json = data.aws_iam_policy_document.first.json
}
data "aws_iam_policy_document" "first" {
  statement {
    sid     = "First"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "second" {
  statement {
    sid     = "Second"
    actions = ["s3:*"]
  }
}
`,
		"main_override.tf": `
locals {
  base_json = data.aws_iam_policy_document.second.json
}
`,
	})
	require.Contains(t, locals["base_json"].AsString(), `"Sid":"Second"`)
	require.NotContains(t, locals["base_json"].AsString(), `"Sid":"First"`)
}

func Test_dataDependentLocals(t *testing.T) {
	parse := func(src string) []localAssignment {
		file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), diags.Error())
		return localAssignmentsFromBody(file.Body.(*hclsyntax.Body))
	}
	names := func(in []localAssignment) []string {
		out := make([]string, len(in))
		for i, item := range in {
			out[i] = item.name
		}
		sort.Strings(out)
		return out
	}
	all := append(parse(`
locals {
  plain    = "p-${var.env}"
  chained  = local.plain
  direct   = data.aws_iam_policy_document.a.json
  through  = "${local.direct}!"
  indexed  = local["through"]
  dynamic  = local[var.which]
  override = "o"
}
`), parse(`
locals {
  override = data.aws_iam_policy_document.a.json
  twice    = data.aws_iam_policy_document.a.json
}
locals {
  twice = "no longer data"
}
`)...)
	// override takes its last declaration and twice stops reading data, while
	// dynamic may read any local that does.
	require.Equal(t, []string{"direct", "dynamic", "indexed", "override", "through"}, names(dataDependentLocals(all)))
	require.Empty(t, dataDependentLocals(parse(`locals { a = "x" }`)))
}

func Test_getDataSourcePolicy_sourceDocumentWithUnresolvedConditionStaysUnresolved(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
data "aws_iam_policy_document" "guarded" {
  source_policy_documents = [jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "Pub", Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "*"
      Condition = var.cond
    }]
  })]
}
data "aws_iam_policy_document" "plain" {
  statement {
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	data := decodeData(t, result["data"])
	require.NotContains(t, data["aws_iam_policy_document"], "guarded")
	require.Contains(t, data["aws_iam_policy_document"], "plain")
}

func Test_getDataSourcePolicy_functionOnlyLocalFeedsSourcePolicy(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  encoded = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "FromLocal"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}
data "aws_iam_policy_document" "via" {
  source_policy_documents = [local.encoded]
}
data "aws_iam_policy_document" "plain" {
  statement {
    sid     = "Plain"
    actions = ["sqs:*"]
  }
}
`), 0o600))
	ctx := context.Background()
	vars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	require.Contains(t, vars["local"].AsValueMap(), "encoded")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	docs := result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap()
	require.Contains(t, docs, "plain")
	require.Contains(t, docs, "via")
	require.Contains(t, docs["via"].AsValueMap()["json"].AsString(), `"Sid":"FromLocal"`)
	// Unrelated var-only locals must still stay unresolved when a policy exists.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.tf"), []byte(`
variable "env" { default = "prod" }
locals { bucket = "logs-${var.env}" }
`), 0o600))
	vars = getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result = getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	require.NotContains(t, result["local"].AsValueMap(), "bucket")
	require.Contains(t, result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap(), "via")
}

func Test_getDataSourcePolicy_JSONLocalChainFeedsSource(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf.json"), []byte(`{
  "locals": [{
    "a": "base",
    "b": "${local.a}",
    "c": "${local.b}",
    "d": "${local.c}",
    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"FromJSON\",\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
  }],
  "data": {
    "aws_iam_policy_document": {
      "via": {
        "source_policy_documents": ["${local.policy}"]
      },
      "chain": {
        "source_policy_documents": ["${local.d}"]
      }
    }
  }
}`), 0o600))
	// Rewrite: chain test needs d to be the policy JSON after 4 hops.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf.json"), []byte(`{
  "locals": [{
    "a": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"FromJSON\",\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}",
    "b": "${local.a}",
    "c": "${local.b}",
    "d": "${local.c}"
  }],
  "data": {
    "aws_iam_policy_document": {
      "via": {
        "source_policy_documents": ["${local.d}"]
      }
    }
  }
}`), 0o600))
	ctx := context.Background()
	vars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	require.Contains(t, vars["local"].AsValueMap(), "d")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	docs := result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap()
	require.Contains(t, docs, "via")
	require.Contains(t, docs["via"].AsValueMap()["json"].AsString(), `"Sid":"FromJSON"`)
}

func Test_getDataSourcePolicy_sameFileLocalsLastWins(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  acts = ["s3:Wrong"]
}
locals {
  acts = ["s3:Right"]
}
data "aws_iam_policy_document" "p" {
  statement {
    actions = local.acts
  }
}
`), 0o600))
	ctx := context.Background()
	vars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	docs := result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap()
	require.Contains(t, docs["p"].AsValueMap()["json"].AsString(), `"s3:Right"`)
	require.NotContains(t, docs["p"].AsValueMap()["json"].AsString(), `"s3:Wrong"`)
}
