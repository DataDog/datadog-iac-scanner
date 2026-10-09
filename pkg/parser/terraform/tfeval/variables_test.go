/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func resourcesByAddress(resources []ResolvedResource) map[string]ResolvedResource {
	out := make(map[string]ResolvedResource, len(resources))
	for _, r := range resources {
		out[r.ModuleAddress+"/"+r.Type+"."+r.Name] = r
	}
	return out
}

func TestEvaluateModule_VariableTypesShapeInputs(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "bucket", map[string]string{
		"main.tf": `
variable "names" { type = set(string) }
variable "settings" {
  type = object({
    versioning = optional(bool, true)
    encryption = optional(string, "aws:kms")
  })
}
variable "acl" {
  type     = string
  default  = "private"
  nullable = false
}
variable "replicas" { type = number }

resource "aws_s3_bucket" "this" {
  for_each   = var.names
  bucket     = each.key
  versioning = var.settings.versioning
  encryption = var.settings.encryption
  acl        = var.acl
  count_like = var.replicas + 1
}
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "bucket" {
  source   = "../bucket"
  names    = ["logs", "data"]
  settings = { versioning = false }
  acl      = null
  replicas = "2"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 2, "a list passed to a set(string) variable must expand for_each")

	byAddr := resourcesByAddress(resources)
	logs, ok := byAddr[`module.bucket/aws_s3_bucket.this["logs"]`]
	require.True(t, ok, "resources: %v", byAddr)
	require.True(t, logs.Attributes["versioning"].False(), "a value the caller sets wins over the optional default")
	requireString(t, logs.Attributes, "encryption", "aws:kms")
	requireString(t, logs.Attributes, "acl", "private")
	require.True(t, logs.Attributes["count_like"].RawEquals(cty.NumberIntVal(3)), "count_like = %#v", logs.Attributes["count_like"])
}

func TestEvaluateModule_PartlyKnownLocalsKeepKnownParts(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "kms_key_arn" {}

locals {
  base = {
    encrypted = true
    kms_key   = var.kms_key_arn
  }
  config = merge(local.base, { name = "logs" })
}

resource "aws_ebs_volume" "v" {
  encrypted  = local.config.encrypted
  kms_key_id = local.config.kms_key
  tags       = { Name = local.config.name }
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	v := findResource(t, resources, "aws_ebs_volume", "v")
	require.True(t, v.Attributes["encrypted"].True())
	require.False(t, v.Attributes["kms_key_id"].IsKnown())
	require.True(t, v.Attributes["tags"].GetAttr("Name").RawEquals(cty.StringVal("logs")))
}

func TestCanonicalInputsKeyKeepsKnownPartsOfPartlyUnknownValues(t *testing.T) {
	a := canonicalInputsKey(map[string]cty.Value{"cfg": cty.ObjectVal(map[string]cty.Value{
		"name": cty.StringVal("a"), "arn": cty.UnknownVal(cty.String),
	})})
	b := canonicalInputsKey(map[string]cty.Value{"cfg": cty.ObjectVal(map[string]cty.Value{
		"name": cty.StringVal("b"), "arn": cty.UnknownVal(cty.String),
	})})
	require.NotEqual(t, a, b)
}

func TestCanonicalInputsKeyDistinguishesCollectionTypes(t *testing.T) {
	elem := cty.UnknownVal(cty.String)
	listKey := canonicalInputsKey(map[string]cty.Value{"v": cty.ListVal([]cty.Value{elem})})
	tupleKey := canonicalInputsKey(map[string]cty.Value{"v": cty.TupleVal([]cty.Value{elem})})
	setKey := canonicalInputsKey(map[string]cty.Value{"v": cty.SetVal([]cty.Value{elem})})
	require.NotEqual(t, listKey, tupleKey)
	require.NotEqual(t, listKey, setKey)
	require.NotEqual(t, tupleKey, setKey)

	mapKey := canonicalInputsKey(map[string]cty.Value{"v": cty.MapVal(map[string]cty.Value{"k": elem})})
	objKey := canonicalInputsKey(map[string]cty.Value{"v": cty.ObjectVal(map[string]cty.Value{"k": elem})})
	require.NotEqual(t, mapKey, objKey)
}

func TestLoadRootVarsReadsJSONAndAppliesTerraformPrecedence(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "stack", map[string]string{
		"terraform.tfvars":      `env = "base"` + "\n" + `region = "us-east-1"`,
		"terraform.tfvars.json": `{"env": "json", "tags": {"team": "sec"}}`,
		"a.auto.tfvars":         `env = "auto"`,
		"b.auto.tfvars.json":    `{"region": "eu-west-1"}`,
	})

	vars := New().LoadRootVars(dir)
	require.True(t, vars["env"].RawEquals(cty.StringVal("auto")))
	require.True(t, vars["region"].RawEquals(cty.StringVal("eu-west-1")))
	require.Equal(t, "sec", vars["tags"].GetAttr("team").AsString())
}
