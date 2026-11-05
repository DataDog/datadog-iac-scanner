/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

const resourceViaDataFixture = `
resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
}

data "aws_iam_policy_document" "p" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.b.bucket}"]
  }
}
`

func TestRootResourcesReevaluateWhenConsumingDataThroughLocal(t *testing.T) {
	src := resourceViaDataFixture + `
locals {
  policy = data.aws_iam_policy_document.p.json
}

resource "aws_iam_policy" "consumer" {
  policy = local.policy
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	_, _, _, resourceBlocks, _ := collectBlocks([]*hclsyntax.Body{file.Body.(*hclsyntax.Body)})
	types := declaredResourceTypes(resourceBlocks)
	dataLocals := parseLocals(t, src).dataLocals
	require.True(t, dataLocals["policy"])
	require.True(t, resourcesReadNamedLocals(resourceBlocks, dataLocals))
	require.False(t, resourcesReadResources(resourceBlocks, dataRoot))
	require.False(t, resourcesReadResources(resourceBlocks, types))

	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": src}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "consumer")))
	require.Contains(t, doc["policy"], `arn:aws:s3:::mybucket`)
}

func TestRootResourcesReevaluateWhenConsumingDataDirectly(t *testing.T) {
	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": resourceViaDataFixture + `
resource "aws_iam_policy" "direct" {
  policy = data.aws_iam_policy_document.p.json
}
`}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "direct")))
	require.Contains(t, doc["policy"], `arn:aws:s3:::mybucket`)
}

func TestRootResourcesReevaluateWhenConsumingDataThroughIndexedLocal(t *testing.T) {
	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": resourceViaDataFixture + `
locals {
  policy = data.aws_iam_policy_document.p.json
}
resource "aws_iam_policy" "consumer" {
  policy = local["policy"]
}
`}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "consumer")))
	require.Contains(t, doc["policy"], `arn:aws:s3:::mybucket`)
}

func TestModuleDataRefreshResolvesLongSourceChains(t *testing.T) {
	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": `
data "aws_iam_policy_document" "a" {
  source_policy_documents = [data.aws_iam_policy_document.b.json]
}
data "aws_iam_policy_document" "b" {
  source_policy_documents = [data.aws_iam_policy_document.c.json]
}
data "aws_iam_policy_document" "c" {
  source_policy_documents = [data.aws_iam_policy_document.d.json]
}
data "aws_iam_policy_document" "d" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]
}
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
resource "aws_iam_policy" "p" {
  policy = data.aws_iam_policy_document.a.json
}
`}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "p")))
	require.Contains(t, doc["policy"], `"Sid":"Base"`)
}

func TestSiblingModuleInputsSeeDataRefreshedFromEarlierOutputs(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "a", map[string]string{"main.tf": `
output "arn" { value = "arn:aws:s3:::from-a" }
`})
	writeModule(t, root, "b", map[string]string{"main.tf": `
variable "policy" {}
resource "aws_iam_policy" "p" { policy = var.policy }
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "a" { source = "../a" }

data "aws_iam_policy_document" "p" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = [module.a.arn]
  }
}

locals {
  policy = data.aws_iam_policy_document.p.json
}

module "b" {
  source = "../b"
  policy = local.policy
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "p")))
	require.Contains(t, doc["policy"], `arn:aws:s3:::from-a`)
	require.NotContains(t, doc["policy"], `${module.a.arn}`)
}

func TestEvaluateModule_LocalsReadThroughData(t *testing.T) {
	const policy = `
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
`
	for name, tc := range map[string]struct {
		files map[string]string
		want  map[string]string
	}{
		"try keeps existing values": {
			files: map[string]string{"main.tf": `
variable "acl" { default = "public-read" }
locals {
  base       = "public-read"
  from_var   = try(var.acl, "private")
  from_local = try(local.base, "private")
  has_local  = can(local.base)
}
resource "aws_x" "r" {
  from_var   = local.from_var
  from_local = local.from_local
  has_local  = local.has_local
}
`},
			want: map[string]string{"from_var": `"public-read"`, "from_local": `"public-read"`, "has_local": `true`},
		},
		"try waits for a local of a later block": {
			files: map[string]string{"main.tf": `
locals { x = try(local.y, "fb") }
locals { y = "real" }
resource "aws_x" "r" { v = local.x }
`},
			want: map[string]string{"v": `"real"`},
		},
		"null locals stay null": {
			files: map[string]string{"main.tf": `
locals {
  nothing  = lookup({}, "k", null)
  fallback = try(local.nothing, "fb")
}
resource "aws_x" "r" {
  nothing  = local.nothing
  fallback = local.fallback
  set      = "x"
}
`},
			want: map[string]string{"nothing": `null`, "fallback": `null`, "set": `"x"`},
		},
		"the last declaration of a local wins": {
			files: map[string]string{
				"main.tf": `
locals { acts = ["s3:Wrong"] }
locals { acts = ["s3:Right"] }
data "aws_iam_policy_document" "p" {
  statement { actions = local.acts }
}
resource "aws_x" "r" { v = data.aws_iam_policy_document.p.json }
`,
			},
			want: map[string]string{"v": `s3:Right`},
		},
		"dynamic key read of the local object": {
			files: map[string]string{"main.tf": `
locals {
  k   = "env"
  env = "production"
  acl = local[local.k]
}
resource "aws_x" "r" { v = local.acl }
`},
			want: map[string]string{"v": `"production"`},
		},
		"locals reading data resolve through variables": {
			files: map[string]string{"main.tf": policy + `
variable "env" { default = "prod" }
locals {
  base_json = data.aws_iam_policy_document.base.json
  tagged    = "${var.env}:${local.base_json}"
  indirect  = local["tagged"]
}
resource "aws_x" "r" { v = local.indirect }
`},
			want: map[string]string{"v": `prod:{\"Version\"`},
		},
		"try on missing data falls back": {
			files: map[string]string{"main.tf": policy + `
locals { out = try(data.aws_iam_policy_document.missing.json, "fb") }
resource "aws_x" "r" { v = local.out }
`},
			want: map[string]string{"v": `"fb"`},
		},
		"function-only local feeds a source policy": {
			files: map[string]string{"main.tf": `
locals {
  encoded = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "FromLocal", Effect = "Allow", Action = ["s3:GetObject"], Resource = "*" }]
  })
}
data "aws_iam_policy_document" "via" { source_policy_documents = [local.encoded] }
resource "aws_x" "r" { v = data.aws_iam_policy_document.via.json }
`},
			want: map[string]string{"v": `\"Sid\":\"FromLocal\"`},
		},
		"JSON local chain feeds a source policy": {
			files: map[string]string{"main.tf.json": `{
  "locals": [{
    "a": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"FromJSON\",\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}",
    "b": "${local.a}",
    "c": "${local.b}"
  }],
  "data": {"aws_iam_policy_document": {"via": {"source_policy_documents": ["${local.c}"]}}},
  "resource": {"aws_x": {"r": {"v": "${data.aws_iam_policy_document.via.json}"}}}
}`},
			want: map[string]string{"v": `\"Sid\":\"FromJSON\"`},
		},
		"local reading data does not cycle through a sibling": {
			files: map[string]string{"main.tf": `
locals {
  alias = data.aws_iam_policy_document.p.json
  safe  = "s3:GetObject"
}
data "aws_iam_policy_document" "p" {
  statement { actions = [local.safe] }
}
resource "aws_x" "r" { v = local.alias }
`},
			want: map[string]string{"v": `s3:GetObject`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeModule(t, t.TempDir(), "root", tc.files)
			resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
			require.NoError(t, err)
			doc := AttributesToDocument(ptr(findResource(t, resources, "aws_x", "r")))
			for key, want := range tc.want {
				raw, err := json.Marshal(doc[key])
				require.NoError(t, err)
				require.Contains(t, string(raw), want, key)
			}
		})
	}
}
