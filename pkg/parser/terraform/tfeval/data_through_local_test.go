/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"os"
	"path/filepath"
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
	_, localExprs, _, resourceBlocks, _ := collectBlocks([]*hclsyntax.Body{file.Body.(*hclsyntax.Body)})
	types := declaredResourceTypes(resourceBlocks)
	dataLocals := localsReadingRoot(localExprs, dataRoot)
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

func TestNestedModuleDataAndResourcesAreAllInstantiated(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "mod_a"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "mod_b"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "stack"), 0o755))

	// mod_a: 2 resources + 2 data = 4, mod_b: 1 resource.
	require.NoError(t, os.WriteFile(filepath.Join(root, "mod_a", "main.tf"), []byte(`
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "b" {}
data "aws_region" "r" {}
data "aws_caller_identity" "c" {}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "mod_b", "main.tf"), []byte(`
resource "aws_s3_bucket" "only" {}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "stack", "main.tf"), []byte(`
module "a" { source = "../mod_a" }
module "b" { source = "../mod_b" }
`), 0o644))

	stack := filepath.Join(root, "stack")
	// Every instance of both modules is there.
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 5)
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
