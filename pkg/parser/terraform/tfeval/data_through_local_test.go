/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
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

func TestRootResourcesConsumeDataThroughLocal(t *testing.T) {
	src := resourceViaDataFixture + `
locals {
  policy = data.aws_iam_policy_document.p.json
}

resource "aws_iam_policy" "consumer" {
  policy = local.policy
}
`

	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": src}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "consumer")))
	require.Contains(t, doc["policy"], `arn:aws:s3:::mybucket`)
}

func TestRootResourcesConsumeDataDirectly(t *testing.T) {
	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": resourceViaDataFixture + `
resource "aws_iam_policy" "direct" {
  policy = data.aws_iam_policy_document.p.json
}
`}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "direct")))
	require.Contains(t, doc["policy"], `arn:aws:s3:::mybucket`)
}

func TestRootResourcesConsumeDataThroughIndexedLocal(t *testing.T) {
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

// Policy documents used in Terraform expressions are computed values, whereas
// rule documents can retain a partial rendering of the configured statements.
func TestPolicyDocumentExpressionValues(t *testing.T) {
	for _, tc := range []struct {
		name     string
		actions  string
		known    bool
		contains bool
	}{
		{name: "known action", actions: `["s3:*"]`, known: true, contains: true},
		{name: "known other action", actions: `["s3:GetObject"]`, known: true},
		{name: "unknown action", actions: `[var.action]`},
		{name: "partially known actions", actions: `["s3:*", var.action]`},
		{name: "literal interpolation text", actions: `["$${literal}"]`, known: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources := evaluateWithChild(t, New(), map[string]string{"main.tf": fmt.Sprintf(`
variable "action" { type = string }
data "aws_iam_policy_document" "p" {
 statement {
  actions = %s
  resources = ["*"]
 }
}
locals {
 document = data.aws_iam_policy_document.p
 policy = local.document.json
}
resource "aws_iam_policy" "consumer" {
 policy = local.policy
 selected = coalesce(null, "", local.policy)
 ambiguous = coalesce(var.action, local.policy)
 selected_contains = strcontains(coalesce(null, local.policy), "s3:*")
 compact = data.aws_iam_policy_document.p.minified_json
 contains_action = strcontains(local.policy, "s3:*")
 configured = true
}
`, tc.actions)}, callChild)
			consumer := findResource(t, resources, "aws_iam_policy", "consumer")
			attrs := consumer.Attributes
			for _, name := range []string{"policy", "compact", "contains_action", "selected", "selected_contains"} {
				require.Equal(t, tc.known, attrs[name].IsWhollyKnown(), "%s = %#v", name, attrs[name])
			}
			doc := AttributesToDocument(&consumer)
			if !tc.known {
				require.Contains(t, doc["policy"], `"Actions":`)
				require.Contains(t, doc["selected"], `"Actions":`)
				require.Contains(t, doc["selected_contains"], "strcontains(")
				require.Contains(t, doc["contains_action"], "strcontains(")
			}
			require.False(t, attrs["ambiguous"].IsWhollyKnown())
			require.Contains(t, doc["ambiguous"], "coalesce(")
			require.True(t, attrs["configured"].RawEquals(cty.True))
			if tc.known {
				require.Equal(t, tc.contains, attrs["contains_action"].True())
			}
		})
	}
}

// Presentation aliases obey their declaration scope and lexical loop bindings.
func TestPolicyDocumentLexicalScopes(t *testing.T) {
	const definitions = `
variable "policy" { type = string }
variable "arn" { type = string }
variable "selector" { default = "intended" }
data "aws_iam_policy_document" "docs" {
  for_each = toset(["intended", "decoy"])
  statement {
    actions = ["${each.key}:*"]
    resources = [var.arn]
  }
}
locals {
  value = data.aws_iam_policy_document.docs["decoy"].json
  picked = data.aws_iam_policy_document.docs[var.selector].json
}
`
	for _, tc := range []struct {
		name, body, typ, field string
		wantActions            bool
	}{
		{"single dynamic binding", `
resource "aws_iam_role" "consumer" {
  dynamic "inline_policy" {
    iterator = local
    for_each = {a = var.policy}
    content {
      name = local.key
      policy = local.value
    }
  }
}`, "aws_iam_role", "inline_policy", false},
		{"repeated dynamic bindings", `
resource "aws_iam_role" "consumer" {
  dynamic "inline_policy" {
    iterator = local
    for_each = {a = var.policy, b = var.policy}
    content {
      name = local.key
      policy = local.value
    }
  }
}`, "aws_iam_role", "inline_policy", false},
		{"bound data expression", `
data "aws_iam_policy_document" "combined" {
  dynamic "statement" {
    iterator = local
    for_each = {a = var.policy}
    content {
      actions = ["intended:*"]
      resources = [local.value]
    }
  }
}
resource "aws_iam_policy" "consumer" {
  policy = data.aws_iam_policy_document.combined.json
}`, "aws_iam_policy", "policy", true},
		{"module alias under for binding", `
resource "aws_iam_policy" "consumer" {
  policy = [for var in [{selector = "decoy"}] : local.picked]
}`, "aws_iam_policy", "policy", true},
		{"module alias under dynamic binding", `
resource "aws_iam_role" "consumer" {
  dynamic "inline_policy" {
    iterator = var
    for_each = [{selector = "decoy"}]
    content {
      name = "configured"
      policy = local.picked
    }
  }
}`, "aws_iam_role", "inline_policy", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources := evaluateWithChild(t, New(), map[string]string{"main.tf": definitions + tc.body}, callChild)
			consumer := findResource(t, resources, tc.typ, "consumer")
			require.False(t, consumer.Attributes[tc.field].IsWhollyKnown())
			doc := fmt.Sprint(AttributesToDocument(&consumer)[tc.field])
			require.NotContains(t, doc, "decoy:*")
			if tc.wantActions {
				require.Contains(t, doc, "intended:*")
			} else {
				require.Contains(t, doc, "${local.value}")
			}
		})
	}
}
