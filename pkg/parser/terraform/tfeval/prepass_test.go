/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func parsePrepassModule(t *testing.T, src string) ([]*hclsyntax.Block, map[string]hclsyntax.Expression, []*hclsyntax.Block) {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	bodies := []*hclsyntax.Body{file.Body.(*hclsyntax.Body)}
	_, locals, modules, _, _ := collectBlocks(bodies)
	return modules, locals, collectDataBlocks(bodies)
}

func TestPlanSiblingPrepass(t *testing.T) {
	for _, tc := range []struct {
		name    string
		src     string
		members []bool
	}{
		{
			name: "earlier siblings only",
			src: `
module "a" { source = "./a" }
locals { first = module.a.out }
module "b" {
  source = "./b"
  in     = local.first
}
data "aws_iam_policy_document" "p" {
  statement { resources = [module.b.out] }
}
module "c" {
  source = "./c"
  in     = data.aws_iam_policy_document.p.json
}`,
			members: []bool{false, false, false},
		},
		{
			name: "forward reference and what it reads directly",
			src: `
module "a" { source = "./a" }
module "b" {
  source = "./b"
  in     = module.c.out
}
module "c" {
  source = "./c"
  in     = module.a.out
}`,
			members: []bool{true, false, true},
		},
		{
			name: "forward reference through a local and a data block",
			src: `
locals { later = data.aws_iam_policy_document.p.json }
data "aws_iam_policy_document" "p" {
  statement { resources = [module.b.out] }
}
module "a" {
  source = "./a"
  in     = local.later
}
module "b" { source = "./b" }`,
			members: []bool{false, true},
		},
		{
			name: "for_each reading a later sibling",
			src: `
module "a" {
  source   = "./a"
  for_each = module.b.names
}
module "b" { source = "./b" }`,
			members: []bool{false, true},
		},
		{
			name: "depends_on is not read",
			src: `
module "a" {
  source     = "./a"
  depends_on = [module.b]
}
module "b" { source = "./b" }`,
			members: []bool{false, false},
		},
		{
			name: "reading module as a whole reads every call",
			src: `
module "a" {
  source = "./a"
  in     = module
}
module "b" { source = "./b" }`,
			members: []bool{true, true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planSiblingPrepass(parsePrepassModule(t, tc.src))
			require.Equal(t, tc.members, plan.members)
			any := false
			for _, m := range tc.members {
				any = any || m
			}
			require.Equal(t, any, plan.any)
		})
	}
}

// A call reading only earlier siblings needs no speculative evaluation: each
// module is evaluated once, where the prepass used to evaluate b twice (its
// speculative inputs lacked a's output, so the main loop missed the cache).
func TestEvaluateModule_NoPrepassWithoutForwardReferences(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" {
  default = ""
}
output "out" { value = "out-${var.in}" }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "a" {
  source = "../child"
  in     = "a"
}
locals { first = module.a.out }
module "b" {
  source = "../child"
  in     = local.first
}
`})
	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.Len(t, e.cache, 3, "a, b and the stack, each evaluated once")
	var buckets []string
	for _, r := range resources {
		buckets = append(buckets, r.Attributes["bucket"].AsString())
	}
	require.ElementsMatch(t, []string{"a", "out-a"}, buckets)
}

func TestEvaluateModule_ForwardReferenceStillResolves(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "producer", map[string]string{"main.tf": `
output "out" { value = "produced" }
`})
	writeModule(t, root, "consumer", map[string]string{"main.tf": `
variable "in" {}
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
	// consumer.tf sorts before producer.tf, so the call reads a later sibling.
	dir := writeModule(t, root, "stack", map[string]string{
		"consumer.tf": `
module "consumer" {
  source = "../consumer"
  in     = module.producer.out
}`,
		"producer.tf": `
module "producer" { source = "../producer" }
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	requireString(t, findResource(t, resources, "aws_s3_bucket", "b").Attributes, "bucket", "produced")
}

func TestEvaluateModule_SharesFunctionTablePerDirectory(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" {}
resource "aws_s3_bucket" "b" { bucket = upper(var.in) }
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "c" {
  source   = "../child"
  for_each = toset(["x", "y"])
  in       = each.key
}
`})
	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 2)
	require.NotSame(t, resources[0].Scope, resources[1].Scope)
	require.Equal(t,
		reflect.ValueOf(resources[0].Scope.evalCtx.Functions).Pointer(),
		reflect.ValueOf(resources[1].Scope.evalCtx.Functions).Pointer(),
		"instances of one directory share its function table")
	require.Len(t, e.funcTables, 2, "one table for the stack and one for the child")
}

// A scope keeps only what rendering its unresolved values can read; the
// rendered documents are unchanged.
func TestKeepRenderContext_KeepsOnlyRenderedRoots(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "name" {}
locals { unused = "x" }
resource "aws_iam_role" "r" { name = var.name }
resource "aws_iam_role_policy" "p" {
  name = "${var.name}-policy"
  role = aws_iam_role.r.id
}
resource "aws_s3_bucket" "known" { bucket = var.name }
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "c" {
  source = "../child"
  name   = "svc"
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	policy := findResource(t, resources, "aws_iam_role_policy", "p")
	vars := policy.Scope.evalCtx.Variables
	require.Contains(t, vars, "aws_iam_role")
	require.Contains(t, vars, "var")
	require.NotContains(t, vars, "local")
	require.NotContains(t, vars, "aws_s3_bucket")

	doc := AttributesToDocument(ptr(policy))
	require.Equal(t, "svc-policy", doc["name"])
	require.Equal(t, "${aws_iam_role.r.id}", doc["role"])
}

func TestExpandBlock_ForEachSetStoredOnceInIterationOrder(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
resource "aws_cloudwatch_log_group" "g" {
  for_each = toset(["c", "a", "b"])
  name     = each.key
}
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "c" { source = "../child" }
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 3)
	want := cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b"), cty.StringVal("c")})
	for _, r := range resources {
		require.True(t, want.RawEquals(r.Attributes[forEachAttr]), r.Attributes[forEachAttr].GoString())
		require.Equal(t, []interface{}{"a", "b", "c"}, AttributesToDocument(ptr(r))[forEachAttr])
	}
}

// A for_each collection within the earlier cap stays readable through a
// reference to the whole object, as before; a larger one is not copied into
// every instance of the injected object.
func TestReferenceAttributes_LargeForEachLeftOut(t *testing.T) {
	small := cty.SetVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})
	attrs := map[string]cty.Value{forEachAttr: small, "name": cty.StringVal("x")}
	require.Contains(t, referenceAttributes(attrs), forEachAttr)

	elems := make([]cty.Value, legacyCountExpansion+1)
	for i := range elems {
		elems[i] = cty.StringVal(fmt.Sprintf("k%d", i))
	}
	large := map[string]cty.Value{forEachAttr: cty.TupleVal(elems), "name": cty.StringVal("x")}
	got := referenceAttributes(large)
	require.NotContains(t, got, forEachAttr)
	require.Contains(t, got, "name")
	require.Contains(t, large, forEachAttr, "the instance's own attributes are left as they are")
}

// The documents of a block's instances share one converted for_each
// collection, so a block of N instances does not hold N copies of it.
func TestAttributesToDocumentCached_SharesForEach(t *testing.T) {
	root := t.TempDir()
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "c" { source = "../child" }
`})
	writeModule(t, root, "child", map[string]string{"main.tf": `
resource "aws_cloudwatch_log_group" "g" {
  for_each = { for i in range(60) : "k${i}" => i }
  name     = each.key
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 60)
	cache := NewDocumentCache()
	first := AttributesToDocumentCached(ptr(resources[0]), cache)
	second := AttributesToDocumentCached(ptr(resources[1]), cache)
	require.Equal(t, AttributesToDocument(ptr(resources[0])), first, "sharing must not change the document")
	require.Equal(t, reflect.ValueOf(first[forEachAttr]).Pointer(), reflect.ValueOf(second[forEachAttr]).Pointer())
	require.NotEqual(t, first["name"], second["name"])
}
