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

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// instanceLocal returns the value of a local in the scope a resource was evaluated in.
func instanceLocal(t *testing.T, r ResolvedResource, name string) cty.Value {
	t.Helper()
	require.NotNil(t, r.Scope)
	require.True(t, r.Scope.Local.Type().HasAttribute(name), "local %q missing", name)
	return r.Scope.Local.GetAttr(name)
}

func TestEvaluateModule_ModuleLoopSharesLocalsDerivedFromSharedInputs(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "acl", map[string]string{
		"main.tf": `
variable "service" { type = string }
variable "config"  { type = any }
locals {
  owners = { for svc, cfg in var.config : svc => cfg.owner }
  mine   = "${var.service}-${local.owners[var.service]}"
}
resource "aws_sqs_queue" "this" {
  name = local.mine
  tags = local.owners
}
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
locals {
  config = {
    a = { owner = "team-a" }
    b = { owner = "team-b" }
    c = { owner = "team-c" }
  }
}
module "acl" {
  source   = "../acl"
  for_each = local.config
  service  = each.key
  config   = local.config
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	byAddr := resourcesByAddress(resources)

	var owners []cty.Value
	for _, svc := range []string{"a", "b", "c"} {
		r, ok := byAddr[fmt.Sprintf(`module.acl[%q]/aws_sqs_queue.this`, svc)]
		require.True(t, ok, "%v", byAddr)
		requireString(t, r.Attributes, "name", svc+"-team-"+svc)
		require.Equal(t, "team-b", r.Attributes["tags"].GetAttr("b").AsString())
		owners = append(owners, instanceLocal(t, r, "owners"))
		require.Equal(t, svc+"-team-"+svc, instanceLocal(t, r, "mine").AsString(),
			"a local reading the instance's own input is not shared")
	}
	require.True(t, sharesStorage(owners[0], owners[1]) && sharesStorage(owners[1], owners[2]),
		"instances reading the same configuration share the local derived from it")
}

func TestEvaluateModule_SharedLocalsAreKeyedByTheValuesTheyRead(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "config" { type = any }
locals {
  common = upper(var.config.common)
  own    = upper(var.config.own)
}
resource "aws_sqs_queue" "this" {
  name = "${local.common}-${local.own}"
}
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "child" {
  source   = "../child"
  for_each = toset(["x", "y"])
  config   = { common = "shared", own = each.key }
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	byAddr := resourcesByAddress(resources)
	x := byAddr[`module.child["x"]/aws_sqs_queue.this`]
	y := byAddr[`module.child["y"]/aws_sqs_queue.this`]
	requireString(t, x.Attributes, "name", "SHARED-X")
	requireString(t, y.Attributes, "name", "SHARED-Y")
}

func TestEvaluateModule_LocalsReadingResourcesAreNotShared(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "name" { type = string }
resource "aws_s3_bucket" "this" { bucket = var.name }
locals { logs = "${aws_s3_bucket.this.bucket}-logs" }
resource "aws_s3_bucket" "logs" { bucket = local.logs }
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "child" {
  source   = "../child"
  for_each = toset(["x", "y"])
  name     = each.key
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	byAddr := resourcesByAddress(resources)
	requireString(t, byAddr[`module.child["x"]/aws_s3_bucket.logs`].Attributes, "bucket", "x-logs")
	requireString(t, byAddr[`module.child["y"]/aws_s3_bucket.logs`].Attributes, "bucket", "y-logs")
}

// The functions a local calls resolve files against the module and root
// directories, so the same module expression reached from another root is not
// the same value even with the same inputs.
func TestEvaluateModule_SharedLocalsAreKeyedByRoot(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"main.tf": `
locals { version = trimspace(file("${path.root}/version.txt")) }
resource "aws_sqs_queue" "this" { name = local.version }
`,
	})
	var stacks []string
	for _, v := range []string{"one", "two"} {
		stacks = append(stacks, writeModule(t, root, "stack-"+v, map[string]string{
			"main.tf":     "module \"child\" {\n  source = \"../child\"\n}\n",
			"version.txt": v,
		}))
	}

	e := New()
	for i, v := range []string{"one", "two"} {
		resources, _, _, err := e.EvaluateModule(context.Background(), stacks[i], nil)
		require.NoError(t, err)
		requireString(t, resourcesByAddress(resources)["module.child/aws_sqs_queue.this"].Attributes, "name", v)
	}
}

func TestEqualValues_AgreesWithRawEquals(t *testing.T) {
	shared := cty.ObjectVal(map[string]cty.Value{
		"a": cty.ListVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y")}),
		"b": cty.MapVal(map[string]cty.Value{"k": cty.NumberIntVal(1)}),
	})
	wrap := func(v cty.Value) cty.Value { return cty.ObjectVal(map[string]cty.Value{"v": v}) }
	values := []cty.Value{
		shared,
		wrap(shared),
		wrap(cty.ObjectVal(map[string]cty.Value{
			"a": cty.ListVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y")}),
			"b": cty.MapVal(map[string]cty.Value{"k": cty.NumberIntVal(1)}),
		})),
		wrap(cty.ObjectVal(map[string]cty.Value{
			"a": cty.ListVal([]cty.Value{cty.StringVal("x"), cty.StringVal("z")}),
			"b": cty.MapVal(map[string]cty.Value{"k": cty.NumberIntVal(1)}),
		})),
		cty.TupleVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y")}),
		cty.ListVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y")}),
		cty.ListValEmpty(cty.String),
		cty.ListValEmpty(cty.Number),
		cty.MapValEmpty(cty.String),
		cty.EmptyObjectVal,
		cty.EmptyTupleVal,
		cty.SetVal([]cty.Value{cty.StringVal("x")}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.UnknownVal(cty.String)}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.NullVal(cty.String)}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.NullVal(cty.Number)}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.StringVal("x").Mark("m")}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.StringVal("x")}),
		cty.DynamicVal,
		cty.NullVal(cty.DynamicPseudoType),
		cty.StringVal("x"),
	}
	for i, a := range values {
		for j, b := range values {
			require.Equal(t, a.RawEquals(b), equalValues(a, b), "values %d and %d: %#v vs %#v", i, j, a, b)
		}
	}
	require.True(t, sharesStorage(wrap(shared).GetAttr("v"), shared))
}

// A plain unknown string may be null. An unknown string known to start with a
// prefix may not, so the two must not share one memoized comparison.
func TestLocalValue_DoesNotReuseARefinedUnknown(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte("var.x == null"), "t.hcl", hcl.InitialPos)
	require.False(t, diags.HasErrors())

	e := New()
	ctxFor := func(x cty.Value) *hcl.EvalContext {
		vars := map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{"x": x}),
		}
		for name, value := range functions.ContextVariables("/mod", "/root") {
			vars[name] = value
		}
		return &hcl.EvalContext{Variables: vars}
	}
	plain := e.localValue(expr, ctxFor(cty.UnknownVal(cty.String)))
	refined := e.localValue(expr, ctxFor(
		cty.UnknownVal(cty.String).Refine().NotNull().StringPrefix("arn:").NewValue(),
	))

	require.False(t, plain.IsKnown(), "a plain unknown string may be null")
	require.True(t, refined.RawEquals(cty.False), "a string known to start with a prefix is not null")
}
