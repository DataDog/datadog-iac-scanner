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
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

func TestRenderFunctionsKeepTheirEvaluationRegistry(t *testing.T) {
	e := New()
	first := cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("first")})
	firstAt := instanceAt{dir: "first", addr: "terraform_data.source", kind: refManaged, typ: "terraform_data", name: "source"}
	e.registry.register(&firstAt, first)
	firstFuncs := e.moduleContext("first", "first").functions

	e.ReleaseEvalCache()
	second := cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("second")})
	secondAt := instanceAt{dir: "second", addr: "terraform_data.source", kind: refManaged, typ: "terraform_data", name: "source"}
	e.registry.register(&secondAt, second)
	secondFuncs := e.moduleContext("second", "second").functions

	for name, tc := range map[string]struct {
		value cty.Value
		funcs map[string]function.Function
	}{
		"first render context": {value: first, funcs: firstFuncs},
		"second evaluation":    {value: second, funcs: secondFuncs},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := &hcl.EvalContext{
				Variables: map[string]cty.Value{"local": cty.ObjectVal(map[string]cty.Value{"s": tc.value})},
				Functions: tc.funcs,
			}
			for expr, want := range map[string]cty.Value{
				`try(local.s.missing, "fallback")`:            cty.DynamicVal,
				`can(local.s.missing)`:                        cty.UnknownVal(cty.Bool),
				`try(merge({}, local.s).missing, "fallback")`: cty.DynamicVal,
			} {
				parsed, diags := hclsyntax.ParseExpression([]byte(expr), "test.tf", hcl.InitialPos)
				require.False(t, diags.HasErrors(), "%s", diags.Error())
				got, diags := parsed.Value(ctx)
				require.False(t, diags.HasErrors(), "%s", diags.Error())
				require.True(t, got.RawEquals(want), "%s = %#v, want %#v", expr, got, want)
			}
		})
	}
}

// An attribute a resource leaves to its provider is unknown to try and can
// however the resource object is reached, as Terraform 1.15 plans it; a
// missing key of a value the configuration sets still falls through.
func TestEvaluateModule_UnsetAttributesThroughAliasesAreUnknown(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `variable "in" {}
output "try_var" {
  value = try(var.in.output, "fallback")
}
output "res" {
  value = terraform_data.inner
}
resource "terraform_data" "inner" {
  input = "inner"
}
`})
	dir := writeModule(t, root, ".", map[string]string{"main.tf": `resource "terraform_data" "source" {
  input = "secure"
}
resource "terraform_data" "counted" {
  count = 2
  input = "c${count.index}"
}
locals {
  s   = terraform_data.source
  l   = [terraform_data.source]
  o   = { src = terraform_data.source }
  c   = terraform_data.counted
  cfg = { a = "b" }
}
module "m" {
  source = "./child"
  in     = terraform_data.source
}
output "alias_try" {
  value = try(local.s.output, "fallback")
}
output "alias_can" {
  value = can(local.s.output)
}
output "alias_index" {
  value = try(local.s["output"], "fallback")
}
output "list_elem" {
  value = try(local.l[0].output, "fallback")
}
output "object_member" {
  value = try(local.o.src.output, "fallback")
}
output "alias_splat" {
  value = try(local.c[*].output, "fallback")
}
output "for_expr" {
  value = try([for r in local.l : r.output], "fallback")
}
output "one_splat" {
  value = try(one(local.s[*]).output, "fallback")
}
output "module_var" {
  value = module.m.try_var
}
output "module_output" {
  value = try(module.m.res.output, "fallback")
}
output "set_attr" {
  value = try(local.s.input, "fallback")
}
output "set_attr_key" {
  value = try(local.s.input.x, "fallback")
}
output "plain_missing" {
  value = try(local.cfg.missing, "fallback")
}
output "plain_can" {
  value = can(local.cfg.missing)
}
`})
	_, outputs, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	for _, name := range []string{
		"alias_try", "alias_can", "alias_index", "list_elem", "object_member", "alias_splat",
		"for_expr", "one_splat", "module_var", "module_output",
	} {
		require.False(t, outputs[name].IsKnown(), "%s = %#v, want unknown", name, outputs[name])
	}
	for name, want := range map[string]cty.Value{
		"set_attr":      cty.StringVal("secure"),
		"set_attr_key":  cty.StringVal("fallback"),
		"plain_missing": cty.StringVal("fallback"),
		"plain_can":     cty.False,
	} {
		require.True(t, outputs[name].RawEquals(want), "%s = %#v, want %#v", name, outputs[name], want)
	}
}

func TestEvaluateModule_ComputedAttributeThroughLocalKeepsForEachKeys(t *testing.T) {
	dir := writeModule(t, t.TempDir(), ".", map[string]string{"main.tf": `
variable "unknown_key" {}
variable "unknown_keys" {}

locals {
  keys = { alpha = "one", beta = "two" }
  via_known_index = { for key, _ in local.keys : key => terraform_data.zone[key].output }
  via_unknown_index = { for key, _ in local.keys : key => terraform_data.zone[var.unknown_key].output }
  transitive = local["via_known_index"]
}

resource "terraform_data" "zone" {
  for_each = local.keys
  input    = each.value
}

resource "r" "known" {
  for_each = local.transitive
  value    = each.value
}

resource "r" "unknown_index" {
  for_each = local.via_unknown_index
  value    = each.value
}

resource "r" "unknown_shape" {
  for_each = var.unknown_keys
  value    = each.value
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	for _, name := range []string{`known["alpha"]`, `known["beta"]`, `unknown_index["alpha"]`, `unknown_index["beta"]`} {
		instance := findResource(t, resources, "r", name)
		require.False(t, instance.Attributes["value"].IsKnown(), "%s.value should stay provider-computed/unknown", name)
	}
	unknownShape := findResource(t, resources, "r", "unknown_shape")
	require.False(t, unknownShape.InstanceKey.IsKnown(), "unknown for_each shape must remain an unkeyed placeholder")
	concreteShape := 0
	for _, resource := range resources {
		if resource.Type == "r" && (resource.Name == `known["alpha"]` || resource.Name == `known["beta"]`) {
			concreteShape++
		}
	}
	require.Equal(t, 2, concreteShape, "known map keys must survive an unknown computed attribute")
}

// A configuration object is not a resource instance because it has the same
// attributes: try and can step past a key it lacks, as Terraform does.
func TestEvaluateModule_LookalikeObjectsAreNotResourceInstances(t *testing.T) {
	dir := writeModule(t, t.TempDir(), ".", map[string]string{"main.tf": `resource "terraform_data" "source" {
  input = "secure"
}
locals {
  literal = { input = "secure" }
  copied  = { input = terraform_data.source.input }
  rebuilt = { for k, v in terraform_data.source : k => v }
}
output "literal_try" {
  value = try(local.literal.missing, "fallback")
}
output "literal_can" {
  value = can(local.literal.missing)
}
output "literal_index" {
  value = try(local.literal["missing"], "fallback")
}
output "copied_try" {
  value = try(local.copied.missing, "fallback")
}
output "rebuilt_try" {
  value = try(local.rebuilt.missing, "fallback")
}
output "rebuilt_can" {
  value = can(local.rebuilt.missing)
}
output "resource_try" {
  value = try(terraform_data.source.output, "fallback")
}
`})
	_, outputs, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	for name, want := range map[string]cty.Value{
		"literal_try":   cty.StringVal("fallback"),
		"literal_can":   cty.False,
		"literal_index": cty.StringVal("fallback"),
		"copied_try":    cty.StringVal("fallback"),
		"rebuilt_try":   cty.StringVal("fallback"),
		"rebuilt_can":   cty.False,
	} {
		require.True(t, outputs[name].RawEquals(want), "%s = %#v, want %#v", name, outputs[name], want)
	}
	// Reading the resource itself still tells apart what it leaves to its provider.
	require.False(t, outputs["resource_try"].IsKnown(), "resource_try = %#v", outputs["resource_try"])
}

// A resource instance and a lookalike object passed to the same module must
// not share a cache entry: try on a missing provider attr is unknown for the
// instance and the fallback for the lookalike.
func TestEvaluateModule_ResourceAndLookalikeModuleInputsDoNotShareCache(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" {}
output "acl" { value = try(var.in.output, "public-read") }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
resource "terraform_data" "src" {
  input = "secure"
}
module "from_resource" {
  source = "../child"
  in     = terraform_data.src
}
module "from_object" {
  source = "../child"
  in     = { input = terraform_data.src.input }
}
output "resource_acl" { value = module.from_resource.acl }
output "object_acl" { value = module.from_object.acl }
`})
	_, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.False(t, outputs["resource_acl"].IsKnown(),
		"resource instance missing attr stays unknown")
	require.True(t,
		outputs["object_acl"].RawEquals(cty.StringVal("public-read")),
		"lookalike object must keep its concrete fallback, got %#v", outputs["object_acl"],
	)
}

// Passing a marked empty resource into a module must not panic while hashing
// inputs, and the child must still see it as an instance.
func TestEvaluateModule_MarkedResourceModuleInputDoesNotDropChild(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "obj" {}
resource "terraform_data" "reader" {
  input = try(var.obj.id, "missing")
}
output "via" { value = try(var.obj.id, "fallback") }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
resource "terraform_data" "source" {}
module "a" {
  source = "../child"
  obj    = terraform_data.source
}
module "b" {
  source = "../child"
  obj    = merge({}, terraform_data.source)
}
resource "terraform_data" "after" {
  input = module.a.via
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 4, "root source/after and both module readers")
	readers := 0
	for _, r := range resources {
		if r.Type != "terraform_data" || r.Name != "reader" {
			continue
		}
		readers++
		require.False(t, r.Attributes["input"].IsKnown(), "%s reader input = %#v", r.ModuleAddress, r.Attributes["input"])
	}
	require.Equal(t, 2, readers)
	after := findResource(t, resources, "terraform_data", "after")
	require.False(t, after.Attributes["input"].IsKnown())
}

// An empty resource and a merge copy keep the instance mark; a lookalike empty
// object does not.
func TestEvaluateModule_EmptyAndMergedResourceObjectsAreUnknown(t *testing.T) {
	dir := writeModule(t, t.TempDir(), ".", map[string]string{"main.tf": `resource "terraform_data" "source" {}
locals {
  s      = terraform_data.source
  merged = merge({}, terraform_data.source)
  empty  = {}
}
output "alias_try" {
  value = try(local.s.id, "fallback")
}
output "alias_can" {
  value = can(local.s.id)
}
output "merged_try" {
  value = try(local.merged.id, "fallback")
}
output "merged_can" {
  value = can(local.merged.id)
}
output "empty_try" {
  value = try(local.empty.id, "fallback")
}
output "empty_can" {
  value = can(local.empty.id)
}
`})
	_, outputs, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	for _, name := range []string{"alias_try", "alias_can", "merged_try", "merged_can"} {
		require.False(t, outputs[name].IsKnown(), "%s = %#v, want unknown", name, outputs[name])
	}
	require.True(t, outputs["empty_try"].RawEquals(cty.StringVal("fallback")), "empty_try = %#v", outputs["empty_try"])
	require.True(t, outputs["empty_can"].RawEquals(cty.False), "empty_can = %#v", outputs["empty_can"])
}

func TestEvaluateModule_CleansInvariantResourceAttributes(t *testing.T) {
	dir := writeModule(t, t.TempDir(), ".", map[string]string{"main.tf": `
resource "terraform_data" "source" {}
resource "terraform_data" "many" {
  count  = 3
  input  = "v${count.index}"
  nested = [terraform_data.source]
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	instances := 0
	for _, resource := range resources {
		if resource.Type != "terraform_data" || resource.Label != "many" {
			continue
		}
		instances++
		require.False(t, resource.Attributes["nested"].HasMarkDeep(resourceInstanceMark{}))
	}
	require.Equal(t, 3, instances)
}

func TestWithoutResourceInstanceMarksPreservesUserMarks(t *testing.T) {
	instance := markResourceInstance(cty.EmptyObjectVal).Mark("sensitive")
	got := withoutResourceInstanceMarks(cty.TupleVal([]cty.Value{instance}))
	nested := got.Index(cty.NumberIntVal(0))
	require.False(t, nested.HasMark(resourceInstanceMark{}))
	require.True(t, nested.HasMark("sensitive"))
}

func TestIsUserMarked(t *testing.T) {
	plain := cty.StringVal("a")
	inst := markEmptyResourceInstance(cty.EmptyObjectVal)
	require.False(t, isUserMarked(plain))
	require.False(t, isUserMarked(inst))
	require.True(t, isUserMarked(plain.Mark("sensitive")))
	require.True(t, isUserMarked(inst.Mark("sensitive")))
}

func TestEqualValues_IgnoresResourceInstanceMark(t *testing.T) {
	plain := cty.EmptyObjectVal
	inst := markResourceInstance(plain)
	require.True(t, equalValues(plain, inst))
	require.True(t, equalValues(inst, markResourceInstance(plain)))
	require.False(t, equalValues(inst, inst.Mark("sensitive")))
}

// A try read per instance does not cost a search through the other instances.
func TestEvaluateModule_TryPerInstanceScalesLinearly(t *testing.T) {
	run := func(n int) time.Duration {
		dir := writeModule(t, t.TempDir(), ".", map[string]string{"main.tf": fmt.Sprintf(`resource "terraform_data" "many" {
  count = %d
  input = "v${count.index}"
}
locals {
  alias = terraform_data.many
}
resource "terraform_data" "reader" {
  count = %d
  input = try(local.alias[count.index].output, "fallback")
}
`, n, n)})
		start := time.Now()
		resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		require.Len(t, resources, 2*n)
		return time.Since(start)
	}
	run(100) // warm up
	small, large := run(500), run(2000)
	// 4x the instances: linear work is about 4x, a search of the others 16x.
	require.Less(t, large, 10*small+200*time.Millisecond, "500 instances took %v, 2000 took %v", small, large)
}
