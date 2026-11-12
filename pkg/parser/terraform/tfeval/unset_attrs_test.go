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

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

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

func TestIsUserMarked(t *testing.T) {
	plain := cty.StringVal("a")
	inst := markEmptyResourceInstance(cty.EmptyObjectVal)
	require.False(t, isUserMarked(plain))
	require.False(t, isUserMarked(inst))
	require.True(t, isUserMarked(plain.Mark("sensitive")))
	require.True(t, isUserMarked(inst.Mark("sensitive")))
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
