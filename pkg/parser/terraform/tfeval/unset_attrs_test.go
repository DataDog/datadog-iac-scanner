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
