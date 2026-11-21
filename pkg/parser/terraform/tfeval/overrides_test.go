/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestResourceOverrides(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `
resource "example" "this" {
  value      = "base"
  depends_on = [example.sibling]
  setting {
    name = "one"
    extra = true
  }
  setting { name = "two" }
  preserved { name = "stays" }
  lifecycle {
    prevent_destroy       = true
    create_before_destroy = false
  }
  connection { host = "original" }
  provisioner "local-exec" { command = "base-one" }
  provisioner "remote-exec" { inline = ["base-two"] }
}
resource "example" "sibling" {}
`,
		"a_override.tf": `
resource "example" "this" {
  value = "first"
  depends_on = []
  setting { name = "replacement" }
  lifecycle { create_before_destroy = true }
  connection { user = "override" }
  provisioner "local-exec" { command = "override" }
}
`,
		"z_override.tf": `
resource "example" "this" {
  value = "last"
}
`,
	})
	e := New()
	resources, _, _, err := e.EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 2)
	r := resources[0]
	require.Equal(t, "this", r.Name)
	require.Equal(t, filepath.Join(dir, "main.tf"), r.DefinedIn)
	doc := AttributesToDocument(&r)
	require.Equal(t, "last", doc["value"])
	require.Equal(t, map[string]interface{}{"name": "replacement"}, doc["setting"])
	require.Equal(t, map[string]interface{}{"name": "stays"}, doc["preserved"])
	require.Equal(t, map[string]interface{}{"prevent_destroy": true, "create_before_destroy": true}, doc["lifecycle"])
	require.Equal(t, map[string]interface{}{"user": "override"}, doc["connection"])
	require.Equal(t, map[string]interface{}{"local-exec": map[string]interface{}{"command": "override"}}, doc["provisioner"])
	require.Equal(t, filepath.Join(dir, "main.tf"), r.Body.Attributes["depends_on"].SrcRange.Filename)
	require.Equal(t, filepath.Join(dir, "z_override.tf"), r.Body.Attributes["value"].SrcRange.Filename)
	overrides := e.ResourceOverrides(t.Context(), dir)
	require.Len(t, overrides, 1)
	require.Len(t, overrides[0].Contributions, 2)
	require.Equal(t, filepath.Join(dir, "a_override.tf"), overrides[0].Contributions[0].TypeRange.Filename)
	require.Equal(t, filepath.Join(dir, "z_override.tf"), overrides[0].Contributions[1].TypeRange.Filename)
	require.Same(t, overrides[0].Declaration.Body, r.DeclarationBody)
}

func TestResourceOverridesExpandInsideCalledModule(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `module "child" { source = "../child" }`,
	})
	child := writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "values" {
  type    = set(string)
  default = ["old"]
}
resource "example" "counted" {
  count = 1
  value = count.index
}
resource "example" "keyed" {
  for_each = toset(["old"])
  value    = each.key
}
data "example" "source" {
  value = "base"
  other = "retained"
}
`,
		"override.tf": `
variable "values" { default = ["new", "new"] }
resource "example" "counted" { count = 2 }
resource "example" "keyed" { for_each = var.values }
data "example" "source" { value = "override" }
`,
	})
	resources, _, _, err := New().EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 4)
	values := make(map[string]cty.Value)
	for _, r := range resources {
		require.Equal(t, filepath.Join(child, "main.tf"), r.DefinedIn)
		address, ok := r.TerraformAddress()
		require.True(t, ok)
		values[address] = r.Attributes["value"]
		if r.Data {
			require.Equal(t, cty.StringVal("retained"), r.Attributes["other"])
		}
	}
	require.Equal(t, map[string]cty.Value{
		"module.child.example.counted[0]":   cty.NumberIntVal(0),
		"module.child.example.counted[1]":   cty.NumberIntVal(1),
		`module.child.example.keyed["new"]`: cty.StringVal("new"),
		"module.child.data.example.source":  cty.StringVal("override"),
	}, values)
}

func TestResourceOverrideJSON(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `
resource "example" "this" {
  value = "base"
  lifecycle {
    prevent_destroy       = true
    create_before_destroy = false
  }
}
`,
		"override.tf.json": `{"resource":{"example":{"this":{
  "value":"json","lifecycle":{"create_before_destroy":true}
}}}}`,
	})
	resources, _, _, err := New().EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	r := resources[0]
	require.Equal(t, filepath.Join(dir, "main.tf"), r.DefinedIn)
	require.Equal(t, filepath.Join(dir, "override.tf.json"), r.Body.Attributes["value"].SrcRange.Filename)
	require.Equal(t, map[string]interface{}{
		"value": "json",
		"lifecycle": map[string]interface{}{
			"create_before_destroy": true,
			"prevent_destroy":       true,
		},
	}, AttributesToDocument(&r))
}

func TestResourceOverrideDynamicBlocks(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `
resource "example" "this" {
  option { name = "original" }
  dynamic "option" {
    for_each = ["also-original"]
    content { name = option.value }
  }
  dynamic "retained" {
    for_each = ["retained"]
    content { name = retained.value }
  }
}
`,
		"override.tf.json": `{"resource":{"example":{"this":{
  "dynamic":{"option":{"for_each":["effective"],"content":{"name":"${option.value}"}}}
}}}}`,
	})
	resources, _, _, err := New().EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	doc := AttributesToDocument(&resources[0])
	require.Equal(t, map[string]interface{}{"name": "effective"}, doc["option"])
	require.Equal(t, map[string]interface{}{"name": "retained"}, doc["retained"])
}

func TestResourceOverrideRequiresDeclarationInModule(t *testing.T) {
	root := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `resource "example" "this" { value = "declared" }`,
	})
	env := writeModule(t, root, "environments/dev", map[string]string{
		"settings_override.tf": `resource "example" "this" { value = "override" }`,
	})
	e := New()
	resources, _, _, err := e.EvaluateModule(t.Context(), env, nil)
	require.NoError(t, err)
	require.Empty(t, resources)
	resources, _, _, err = e.EvaluateModule(t.Context(), root, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, cty.StringVal("declared"), resources[0].Attributes["value"])
}
