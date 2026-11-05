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
)

func TestTryReadingComputedAttributeIsUnknown(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
resource "null_resource" "src" {
  count    = 2
  triggers = { i = tostring(count.index) }
}
resource "null_resource" "reader" {
  triggers = {
    computed  = try(null_resource.src[0].id, "none")
    missing   = try(null_resource.src[5].id, "none")
    undefined = try(null_resource.nope.id, "none")
    absent    = try(null_resource.src[0].triggers.acl, "public-read")
    can       = can(null_resource.src[1].id)
    mod       = module.child.out
    nomod     = module.empty.out
  }
}
module "child" {
  source = "./child"
}
module "empty" {
  source = "./child"
  make   = 0
}
`})
	writeModule(t, dir, "child", map[string]string{"main.tf": `
variable "make" {
  default = 1
}
resource "null_resource" "inner" {
  count = var.make
}
output "out" {
  value = try(null_resource.inner[0].id, "none")
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	r := findResource(t, resources, "null_resource", "reader")
	require.Equal(t, map[string]interface{}{"triggers": map[string]interface{}{
		"computed": true, "can": true, "mod": true,
	}}, Unknowns(&r, AttributesToDocument(&r)))
	triggers := r.Attributes["triggers"].AsValueMap()
	for _, name := range []string{"missing", "undefined", "nomod"} {
		require.Equal(t, "none", triggers[name].AsString(), name)
	}
	require.Equal(t, "public-read", triggers["absent"].AsString(),
		"a missing key of a configured map is an error, not a computed attribute")
}

func TestUnknownShapeIsTheSameForEveryInstance(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
resource "null_resource" "src" {
  count    = 2
  triggers = { i = tostring(count.index) }
}
resource "null_resource" "reader" {
  count    = 2
  triggers = {
    direct = null_resource.src[count.index].id
    fixed  = null_resource.src[1].id
    known  = "k"
  }
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	for _, name := range []string{"reader[0]", "reader[1]"} {
		r := findResource(t, resources, "null_resource", name)
		require.Equal(t, map[string]interface{}{"triggers": map[string]interface{}{"direct": true, "fixed": true}},
			Unknowns(&r, AttributesToDocument(&r)), name)
		require.Equal(t, "k", r.Attributes["triggers"].GetAttr("known").AsString(), name)
	}
}

func TestUnknownsLeaveMetaArgumentsOut(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
resource "null_resource" "src" {
  triggers = { i = "x" }
}
resource "null_resource" "reader" {
  depends_on = [null_resource.src]
  provider   = null.alt
  triggers   = { a = null_resource.src.id }
  lifecycle {
    ignore_changes       = [triggers]
    replace_triggered_by = [null_resource.src.id]
  }
  provisioner "local-exec" {
    command = null_resource.src.id
  }
  connection {
    host = null_resource.src.id
  }
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	r := findResource(t, resources, "null_resource", "reader")
	require.Equal(t, map[string]interface{}{"triggers": map[string]interface{}{"a": true}},
		Unknowns(&r, AttributesToDocument(&r)))
}
