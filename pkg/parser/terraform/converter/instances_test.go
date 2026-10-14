/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package converter

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

func convertLayers(t *testing.T, input string, vars VariableMap) []model.Document {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(input), "main.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors())
	layers, err := ConvertAll(context.Background(), file, vars, Options{})
	require.NoError(t, err)
	return layers
}

// resourceOf returns the block of a layer, or nil when the layer has none.
func resourceOf(layer model.Document, kind, typ, name string) model.Document {
	byType, _ := layer[kind].(model.Document)
	byName, _ := byType[typ].(model.Document)
	block, _ := byName[name].(model.Document)
	return block
}

func stringAttr(t *testing.T, block model.Document, key string) string {
	t.Helper()
	switch v := block[key].(type) {
	case string:
		return v
	case ctyjson.SimpleJSONValue:
		return v.AsString()
	}
	require.Failf(t, "attribute is not a string", "%s: %#v", key, block[key])
	return ""
}

func TestForEachExpandsIntoOneDocumentPerDistinctInstance(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_s3_bucket" "b" {
  for_each = var.buckets
  bucket   = each.key
  versioning {
    enabled = each.value.versioned
  }
}
resource "aws_s3_bucket" "static" {
  bucket = "static"
}
`, VariableMap{"var": cty.ObjectVal(map[string]cty.Value{
		"buckets": cty.MapVal(map[string]cty.Value{
			"a": cty.ObjectVal(map[string]cty.Value{"versioned": cty.False}),
			"b": cty.ObjectVal(map[string]cty.Value{"versioned": cty.True}),
		}),
	})})

	require.Len(t, layers, 2)
	first := resourceOf(layers[0], "resource", "aws_s3_bucket", "b")
	second := resourceOf(layers[1], "resource", "aws_s3_bucket", "b")
	require.Equal(t, "a", stringAttr(t, first, "bucket"))
	require.Equal(t, "b", stringAttr(t, second, "bucket"))
	require.False(t, first["versioning"].(model.Document)["enabled"].(ctyjson.SimpleJSONValue).True())
	require.True(t, second["versioning"].(model.Document)["enabled"].(ctyjson.SimpleJSONValue).True())

	static := resourceOf(layers[0], "resource", "aws_s3_bucket", "static")
	require.NotNil(t, static)
	require.Equal(t, static, resourceOf(layers[1], "resource", "aws_s3_bucket", "static"),
		"a later document is the whole file, so rules that look across blocks see the same configuration")
}

func TestCountExpandsOnlyWhenInstancesDiffer(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_instance" "indexed" {
  count = 3
  tags  = { name = "web-${count.index}" }
}
resource "aws_instance" "same" {
  count = 3
  ami   = "ami-1"
}
`, nil)

	require.Len(t, layers, 3)
	for i, layer := range layers {
		indexed := resourceOf(layer, "resource", "aws_instance", "indexed")
		require.Equal(t, fmt.Sprintf("web-%d", i), stringAttr(t, indexed["tags"].(model.Document), "name"))
	}
	same := resourceOf(layers[0], "resource", "aws_instance", "same")
	require.NotNil(t, same)
	for _, layer := range layers[1:] {
		require.Equal(t, same, resourceOf(layer, "resource", "aws_instance", "same"),
			"instances that read the same are one instance, in every document")
	}
}

func TestBlockWithFewerInstancesKeepsItsFirstInstanceInLaterDocuments(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_instance" "three" {
  count = 3
  name  = "t-${count.index}"
}
resource "aws_instance" "two" {
  count = 2
  name  = "w-${count.index}"
}
`, nil)
	require.Len(t, layers, 3)
	require.Equal(t, "w-0", stringAttr(t, resourceOf(layers[0], "resource", "aws_instance", "two"), "name"))
	require.Equal(t, "w-1", stringAttr(t, resourceOf(layers[1], "resource", "aws_instance", "two"), "name"))
	require.Equal(t, "w-0", stringAttr(t, resourceOf(layers[2], "resource", "aws_instance", "two"), "name"))
	require.Equal(t, "t-2", stringAttr(t, resourceOf(layers[2], "resource", "aws_instance", "three"), "name"))
}

func TestForEachOverASetBindsKeyAndValueToTheElement(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_iam_user" "u" {
  for_each = toset(["x", "y"])
  name     = "${each.key}-${each.value}"
}
`, nil)
	require.Len(t, layers, 2)
	require.Equal(t, "x-x", stringAttr(t, resourceOf(layers[0], "resource", "aws_iam_user", "u"), "name"))
	require.Equal(t, "y-y", stringAttr(t, resourceOf(layers[1], "resource", "aws_iam_user", "u"), "name"))
}

func TestDataBlocksExpandLikeResources(t *testing.T) {
	layers := convertLayers(t, `
data "aws_ami" "a" {
  count  = 2
  owners = ["${count.index}"]
}
`, nil)
	require.Len(t, layers, 2)
	require.NotNil(t, resourceOf(layers[1], "data", "aws_ami", "a"))
}

func TestBlocksWithNoInstanceAreDropped(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_s3_bucket" "zero" {
  count = 0
}
resource "aws_s3_bucket" "empty" {
  for_each = {}
}
resource "aws_s3_bucket" "emptyset" {
  for_each = toset([])
}
module "none" {
  source   = "./m"
  for_each = {}
}
resource "aws_s3_bucket" "kept" {
  bucket = "kept"
}
`, nil)
	require.Len(t, layers, 1)
	for _, name := range []string{"zero", "empty", "emptyset"} {
		require.Nil(t, resourceOf(layers[0], "resource", "aws_s3_bucket", name), name)
	}
	require.NotContains(t, layers[0], "module")
	require.NotNil(t, resourceOf(layers[0], "resource", "aws_s3_bucket", "kept"))
}

func TestUnresolvedExpansionIsKeptAsWritten(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_s3_bucket" "unknown_count" {
  count  = var.n
  bucket = "b-${count.index}"
}
resource "aws_s3_bucket" "unknown_each" {
  for_each = var.m
  bucket   = each.key
}
`, VariableMap{"var": cty.ObjectVal(map[string]cty.Value{
		"n": cty.UnknownVal(cty.Number),
		"m": cty.UnknownVal(cty.Map(cty.String)),
	})})
	require.Len(t, layers, 1)
	require.Equal(t, "b-${count.index}", stringAttr(t, resourceOf(layers[0], "resource", "aws_s3_bucket", "unknown_count"), "bucket"))
	require.Equal(t, "${each.key}", stringAttr(t, resourceOf(layers[0], "resource", "aws_s3_bucket", "unknown_each"), "bucket"))
}

func TestCountOrForEachBeyondTheCapKeepsTheFirstInstancesAndTheBlockAsWritten(t *testing.T) {
	n := instances.MaxPerBlock + 5
	layers := convertLayers(t, fmt.Sprintf(`
resource "aws_instance" "many" {
  count = %d
  name  = "i-${count.index}"
}
`, n), nil)
	require.Len(t, layers, instances.MaxPerBlock+1)
	require.Equal(t, "i-0", stringAttr(t, resourceOf(layers[0], "resource", "aws_instance", "many"), "name"))
	last := resourceOf(layers[instances.MaxPerBlock], "resource", "aws_instance", "many")
	require.Equal(t, "i-${count.index}", stringAttr(t, last, "name"))
}

func TestInstancesBeyondTheFileBudgetStayAsWritten(t *testing.T) {
	var src strings.Builder
	blocks := instances.MaxPerFile/(instances.MaxPerBlock-1) + 2
	for i := 0; i < blocks; i++ {
		fmt.Fprintf(&src, "resource \"aws_instance\" \"r%d\" {\n  count = %d\n  name = \"i-${count.index}\"\n}\n", i, instances.MaxPerBlock)
	}
	layers := convertLayers(t, src.String(), nil)
	last := resourceOf(layers[0], "resource", "aws_instance", fmt.Sprintf("r%d", blocks-1))
	require.Equal(t, "i-${count.index}", stringAttr(t, last, "name"), "a block that no longer fits is read as written")
	first := resourceOf(layers[0], "resource", "aws_instance", "r0")
	require.Equal(t, "i-0", stringAttr(t, first, "name"))
}

func TestCountAttributeOfNestedBlockDoesNotDropTheBlock(t *testing.T) {
	layers := convertLayers(t, `
resource "google_container_node_pool" "np" {
  guest_accelerator {
    type  = "nvidia"
    count = 0
  }
}
locals {
  count = 0
}
`, nil)
	require.Len(t, layers, 1)
	np := resourceOf(layers[0], "resource", "google_container_node_pool", "np")
	require.Contains(t, np, "guest_accelerator")
	require.Contains(t, layers[0], "locals")
}

func TestIterationVariablesDoNotStayBoundAfterTheBlock(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_instance" "a" {
  count = 2
  name  = "a-${count.index}"
}
resource "aws_instance" "after" {
  name = "${count.index}"
}
`, nil)
	after := resourceOf(layers[0], "resource", "aws_instance", "after")
	require.Equal(t, "${count.index}", stringAttr(t, after, "name"))
}

func TestInstancesRunDynamicBlocksWithTheirOwnBudget(t *testing.T) {
	layers := convertLayers(t, `
resource "aws_security_group" "sg" {
  count = 2
  dynamic "ingress" {
    for_each = [count.index, 10]
    content {
      from_port = ingress.value
    }
  }
}
`, nil)
	require.Len(t, layers, 2)
	for _, layer := range layers {
		sg := resourceOf(layer, "resource", "aws_security_group", "sg")
		require.Len(t, sg["ingress"], 2)
	}
}
