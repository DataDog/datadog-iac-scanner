/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func bucketModule(t *testing.T, root string) string {
	t.Helper()
	return writeModule(t, root, "bucket", map[string]string{
		"main.tf": `
variable "name" {}
variable "encrypt" { default = true }
resource "aws_s3_bucket" "this" {
  bucket    = var.name
  encrypted = var.encrypt
}
output "name" { value = aws_s3_bucket.this.bucket }
`,
	})
}

func TestEvaluateModule_ExpandsModuleForEach(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "buckets" {
  source   = "../bucket"
  for_each = {
    prod = { encrypt = true }
    dev  = { encrypt = false }
  }
  name    = "bucket-${each.key}"
  encrypt = each.value.encrypt
}

module "logs" {
  source = "../bucket"
  name   = "${module.buckets["prod"].name}-logs"
}
`,
	})

	e := New()
	e.SetTrackModuleInstances(true)
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	byAddr := resourcesByAddress(resources)
	prod, ok := byAddr[`module.buckets["prod"]/aws_s3_bucket.this`]
	require.True(t, ok, "instances are addressed by their for_each key: %v", byAddr)
	requireString(t, prod.Attributes, "bucket", "bucket-prod")
	require.True(t, prod.Attributes["encrypted"].True())

	dev := byAddr[`module.buckets["dev"]/aws_s3_bucket.this`]
	requireString(t, dev.Attributes, "bucket", "bucket-dev")
	require.True(t, dev.Attributes["encrypted"].False(), "each.value must reach the instance's inputs")

	requireString(t, byAddr["module.logs/aws_s3_bucket.this"].Attributes, "bucket", "bucket-prod-logs")

	addresses := make([]string, 0)
	for _, instance := range e.TakeModuleInstances() {
		addresses = append(addresses, instance.ModuleAddress)
	}
	sort.Strings(addresses)
	require.Equal(t, []string{`module.buckets["dev"]`, `module.buckets["prod"]`, "module.logs"}, addresses)
}

func TestEvaluateModule_ExpandsModuleCount(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
variable "enabled" { default = false }

module "replicas" {
  source = "../bucket"
  count  = 2
  name   = "replica-${count.index}"
}

module "disabled" {
  source = "../bucket"
  count  = var.enabled ? 1 : 0
  name   = "never"
}

output "second" { value = module.replicas[1].name }
output "replica_count" { value = length(module.replicas) }
`,
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	byAddr := resourcesByAddress(resources)
	require.Len(t, byAddr, 2)
	requireString(t, byAddr["module.replicas[0]/aws_s3_bucket.this"].Attributes, "bucket", "replica-0")
	requireString(t, byAddr["module.replicas[1]/aws_s3_bucket.this"].Attributes, "bucket", "replica-1")

	require.True(t, outputs["second"].RawEquals(cty.StringVal("replica-1")), "second = %#v", outputs["second"])
	require.True(t, outputs["replica_count"].RawEquals(cty.NumberIntVal(2)), "replica_count = %#v", outputs["replica_count"])
}

func TestEvaluateModule_UnknownModuleExpansionEvaluatesOnce(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
variable "names" {}

module "buckets" {
  source   = "../bucket"
  for_each = var.names
  name     = each.key
  encrypt  = false
}

output "names" { value = module.buckets }
`,
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	require.Len(t, resources, 1)
	require.Equal(t, "module.buckets", resources[0].ModuleAddress)
	require.False(t, resources[0].Attributes["bucket"].IsKnown())
	require.True(t, resources[0].Attributes["encrypted"].False())
	require.False(t, outputs["names"].IsKnown(), "outputs of an unexpanded call are unknown")
}

// largeExpansion is past every cap module evaluation used to apply: 50
// instances per block and a 512-instance shape for padded references.
const largeExpansion = 600

func TestEvaluateModule_LargeModuleCountExpandsEveryInstance(t *testing.T) {
	root := t.TempDir()
	bucket := bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": fmt.Sprintf(`
module "many" {
  source = "../bucket"
  count  = %d
  name   = "b-${count.index}"
}

output "n" { value = length(module.many) }
output "last" { value = module.many[%d].name }
output "first" { value = module.many[0].name }
`, largeExpansion, largeExpansion-1),
	})

	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	e := New()
	resources, outputs, _, err := e.EvaluateModule(ctx, stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, largeExpansion)
	for i := range resources {
		require.Equal(t, fmt.Sprintf("module.many[%d]", i), resources[i].ModuleAddress)
		require.True(t, resources[i].Attributes["bucket"].RawEquals(cty.StringVal(fmt.Sprintf("b-%d", i))))
	}
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(largeExpansion)), "length = %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("b-0")))
	require.True(t, outputs["last"].RawEquals(cty.StringVal(fmt.Sprintf("b-%d", largeExpansion-1))))
	require.True(t, e.Report().Complete(), "%v", e.Report().Incomplete())
	require.NotContains(t, logs.String(), "truncat")

	abs, err := filepath.Abs(bucket)
	require.NoError(t, err)
	require.NotContains(t, e.NotEvaluatedDirs(), abs, "a complete expansion leaves nothing to scan as written")
}

func forEachEntries(n int) (entries string, last string) {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf(`    "k%04d" = true`, i)
	}
	return strings.Join(lines, "\n"), fmt.Sprintf("k%04d", n-1)
}

func TestEvaluateModule_LargeModuleForEachExpandsEveryKey(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	entries, last := forEachEntries(largeExpansion)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": fmt.Sprintf(`
module "many" {
  source   = "../bucket"
  for_each = {
%s
  }
  name = each.key
}

output "n" { value = length(module.many) }
output "last" { value = module.many["%s"].name }
output "first" { value = module.many["k0000"].name }
`, entries, last),
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, largeExpansion)
	seen := map[string]bool{}
	for i := range resources {
		seen[resources[i].ModuleAddress] = true
	}
	require.Len(t, seen, largeExpansion, "every key is its own instance address")
	require.True(t, seen[`module.many["`+last+`"]`])
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(largeExpansion)), "length = %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("k0000")))
	require.True(t, outputs["last"].RawEquals(cty.StringVal(last)))
}

func TestEvaluateModule_LargeResourceCountExpandsEveryInstance(t *testing.T) {
	root := t.TempDir()
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "replica" {
  count  = %d
  bucket = "b-${count.index}"
}

output "n" { value = length(aws_s3_bucket.replica) }
output "last" { value = aws_s3_bucket.replica[%d].bucket }
output "first" { value = aws_s3_bucket.replica[0].bucket }
`, largeExpansion, largeExpansion-1),
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, largeExpansion)
	for i := range resources {
		require.Equal(t, fmt.Sprintf("replica[%d]", i), resources[i].Name)
	}
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(largeExpansion)), "length = %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("b-0")))
	require.True(t, outputs["last"].RawEquals(cty.StringVal(fmt.Sprintf("b-%d", largeExpansion-1))))
}

func TestEvaluateModule_LargeResourceForEachExpandsEveryKey(t *testing.T) {
	root := t.TempDir()
	entries, last := forEachEntries(largeExpansion)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "replica" {
  for_each = {
%s
  }
  bucket = each.key
}

output "n" { value = length(aws_s3_bucket.replica) }
output "last" { value = aws_s3_bucket.replica["%s"].bucket }
output "first" { value = aws_s3_bucket.replica["k0000"].bucket }
`, entries, last),
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, largeExpansion)
	require.Equal(t, `replica["`+last+`"]`, resources[largeExpansion-1].Name)
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(largeExpansion)), "length = %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("k0000")))
	require.True(t, outputs["last"].RawEquals(cty.StringVal(last)))
}

func TestModuleInstances_ForEachYieldsEveryKeyInOrder(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte(`{ b = 2, a = 1 }`), "x.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	block := &hclsyntax.Block{Type: "module", Body: &hclsyntax.Body{
		Attributes: hclsyntax.Attributes{"for_each": {Name: "for_each", Expr: expr}},
	}}
	plan := moduleInstances(block, &hcl.EvalContext{})
	require.Equal(t, expansionForEach, plan.mode)
	var keys, outs []cty.Value
	for instance := range plan.all {
		keys = append(keys, instance.key)
		key := instance.ctx.Variables["each"].GetAttr("key")
		outs = append(outs, cty.ObjectVal(map[string]cty.Value{"name": key}))
	}
	require.Equal(t, []cty.Value{cty.StringVal("a"), cty.StringVal("b")}, keys)
	got, ok := moduleOutputsValue(&plan, keys, outs)
	require.True(t, ok)
	require.True(t, got.IsWhollyKnown())
	require.True(t, got.GetAttr("a").GetAttr("name").RawEquals(cty.StringVal("a")))
	require.True(t, got.GetAttr("b").GetAttr("name").RawEquals(cty.StringVal("b")))
}

func TestEvaluateModule_InstanceAttributesKeepIterationValuesWithSharedOnes(t *testing.T) {
	root := t.TempDir()
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
locals {
  tags = merge({ team = "a" }, { env = "prod" })
}
resource "aws_s3_bucket" "b" {
  for_each = toset(["x", "y", "z"])
  bucket   = "b-${each.key}"
  tags     = local.tags
  versioning {
    enabled = each.key == "y"
    shared  = local.tags.team
  }
}
resource "aws_s3_bucket" "c" {
  count  = 3
  bucket = "c-${count.index}"
  tags   = local.tags
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 6)
	byName := map[string]ResolvedResource{}
	for _, r := range resources {
		byName[r.Name] = r
	}
	for _, key := range []string{"x", "y", "z"} {
		r := byName[fmt.Sprintf("b[%q]", key)]
		require.True(t, r.Attributes["bucket"].RawEquals(cty.StringVal("b-"+key)))
		require.True(t, r.Attributes["tags"].GetAttr("team").RawEquals(cty.StringVal("a")))
		v := r.Attributes["versioning"]
		require.Equal(t, key == "y", v.GetAttr("enabled").True(), key)
		require.True(t, v.GetAttr("shared").RawEquals(cty.StringVal("a")))
	}
	for i := 0; i < 3; i++ {
		r := byName[fmt.Sprintf("c[%d]", i)]
		require.True(t, r.Attributes["bucket"].RawEquals(cty.StringVal(fmt.Sprintf("c-%d", i))))
		require.True(t, r.Attributes["tags"].GetAttr("env").RawEquals(cty.StringVal("prod")))
	}
}
