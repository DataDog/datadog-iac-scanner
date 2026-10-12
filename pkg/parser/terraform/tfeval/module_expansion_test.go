/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
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

func TestEvaluateModule_TruncatedModuleCountKeepsModuleScanned(t *testing.T) {
	root := t.TempDir()
	bucket := bucketModule(t, root)
	requested := maxCountExpansion + 2
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
`, requested, requested-1),
	})

	e := New()
	resources, outputs, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, maxCountExpansion)
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(int64(requested))), "length must keep the full requested size, got %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("b-0")), "expanded instance outputs stay known")
	require.False(t, outputs["last"].IsKnown(), "omitted instance outputs must be unknown, got %#v", outputs["last"])

	abs, err := filepath.Abs(bucket)
	require.NoError(t, err)
	require.Contains(t, e.NotEvaluatedDirs(), abs)
}

func TestEvaluateModule_TruncatedModuleForEachPadsMissingKeys(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	requested := maxCountExpansion + 2
	entries := make([]string, requested)
	for i := range entries {
		entries[i] = fmt.Sprintf(`    "k%02d" = true`, i)
	}
	missing := fmt.Sprintf("k%02d", requested-1)
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
output "missing" { value = module.many["%s"].name }
output "first" { value = module.many["k00"].name }
`, strings.Join(entries, "\n"), missing),
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, maxCountExpansion)
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(int64(requested))), "length = %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("k00")))
	require.False(t, outputs["missing"].IsKnown(), "omitted for_each key must be unknown, got %#v", outputs["missing"])
}

func TestEvaluateModule_TruncatedResourceCountPadsRefs(t *testing.T) {
	root := t.TempDir()
	requested := maxCountExpansion + 2
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "replica" {
  count  = %d
  bucket = "b-${count.index}"
}

output "n" { value = length(aws_s3_bucket.replica) }
output "last" { value = aws_s3_bucket.replica[%d].bucket }
output "first" { value = aws_s3_bucket.replica[0].bucket }
`, requested, requested-1),
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, maxCountExpansion)
	require.True(t, resources[0].ExpansionTruncated)
	require.Equal(t, requested, resources[0].ExpansionTotal)
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(int64(requested))), "length = %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("b-0")))
	require.False(t, outputs["last"].IsKnown(), "omitted resource index must be unknown, got %#v", outputs["last"])
}

func TestEvaluateModule_TruncatedResourceForEachPadsRefs(t *testing.T) {
	root := t.TempDir()
	requested := maxCountExpansion + 2
	entries := make([]string, requested)
	for i := range entries {
		entries[i] = fmt.Sprintf(`    "k%02d" = true`, i)
	}
	missing := fmt.Sprintf("k%02d", requested-1)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "replica" {
  for_each = {
%s
  }
  bucket = each.key
}

output "n" { value = length(aws_s3_bucket.replica) }
output "missing" { value = aws_s3_bucket.replica["%s"].bucket }
output "first" { value = aws_s3_bucket.replica["k00"].bucket }
`, strings.Join(entries, "\n"), missing),
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, maxCountExpansion)
	require.True(t, resources[0].ExpansionTruncated)
	require.Len(t, resources[0].ExpansionKeys, requested)
	require.True(t, outputs["n"].RawEquals(cty.NumberIntVal(int64(requested))), "length = %#v", outputs["n"])
	require.True(t, outputs["first"].RawEquals(cty.StringVal("k00")))
	require.False(t, outputs["missing"].IsKnown(), "omitted for_each key must be unknown, got %#v", outputs["missing"])
}

func TestModuleOutputsValue_HugeTruncatedCountBecomesUnknown(t *testing.T) {
	outs := make([]cty.Value, maxCountExpansion)
	for i := range outs {
		outs[i] = cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("x")})
	}
	got, ok := moduleOutputsValue(moduleExpansionPlan{
		mode:      expansionCount,
		requested: maxExpansionShape + 1,
		instances: make([]moduleInstance, maxCountExpansion),
	}, outs)
	require.True(t, ok)
	require.False(t, got.IsKnown(), "shapes beyond maxExpansionShape must not materialize")
}

func TestForEachInstances_SmallKeepsConcreteOutputsWithoutFullKeyList(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte(`{ a = 1, b = 2 }`), "x.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	plan := forEachInstances(&hclsyntax.Attribute{Expr: expr}, &hcl.EvalContext{})
	require.Equal(t, expansionForEach, plan.mode)
	require.Equal(t, 2, plan.requested)
	require.Len(t, plan.instances, 2)
	require.Nil(t, plan.forEachKeys, "small for_each should not materialize a padding key list")

	outs := []cty.Value{
		cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("a")}),
		cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("b")}),
	}
	got, ok := moduleOutputsValue(plan, outs)
	require.True(t, ok)
	require.True(t, got.IsWhollyKnown())
	require.True(t, got.GetAttr("a").GetAttr("name").RawEquals(cty.StringVal("a")))
	require.True(t, got.GetAttr("b").GetAttr("name").RawEquals(cty.StringVal("b")))
}

func TestForEachInstances_HugeTruncationDoesNotKeepKeys(t *testing.T) {
	n := maxExpansionShape + 1
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"k%04d"=true`, i)
	}
	b.WriteByte('}')
	expr, diags := hclsyntax.ParseExpression([]byte(b.String()), "x.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	plan := forEachInstances(&hclsyntax.Attribute{Expr: expr}, &hcl.EvalContext{})
	require.True(t, plan.truncated())
	require.Equal(t, n, plan.requested)
	require.Len(t, plan.instances, maxCountExpansion)
	require.Nil(t, plan.forEachKeys)
	got, ok := moduleOutputsValue(plan, make([]cty.Value, len(plan.instances)))
	require.True(t, ok)
	require.False(t, got.IsKnown())
}
