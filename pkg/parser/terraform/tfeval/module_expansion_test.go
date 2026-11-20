/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"runtime"
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
	evaluation, err := e.EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
	require.NoError(t, err)

	byAddr := resourcesByAddress(resources)
	canonicalAddresses := make(map[string]string, len(resources))
	for _, resource := range resources {
		if strings.HasPrefix(resource.ModuleAddress, "module.buckets[") {
			require.NotEmpty(t, resource.CallChain)
			require.NotEqual(t, cty.NilVal, resource.CallChain[0].InstanceKey)
		}
		address, ok := resource.TerraformAddress()
		require.True(t, ok)
		canonicalAddresses[resource.ModuleAddress] = address
	}
	require.Equal(t, map[string]string{
		`module.buckets["prod"]`: `module.buckets["prod"].aws_s3_bucket.this`,
		`module.buckets["dev"]`:  `module.buckets["dev"].aws_s3_bucket.this`,
		"module.logs":            "module.logs.aws_s3_bucket.this",
	}, canonicalAddresses)
	prod, ok := byAddr[`module.buckets["prod"]/aws_s3_bucket.this`]
	require.True(t, ok, "instances are addressed by their for_each key: %v", byAddr)
	requireString(t, prod.Attributes, "bucket", "bucket-prod")
	require.True(t, prod.Attributes["encrypted"].True())

	dev := byAddr[`module.buckets["dev"]/aws_s3_bucket.this`]
	requireString(t, dev.Attributes, "bucket", "bucket-dev")
	require.True(t, dev.Attributes["encrypted"].False(), "each.value must reach the instance's inputs")

	requireString(t, byAddr["module.logs/aws_s3_bucket.this"].Attributes, "bucket", "bucket-prod-logs")

	addresses := make([]string, 0)
	for _, instance := range evaluation.ModuleInstances {
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

	evaluation, err := New().EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
	outputs := evaluation.Outputs
	require.NoError(t, err)

	byAddr := resourcesByAddress(resources)
	require.Len(t, byAddr, 2)
	requireString(t, byAddr["module.replicas[0]/aws_s3_bucket.this"].Attributes, "bucket", "replica-0")
	requireString(t, byAddr["module.replicas[1]/aws_s3_bucket.this"].Attributes, "bucket", "replica-1")

	require.True(t, outputs["second"].RawEquals(cty.StringVal("replica-1")), "second = %#v", outputs["second"])
	require.True(t, outputs["replica_count"].RawEquals(cty.NumberIntVal(2)), "replica_count = %#v", outputs["replica_count"])
}

func TestResolvedResourceTerraformAddressInstances(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
resource "aws_s3_bucket" "from_module" { bucket = "logs" }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
variable "unknown_items" {}
resource "aws_s3_bucket" "counted" {
  count = 2
  bucket = "count-${count.index}"
}
resource "aws_s3_bucket" "keyed" {
  for_each = { first = "one", second = "two" }
  bucket = each.value
}
resource "aws_s3_bucket" "unexpanded" { bucket = "plain" }
resource "aws_s3_bucket" "unknown" {
  for_each = var.unknown_items
  bucket = each.key
}
module "child" {
  source = "../child"
  count = 2
}
`})
	evaluation, err := New().EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
	require.NoError(t, err)
	addresses := make(map[string]bool, len(resources))
	for _, resource := range resources {
		address, ok := resource.TerraformAddress()
		if ok {
			addresses[address] = true
		}
	}
	require.Equal(t, map[string]bool{
		"aws_s3_bucket.counted[0]":                  true,
		"aws_s3_bucket.counted[1]":                  true,
		`aws_s3_bucket.keyed["first"]`:              true,
		`aws_s3_bucket.keyed["second"]`:             true,
		"aws_s3_bucket.unexpanded":                  true,
		"module.child[0].aws_s3_bucket.from_module": true,
		"module.child[1].aws_s3_bucket.from_module": true,
	}, addresses)
	for _, resource := range resources {
		if resource.Name == "unknown" {
			_, ok := resource.TerraformAddress()
			require.False(t, ok, "unresolved for_each must not claim a concrete instance address")
		}
	}
}

func TestResolvedResourceTerraformAddressQuotesForEachKeysAsHCL(t *testing.T) {
	for _, tc := range []struct{ key, want string }{
		{`quote"slash\`, `aws_s3_bucket.web["quote\"slash\\"]`},
		{"line\nbreak", `aws_s3_bucket.web["line\nbreak"]`},
		{`${literal}`, `aws_s3_bucket.web["$${literal}"]`},
		{`%{literal}`, `aws_s3_bucket.web["%%{literal}"]`},
		{"\x00", `aws_s3_bucket.web["\u0000"]`},
		{"雪", `aws_s3_bucket.web["雪"]`},
	} {
		t.Run(tc.want, func(t *testing.T) {
			resource := makeForEachResource("web", tc.key, cty.StringVal(tc.key), cty.StringVal(tc.key), &hcl.EvalContext{},
				func(name string, _ *hcl.EvalContext) ResolvedResource {
					return ResolvedResource{Type: "aws_s3_bucket", Name: name}
				})
			require.Equal(t, fmt.Sprintf("web[%q]", tc.key), resource.Name, "legacy Name representation stays unchanged")
			got, ok := resource.TerraformAddress()
			require.True(t, ok, "resource name %q", resource.Name)
			require.Equal(t, tc.want, got)
			moduleResource := ResolvedResource{
				Type: "aws_s3_bucket", Name: "web", ModuleAddress: "module.bucket",
				CallChain: []CallSite{{ModuleName: "bucket", InstanceKey: cty.StringVal(tc.key)}},
			}
			moduleGot, ok := moduleResource.TerraformAddress()
			require.True(t, ok)
			resourceSuffix := strings.TrimPrefix(tc.want, "aws_s3_bucket.web")
			require.Equal(t, "module.bucket"+resourceSuffix+".aws_s3_bucket.web", moduleGot)
		})
	}
}

func TestResolvedResourceCanonicalModuleAddressKeepsLegacyAddress(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
resource "aws_s3_bucket" "this" { bucket = "logs" }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "bucket" {
  source = "../child"
  for_each = { "$${literal}" = "same" }
}
`})
	evaluation, err := New().EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
	require.NoError(t, err)
	require.Len(t, resources, 1)
	resource := resources[0]
	require.Equal(t, `module.bucket["${literal}"]`, resource.ModuleAddress,
		"legacy ModuleAddress remains byte-identical")
	canonical, ok := resource.TerraformAddress()
	require.True(t, ok)
	require.Equal(t, `module.bucket["$${literal}"].aws_s3_bucket.this`, canonical)
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

	evaluation, err := New().EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
	outputs := evaluation.Outputs
	require.NoError(t, err)

	require.Len(t, resources, 1)
	require.Equal(t, "module.buckets", resources[0].ModuleAddress)
	_, addressKnown := resources[0].TerraformAddress()
	require.False(t, addressKnown, "an unresolved module key must not become a concrete resource address")
	require.False(t, resources[0].Attributes["bucket"].IsKnown())
	require.True(t, resources[0].Attributes["encrypted"].False())
	require.False(t, outputs["names"].IsKnown(), "outputs of an unexpanded call are unknown")
}

func TestModuleInstances_CanceledContextDoesNotAllocateTheCount(t *testing.T) {
	file, diags := hclsyntax.ParseConfig([]byte("count = 1000000000000000"), "call.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan := moduleInstances(ctx, &hclsyntax.Block{Body: file.Body.(*hclsyntax.Body)}, &hcl.EvalContext{})
	require.Equal(t, expansionUnknown, plan.mode)
	require.Zero(t, plan.Len())
}

func TestForEachInstances_SmallKeepsConcreteOutputsWithoutFullKeyList(t *testing.T) {
	file, diags := hclsyntax.ParseConfig([]byte(`for_each = { a = 1, b = 2 }`), "x.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	plan := moduleInstances(context.Background(), &hclsyntax.Block{Body: file.Body.(*hclsyntax.Body)}, &hcl.EvalContext{})
	require.Equal(t, expansionForEach, plan.mode)
	require.Equal(t, 2, plan.Len())

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

	evaluation, err := New().EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
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

// Pin count conversion, invalid/unknown separation, and
// iteration bindings in child contexts.
func TestModuleInstances_ResolutionSemantics(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		mode         moduleExpansion
		requested    int
		binding      string
		want         cty.Value
	}{
		{"decimal string count", `count = "2"`, expansionCount, 2, "count.index", cty.NumberIntVal(0)},
		{"negative count", `count = -2`, expansionInvalid, 0, "", cty.NilVal},
		{"fractional count", `count = 1.5`, expansionInvalid, 0, "", cty.NilVal},
		{"unknown count", `count = uncertain`, expansionUnknown, 0, "count.index", cty.UnknownVal(cty.Number)},
		{"conflicting expansion", "count = 1\nfor_each = missing", expansionInvalid, 0, "", cty.NilVal},
		{"unknown each", `for_each = unknownmap`, expansionUnknown, 0, "each.key", cty.UnknownVal(cty.String)},
		{"invalid set", `for_each = numbers`, expansionInvalid, 0, "", cty.NilVal},
		{"partially known map", `for_each = values`, expansionForEach, 1, "each.value", cty.UnknownVal(cty.Number)},
		{"marked element", `for_each = marked`, expansionForEach, 1, "each.value", cty.StringVal("secret").Mark("sensitive")},
		{"empty each", `for_each = {}`, expansionForEach, 0, "", cty.NilVal},
		{"no expansion", `source = "./child"`, expansionNone, 1, "", cty.NilVal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte(tt.source), "call.tf", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			parent := &hcl.EvalContext{Variables: map[string]cty.Value{
				"inherited":  cty.StringVal("parent"),
				"uncertain":  cty.UnknownVal(cty.Number),
				"unknownmap": cty.UnknownVal(cty.Map(cty.String)),
				"numbers":    cty.SetVal([]cty.Value{cty.NumberIntVal(1)}),
				"values":     cty.MapVal(map[string]cty.Value{"a": cty.UnknownVal(cty.Number)}),
				"marked":     cty.MapVal(map[string]cty.Value{"a": cty.StringVal("secret").Mark("sensitive")}),
			}}
			plan := moduleInstances(context.Background(), &hclsyntax.Block{Body: file.Body.(*hclsyntax.Body)}, parent)
			var first moduleInstance
			for instance := range plan.Instances() {
				first = instance
				break
			}
			require.Equal(t, tt.mode, plan.mode)
			if tt.mode == expansionUnknown {
				require.Equal(t, 1, plan.Len())
				require.Equal(t, cty.NilVal, first.key)
			} else {
				require.Equal(t, tt.requested, plan.Len())
			}
			if tt.binding != "" {
				expr, diags := hclsyntax.ParseExpression([]byte(tt.binding), "binding.tf", hcl.InitialPos)
				require.False(t, diags.HasErrors(), diags.Error())
				got, diags := expr.Value(first.ctx)
				require.False(t, diags.HasErrors(), diags.Error())
				require.True(t, tt.want.RawEquals(got), "%#v", got)
				require.Same(t, parent, first.ctx.Parent())
				require.Equal(t, cty.StringVal("parent"), parent.Variables["inherited"])
				require.NotContains(t, parent.Variables, "count")
				require.NotContains(t, parent.Variables, "each")
			}
			if tt.mode == expansionNone {
				require.Same(t, parent, first.ctx)
			}
		})
	}
}

// A call that cannot be evaluated is skipped without building its instances:
// an unresolvable source before its count, a missing directory after its first
// instance, which every other instance would fail the same way.
func TestEvaluateModule_UnavailableModuleDoesNotBuildItsInstances(t *testing.T) {
	for name, source := range map[string]string{
		"unresolvable source": "git::https://example.invalid/missing.git",
		"missing directory":   "./missing",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeModule(t, t.TempDir(), "root", map[string]string{"main.tf": `
module "m" {
  source = "` + source + `"
  count  = 100000
  name   = "x-${count.index}"
}
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`})
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			evaluation, err := New().EvaluateModule(context.Background(), dir, nil)
			resources := evaluation.Resources
			runtime.ReadMemStats(&after)
			require.NoError(t, err)
			require.Len(t, resources, 1)
			require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(32<<20))
		})
	}
}

// Expansion validity and presence are independent of the values in an instance.
// Exercise the same semantics for resources, data and module occurrences,
// including cached results with no surviving instance to carry a diagnostic.
func TestEvaluateModule_ExpansionOutcomes(t *testing.T) {
	for _, kind := range []string{"resource", "data", "module"} {
		t.Run(kind, func(t *testing.T) {
			for _, test := range []struct {
				name, meta         string
				instances          int
				invalid, uncertain bool
			}{
				{"count zero", `count=0`, 0, false, false},
				{"count positive", `count=2`, 2, false, false},
				{"count converted string", `count="2"`, 2, false, false},
				{"negative count", `count=-1`, 0, true, false},
				{"fractional count", `count=1.5`, 0, true, false},
				{"null count", `count=null`, 0, true, false},
				{"failed count", `count=tonumber("invalid")`, 0, true, false},
				{"unknown count", `count=var.number`, 1, false, true},
				{"empty each", `for_each={}`, 0, false, false},
				{"known keys unknown values", `for_each={a=var.input}`, 1, false, false},
				{"unknown keys", `for_each=var.keys`, 1, false, true},
				{"unknown set member", `for_each=toset([var.input])`, 1, false, true},
				{"invalid each sequence", `for_each=["a"]`, 0, true, false},
				{"null each", `for_each=null`, 0, true, false},
				{"invalid each set", `for_each=toset([1])`, 0, true, false},
				{"conflicting expansion", "count=0\nfor_each={}", 0, true, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					base := t.TempDir()
					writeModule(t, base, "child", map[string]string{"main.tf": `resource "test_resource" "target" {value="known"}`})
					declaration := fmt.Sprintf(`%s "test_resource" "target" {
%s
value="known"
}`, kind, test.meta)
					if kind == "module" {
						declaration = fmt.Sprintf(`module "target" {
source="../child"
%s
}`, test.meta)
					}
					source := `variable "number" {type=number}
variable "input" {type=string}
variable "keys" {type=map(string)}
resource "test_resource" "independent" {value="known"}
` + declaration
					dir := writeModule(t, base, "root", map[string]string{"main.tf": source})
					evaluator := New()
					for range 2 {
						evaluation, err := evaluator.EvaluateModule(context.Background(), dir, nil)
						require.NoError(t, err)
						require.Len(t, evaluation.Resources, 1+test.instances)
						require.Equal(t, test.invalid, len(evaluation.Diagnostics()) > 0)
						require.Equal(t, test.invalid, evaluation.PolicyUnit(nil).Failure() != nil)
						for _, resource := range evaluation.Resources {
							requireString(t, resource.Attributes, "value", "known")
							if resource.Name == "independent" {
								continue
							}
							uncertain := resource.InstanceKey != cty.NilVal && !resource.InstanceKey.IsKnown()
							for _, hop := range resource.CallChain {
								uncertain = uncertain || (hop.InstanceKey != cty.NilVal && !hop.InstanceKey.IsKnown())
							}
							require.Equal(t, test.uncertain, uncertain)
						}
					}
				})
			}
		})
	}
}

func TestEvaluateModule_ExpansionInputTransitions(t *testing.T) {
	for _, kind := range []string{"resource", "data", "module"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			writeModule(t, base, "child", map[string]string{"main.tf": `resource "test_resource" "child" {value="known"}`})
			declaration := fmt.Sprintf(`%s "test_resource" "target" {
count=var.n
value="known"
}`, kind)
			if kind == "module" {
				declaration = `module "target" {
source="../child"
count=var.n
}`
			}
			dir := writeModule(t, base, "root", map[string]string{"main.tf": `variable "n" {type=number}
resource "test_resource" "independent" {value="known"}
` + declaration})
			evaluator := New()
			for _, test := range []struct {
				input     cty.Value
				instances int
				failed    bool
			}{
				{cty.NullVal(cty.Number), 0, true},
				{cty.NumberIntVal(0), 0, false},
				{cty.NumberIntVal(2), 2, false},
				{cty.UnknownVal(cty.Number), 1, false},
				{cty.NullVal(cty.Number), 0, true},
			} {
				evaluation, err := evaluator.EvaluateModule(context.Background(), dir, map[string]cty.Value{"n": test.input})
				require.NoError(t, err)
				require.Len(t, evaluation.Resources, 1+test.instances)
				require.Equal(t, test.failed, evaluation.PolicyUnit(nil).Failure() != nil)
				require.Equal(t, test.failed, len(evaluation.Diagnostics()) > 0)
			}
		})
	}
}
