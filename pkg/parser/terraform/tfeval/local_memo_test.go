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
	"strings"
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

func TestEvaluateModule_SharedLocalsTellAbsentAttributesApart(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "config" { type = any }
locals {
  owner = try(var.config.owner, "nobody")
}
resource "aws_sqs_queue" "this" {
  name = local.owner
}
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "set" {
  source = "../child"
  config = { owner = "team" }
}
module "unset" {
  source = "../child"
  config = { other = "x" }
}
module "unset_too" {
  source = "../child"
  config = { another = "y" }
}
`,
	})

	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	byAddr := resourcesByAddress(resources)
	requireString(t, byAddr["module.set/aws_sqs_queue.this"].Attributes, "name", "team")
	requireString(t, byAddr["module.unset/aws_sqs_queue.this"].Attributes, "name", "nobody")
	requireString(t, byAddr["module.unset_too/aws_sqs_queue.this"].Attributes, "name", "nobody")
	require.Equal(t, 1, e.LocalMemoSize(),
		"the absent attribute is shared once it is seen twice, and the configuration seen once is not kept")
}

func TestLocalMemo_PerInstanceValuesAreNotRetained(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "n" {}
locals { name = var.n }
resource "aws_sqs_queue" "q" { name = local.name }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "leaf" {
  source   = "../leaf"
  for_each = toset(["a", "b", "c", "d"])
  n        = each.key
}
`})
	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 4)
	require.Zero(t, e.LocalMemoSize())
}

// Each instance of the loop runs a prepass over its two child modules. A local
// pending from one instance is still there for the next one to share.
func TestLocalMemo_LoopOfModulesWithTwoChildrenSharesLocals(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "n" {}
resource "aws_sqs_queue" "q" { name = var.n }
`})
	writeModule(t, root, "mid", map[string]string{"main.tf": `
variable "config" { type = any }
variable "name" {}
locals { owners = join(",", keys(var.config)) }
module "one" {
  source = "../leaf"
  n      = "${var.name}-one"
}
module "two" {
  source = "../leaf"
  n      = "${var.name}-two"
}
resource "aws_sqs_queue" "q" { name = "${var.name}-${local.owners}" }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
locals {
  config = {
    a = { owner = "team-a" }
    b = { owner = "team-b" }
  }
}
module "mid" {
  source   = "../mid"
  for_each = local.config
  name     = each.key
  config   = local.config
}
`})
	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	byAddr := resourcesByAddress(resources)
	requireString(t, byAddr[`module.mid["a"]/aws_sqs_queue.q`].Attributes, "name", "a-a,b")
	requireString(t, byAddr[`module.mid["b"]/aws_sqs_queue.q`].Attributes, "name", "b-a,b")
	require.Equal(t, 1, e.LocalMemoSize())
}

func parseLocalExpr(t *testing.T, src string) hclsyntax.Expression {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "t.hcl", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	return expr
}

func localCtx(x cty.Value) *hcl.EvalContext {
	vars := map[string]cty.Value{
		"var": cty.ObjectVal(map[string]cty.Value{"x": x}),
	}
	for name, value := range functions.ContextVariables("/mod", "/root") {
		vars[name] = value
	}
	return &hcl.EvalContext{Variables: vars}
}

func TestLocalMemo_PromotionsAreBounded(t *testing.T) {
	e := New()
	expr := parseLocalExpr(t, `"v-${var.x}"`)
	for i := range localMemoCap + 10 {
		x := cty.NumberIntVal(int64(i))
		e.evalAddr = "a"
		e.localValue(expr, localCtx(x))
		e.evalAddr = "b"
		got := e.localValue(expr, localCtx(x))
		require.Equal(t, fmt.Sprintf("v-%d", i), got.AsString())
	}
	require.Equal(t, localMemoCap, e.LocalMemoSize())
}

// Once a local is shared, an expression never promoted is still not hashed on
// its first sight.
func TestLocalMemo_UnpromotedExpressionsAreNotHashed(t *testing.T) {
	e := New()
	shared := parseLocalExpr(t, `"s-${var.x}"`)
	other := parseLocalExpr(t, `"o-${var.x}"`)
	ctx := localCtx(cty.StringVal("x"))
	e.evalAddr = "a"
	e.localValue(shared, ctx)
	e.evalAddr = "b"
	e.localValue(shared, ctx)
	require.Equal(t, 1, e.LocalMemoSize())
	gen := e.keyMemo.digestGen
	e.evalAddr = "c"
	require.Equal(t, "o-x", e.localValue(other, ctx).AsString())
	require.Equal(t, gen, e.keyMemo.digestGen, "a first sight is not hashed")
	e.evalAddr = "d"
	require.Equal(t, "s-x", e.localValue(shared, ctx).AsString())
}

// Comparing each instance against the one before hashes the new inputs once:
// the pending entry keeps the digest it was compared with.
func TestLocalMemo_PendingDigestIsReused(t *testing.T) {
	e := New()
	expr := parseLocalExpr(t, `"v-${var.x}"`)
	for _, addr := range []string{"a", "b", "c", "d"} {
		e.evalAddr = addr
		require.Equal(t, "v-"+addr, e.localValue(expr, localCtx(cty.StringVal(addr))).AsString())
	}
	require.Equal(t, uint64(4), e.keyMemo.digestGen, "b hashes itself and a, c and d hash themselves")
	require.Zero(t, e.LocalMemoSize())
}

// Collections are the same input only by storage; walking them is what the
// comparison avoids. One instance passing the same storage still reuses.
func TestSameInputs_ComparesCollectionsByStorage(t *testing.T) {
	list := func() cty.Value { return cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}) }
	a, b := list(), list()
	require.True(t, sameInputs(map[string]cty.Value{"x": a}, map[string]cty.Value{"x": a}))
	require.False(t, sameInputs(map[string]cty.Value{"x": a}, map[string]cty.Value{"x": b}))
	require.True(t, sameInputs(
		map[string]cty.Value{"x": cty.StringVal("s")},
		map[string]cty.Value{"x": cty.StringVal("s")},
	))

	e := New()
	expr := parseLocalExpr(t, `[for s in var.x : "${s}!"]`)
	e.evalAddr = "a"
	first := e.localValue(expr, localCtx(a))
	require.True(t, sharesStorage(first, e.localValue(expr, localCtx(a))))
	require.Zero(t, e.keyMemo.digestGen, "the same instance reuses without hashing")
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

// memoChainCost is what evaluating a chain of locals allocated, and what it
// left live after a GC while its results were held.
type memoChainCost struct {
	retained, allocated float64
}

func memoChainStack(t *testing.T, length int) string {
	t.Helper()
	const width = 100
	var b strings.Builder
	fmt.Fprintf(&b, "locals {\n  l0 = { for i in range(%d) : format(\"k%%04d\", i) => { n = i, s = \"v\" } }\n", width)
	for l := 1; l < length; l++ {
		fmt.Fprintf(&b, "  l%d = { for k, v in local.l%d : k => { n = v.n + 1, s = \"${v.s}x\" } }\n", l, l-1)
	}
	fmt.Fprintf(&b, "}\nresource \"aws_sqs_queue\" \"q\" { name = local.l%d[\"k0000\"].s }\n", length-1)
	return writeModule(t, t.TempDir(), "stack", map[string]string{"main.tf": b.String()})
}

func memoChainHeap() runtime.MemStats {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

func measureMemoChain(t *testing.T, length int) memoChainCost {
	t.Helper()
	stack := memoChainStack(t, length)
	before := memoChainHeap()
	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	after := memoChainHeap()
	runtime.KeepAlive(e)
	require.Len(t, resources, 1)
	want := "v" + strings.Repeat("x", length-1)
	require.True(t, resources[0].Attributes["name"].RawEquals(cty.StringVal(want)),
		"a chain of %d locals did not resolve: %#v", length, resources[0].Attributes["name"])
	return memoChainCost{
		retained:  float64(int64(after.HeapAlloc) - int64(before.HeapAlloc)),
		allocated: float64(after.TotalAlloc - before.TotalAlloc),
	}
}

// A chain of locals each derived from the one before must cost the same per
// local however long it is: work repeated for every resolved local whenever
// another resolves makes the chain quadratic.
func TestLocalMemo_ChainCostIsLinear(t *testing.T) {
	const (
		maxGrowth = 1.5
		// Calibrated at about 800 KiB allocated and 95 KiB retained per local,
		// with 2x headroom.
		allocatedBudget float64 = 1600 * 1024
		retainedBudget  float64 = 190 * 1024
	)
	measureMemoChain(t, 2) // charges lazily initialized globals to no size
	lengths := []int{3, 5, 10}
	costs := make([]memoChainCost, len(lengths))
	for i, length := range lengths {
		costs[i] = measureMemoChain(t, length)
		t.Logf("%2d locals: retained %.1f KiB, allocated %.1f KiB", length, costs[i].retained/1024, costs[i].allocated/1024)
	}
	perLocal := func(i, j int) memoChainCost {
		n := float64(lengths[j] - lengths[i])
		return memoChainCost{
			retained:  (costs[j].retained - costs[i].retained) / n,
			allocated: (costs[j].allocated - costs[i].allocated) / n,
		}
	}
	first, last := perLocal(0, 1), perLocal(1, 2)
	t.Logf("per local: allocated %.1f→%.1f KiB, retained %.1f→%.1f KiB",
		first.allocated/1024, last.allocated/1024, first.retained/1024, last.retained/1024)
	require.LessOrEqual(t, last.allocated, maxGrowth*max(first.allocated, 1024),
		"allocated bytes per local grew with the chain length")
	require.LessOrEqual(t, last.retained, maxGrowth*max(first.retained, 1024),
		"retained heap per local grew with the chain length")
	require.LessOrEqual(t, last.allocated, allocatedBudget, "every local got more expensive to resolve")
	require.LessOrEqual(t, last.retained, retainedBudget, "every local retains more")
}
