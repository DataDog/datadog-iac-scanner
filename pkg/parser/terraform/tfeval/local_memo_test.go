/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"math/big"
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
		cty.SetVal([]cty.Value{cty.StringVal("x"), cty.UnknownVal(cty.String)}),
		cty.SetVal([]cty.Value{cty.StringVal("x"), cty.NullVal(cty.String)}),
		cty.SetVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y").Mark("m")}),
		cty.SetVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y")}),
		cty.SetVal([]cty.Value{cty.NumberIntVal(1), cty.UnknownVal(cty.Number)}),
		cty.SetVal([]cty.Value{cty.NumberIntVal(1), cty.NullVal(cty.Number)}),
		cty.SetVal([]cty.Value{cty.True, cty.UnknownVal(cty.Bool)}),
		cty.SetVal([]cty.Value{cty.True, cty.NullVal(cty.Bool)}),
		cty.SetVal([]cty.Value{cty.StringVal("x"), cty.UnknownVal(cty.String), cty.UnknownVal(cty.String)}),
		cty.SetValEmpty(cty.String),
		cty.ObjectVal(map[string]cty.Value{"v": cty.UnknownVal(cty.String)}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.NullVal(cty.String)}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.NullVal(cty.Number)}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.StringVal("x").Mark("m")}),
		cty.ObjectVal(map[string]cty.Value{"v": cty.StringVal("x")}),
		cty.DynamicVal,
		cty.NullVal(cty.DynamicPseudoType),
		cty.StringVal("x"),
	}
	var memo keyMemo
	for i, a := range values {
		for j, b := range values {
			require.Equal(t, a.RawEquals(b), equalValues(a, b), "values %d and %d: %#v vs %#v", i, j, a, b)
			require.Equal(t, a.RawEquals(b), memo.equal(a, b), "memoized, values %d and %d: %#v vs %#v", i, j, a, b)
		}
	}
	require.True(t, sharesStorage(wrap(shared).GetAttr("v"), shared))
	set := cty.SetVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y")})
	require.True(t, sharesStorage(wrap(set).GetAttr("v"), set))

	base, _, err := big.ParseFloat("0.1", 10, 64, big.ToNearestEven)
	require.NoError(t, err)
	// Same numeric value at a higher precision. Cmp matches; cty does not.
	wider := new(big.Float).SetPrec(256).Set(base)
	a, b := cty.NumberVal(base), cty.NumberVal(wider)
	require.Zero(t, base.Cmp(wider))
	require.False(t, a.RawEquals(b))
	require.False(t, memo.equal(a, b))
	require.False(t, memo.equalElement(a, b))
}

func memoSet(tag string, i int) cty.Value {
	return cty.SetVal([]cty.Value{cty.StringVal(fmt.Sprintf("%s-%d-a", tag, i)), cty.StringVal(fmt.Sprintf("%s-%d-b", tag, i))})
}

// The memo keys a set by its storage, so it keeps the set: a set allocated
// after a GC must not reuse the storage of one it remembers.
func TestKeyMemo_KeepsTheSetsItSorted(t *testing.T) {
	var memo keyMemo
	kept := memoSet("kept", 0)
	memo.setElements(kept)
	keptID, _ := collectionIdentity(kept)
	require.NotContains(t, memo.sets, keptID, "a set seen once is not kept")
	memo.setElements(kept)
	require.Contains(t, memo.sets, keptID)
	runtime.GC()
	runtime.GC()
	for i := range 2000 {
		got := memo.setElements(memoSet("new", i))
		require.Len(t, got, 2)
		require.Equal(t, fmt.Sprintf("new-%d-a", i), got[0].value.AsString())
		require.Equal(t, fmt.Sprintf("new-%d-b", i), got[1].value.AsString())
		id, ok := collectionIdentity(memoSet("new", i))
		if ok {
			require.NotContains(t, memo.sets, id)
		}
	}
	for _, entry := range memo.sets {
		require.Equal(t, entry.value.LengthInt(), len(entry.pairs))
		for _, pair := range entry.pairs {
			require.True(t, entry.value.HasElement(pair.value).True())
		}
	}
}

// A full record of sets seen once still lets a stable set be stored when it is
// sorted again.
func TestKeyMemo_StableSetIsKeptAfterManyOneOffSets(t *testing.T) {
	var memo keyMemo
	others := make([]cty.Value, keyMemoSeenSetsCap+10)
	for i := range others {
		others[i] = memoSet("other", i)
		memo.setElements(others[i])
	}
	stable := memoSet("stable", 0)
	memo.setElements(stable)
	memo.setElements(stable)
	id, ok := collectionIdentity(stable)
	require.True(t, ok)
	require.Contains(t, memo.sets, id)
	require.LessOrEqual(t, len(memo.seenSets), keyMemoSeenSetsCap)
}

// A set seen once is recorded by its storage. Dropping it lets a later set
// reuse that storage, and the first sort of that set would look like a second
// one, so the record keeps the value alive.
func TestKeyMemo_SeenSetIsNotConfusedWithAReusedStorage(t *testing.T) {
	var memo keyMemo
	for i := range 64 {
		memo.setElements(memoSet("gone", i))
	}
	require.Len(t, memo.seenSets, 64)
	for id, seen := range memo.seenSets {
		kept, ok := collectionIdentity(seen.value)
		require.True(t, ok)
		require.Equal(t, id, kept, "the record holds the set its id was taken from")
	}
	runtime.GC()
	runtime.GC()
	for i := range 4000 {
		memo.setElements(memoSet("new", i))
		require.Empty(t, memo.sets, "set %d was sorted once", i)
	}
}

// Counted sets stop being stored once they would pass the element cap, and
// that does not drop a digest or another set. Two sets over the cap both stay
// cached. Releasing one evaluator leaves the other's sets in place.
func TestKeyMemo_SetPairsAreBoundedAndReleasedPerEvaluator(t *testing.T) {
	big := func(tag string, n int) cty.Value {
		elems := make([]cty.Value, n)
		for i := range elems {
			elems[i] = cty.StringVal(fmt.Sprintf("%s-%d", tag, i))
		}
		return cty.SetVal(elems)
	}
	var memo keyMemo
	kept := big("a", keyMemoPairsCap/2+1)
	memo.setElements(kept)
	memo.setElements(kept)
	other := big("b", keyMemoPairsCap/2+1)
	memo.setElements(other)
	memo.setElements(other)
	require.Len(t, memo.sets, 1)
	require.Equal(t, keyMemoPairsCap/2+1, memo.pairs)
	keptID, _ := collectionIdentity(kept)
	require.Contains(t, memo.sets, keptID)

	cfg := cty.ObjectVal(map[string]cty.Value{"k": cty.StringVal("v")})
	memo.inputsKey(map[string]cty.Value{"config": cfg})
	memo.inputsKey(map[string]cty.Value{"config": cfg})
	require.Len(t, memo.digests, 1)

	hugeA := big("huge-a", keyMemoPairsCap+1)
	hugeB := big("huge-b", keyMemoPairsCap+1)
	memo.setElements(hugeA)
	memo.setElements(hugeB)
	pairsA := memo.setElements(hugeA)
	pairsB := memo.setElements(hugeB)
	require.Same(t, &pairsA[0], &memo.setElements(hugeA)[0])
	require.Same(t, &pairsB[0], &memo.setElements(hugeB)[0])
	require.Len(t, memo.sets, 1)
	require.Len(t, memo.digests, 1)
	small := memoSet("small", 0)
	memo.setElements(small)
	memo.setElements(small)
	require.Len(t, memo.sets, 2)
	require.Len(t, memo.digests, 1)

	set := memoSet("both", 0)
	first, second := New(), New()
	in := map[string]cty.Value{"v": set}
	first.keyMemo.inputsKey(in)
	first.keyMemo.inputsKey(in)
	first.keyMemo.setElements(set)
	first.keyMemo.setElements(set)
	secondSet := memoSet("second", 0)
	second.keyMemo.setElements(secondSet)
	second.keyMemo.setElements(secondSet)
	require.Len(t, first.keyMemo.digests, 1)
	require.Len(t, first.keyMemo.sets, 1)
	first.ReleaseEvalCache()
	require.Empty(t, first.keyMemo.digests)
	require.Empty(t, first.keyMemo.sets)
	require.Zero(t, first.keyMemo.pairs)
	require.Zero(t, first.KeyMemoSize())
	require.Len(t, second.keyMemo.sets, 1)
}

func TestKeyMemo_DigestRetentionIsBounded(t *testing.T) {
	var memo keyMemo
	objects := make([]cty.Value, keyMemoDigestCap+10)
	for i := range objects {
		objects[i] = cty.ObjectVal(map[string]cty.Value{"n": cty.NumberIntVal(int64(i))})
	}
	for _, obj := range objects {
		in := map[string]cty.Value{"c": obj}
		memo.inputsKey(in)
		memo.inputsKey(in)
	}
	require.LessOrEqual(t, len(memo.digests), keyMemoDigestCap)
	id, ok := collectionIdentity(objects[0])
	require.True(t, ok)
	require.Contains(t, memo.digests, id)
}

// A full pending set gives way to the oldest entry, so a collection keyed again
// after many one-off collections is still retained.
func TestKeyMemo_RepeatedDigestIsKeptAfterManyOneOffs(t *testing.T) {
	var memo keyMemo
	objects := make([]cty.Value, keyMemoDigestCap+10)
	for i := range objects {
		objects[i] = cty.ObjectVal(map[string]cty.Value{"n": cty.NumberIntVal(int64(i))})
		memo.inputsKey(map[string]cty.Value{"c": objects[i]})
	}
	shared := cty.ObjectVal(map[string]cty.Value{"owner": cty.StringVal("team")})
	memo.inputsKey(map[string]cty.Value{"c": shared})
	memo.inputsKey(map[string]cty.Value{"c": shared})
	id, ok := collectionIdentity(shared)
	require.True(t, ok)
	require.Contains(t, memo.digests, id)
	require.LessOrEqual(t, len(memo.pendingDigests), keyMemoDigestCap)
}

// Other locals key their own collections between two instances. The shared
// configuration is still retained when the next instance keys it.
func TestKeyMemo_SharedDigestSurvivesInterveningKeys(t *testing.T) {
	var memo keyMemo
	shared := cty.ObjectVal(map[string]cty.Value{"owner": cty.StringVal("team")})
	for i := range 5 {
		memo.inputsKey(map[string]cty.Value{"config": shared})
		other := cty.ObjectVal(map[string]cty.Value{"n": cty.NumberIntVal(int64(i))})
		memo.inputsKey(map[string]cty.Value{"config": other})
	}
	id, ok := collectionIdentity(shared)
	require.True(t, ok)
	require.Contains(t, memo.digests, id)
	require.NotZero(t, len(memo.digests))
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
