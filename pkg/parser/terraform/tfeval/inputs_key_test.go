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

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestInputsKeySharedCollectionDoesNotScale(t *testing.T) {
	cfg := objectWithKeys(500, "")
	one := keyingAlloc(t, cfg, 1)
	many := keyingAlloc(t, cfg, 32)
	// A cache key used to retain another encoding of cfg for every instance.
	if many > one*4 {
		t.Fatalf("keying 32 instances allocated %d bytes, one instance %d", many, one)
	}

	var memo keyMemo
	first := memo.inputsKey(map[string]cty.Value{
		"config": cfg,
		"n":      cty.NumberIntVal(0),
	})
	if again := memo.inputsKey(map[string]cty.Value{
		"config": cfg,
		"n":      cty.NumberIntVal(0),
	}); again != first {
		t.Fatal("the same inputs produced a different key")
	}
	if got := memo.inputsKey(map[string]cty.Value{
		"config": cfg,
		"n":      cty.NumberIntVal(1),
	}); got == first {
		t.Fatal("a different instance reused the first key")
	}
	if got := memo.inputsKey(map[string]cty.Value{
		"config": objectWithKeys(500, "other"),
		"n":      cty.NumberIntVal(0),
	}); got == first {
		t.Fatal("a different collection produced the same key")
	}
	if len(memo.entries) != 2 {
		t.Fatalf("memoized %d collections, want the two distinct configs", len(memo.entries))
	}
}

// A long collection checked for unknowns once, such as a value built per
// instance, is not kept; one checked again in a later module evaluation is
// remembered with its answer.
func TestWhollyKnownRemembersACollectionCheckedAgain(t *testing.T) {
	var memo keyMemo
	shared := objectWithKeys(minWhollyKnownMemo, "")
	perInstance := make([]cty.Value, 3)
	for i := range perInstance {
		memo.beginGeneration()
		perInstance[i] = objectWithKeys(minWhollyKnownMemo, fmt.Sprint(i))
		if !memo.whollyKnown(perInstance[i]) {
			t.Fatal("a known collection was reported unknown")
		}
	}
	if len(memo.entries) != 0 {
		t.Fatalf("kept %d collections each checked once", len(memo.entries))
	}
	memo.beginGeneration()
	if !memo.whollyKnown(shared) {
		t.Fatal("a known collection was reported unknown")
	}
	memo.beginGeneration()
	for range 3 {
		if !memo.whollyKnown(shared) {
			t.Fatal("a known collection was reported unknown")
		}
	}
	if len(memo.entries) != 1 {
		t.Fatalf("kept %d collections, want the one checked again", len(memo.entries))
	}
	partly := cty.ObjectVal(map[string]cty.Value{"a": cty.UnknownVal(cty.String), "b": shared})
	list := cty.ListVal([]cty.Value{partly, partly, partly})
	for range minWhollyKnownMemo / 3 {
		list = cty.ListVal(append(list.AsValueSlice(), partly))
	}
	memo.beginGeneration()
	if memo.whollyKnown(list) {
		t.Fatal("a collection holding an unknown was reported wholly known")
	}
	memo.beginGeneration()
	for range 3 {
		if memo.whollyKnown(list) {
			t.Fatal("a collection holding an unknown was reported wholly known")
		}
	}
}

// resolveLocalsWith re-checks unresolved locals within one evaluation; that
// must not promote a long collection into entries.
func TestWhollyKnownSameGenerationDoesNotPromote(t *testing.T) {
	var memo keyMemo
	shared := objectWithKeys(minWhollyKnownMemo, "")
	memo.beginGeneration()
	for range 3 {
		if !memo.whollyKnown(shared) {
			t.Fatal("a known collection was reported unknown")
		}
	}
	if len(memo.entries) != 0 {
		t.Fatalf("kept %d collections within one generation", len(memo.entries))
	}
	memo.beginGeneration()
	if !memo.whollyKnown(shared) {
		t.Fatal("a known collection was reported unknown")
	}
	if len(memo.entries) != 1 {
		t.Fatalf("kept %d collections after the next generation, want 1", len(memo.entries))
	}
}

func TestInputsKeyEmptyListsOfDifferentTypesDoNotCollide(t *testing.T) {
	var memo keyMemo
	strings := memo.inputsKey(map[string]cty.Value{"v": cty.ListValEmpty(cty.String)})
	numbers := memo.inputsKey(map[string]cty.Value{"v": cty.ListValEmpty(cty.Number)})
	if strings == numbers {
		t.Fatal("empty lists of different types produced the same key")
	}
	if len(memo.entries) != 0 {
		t.Fatalf("memoized %d empty lists", len(memo.entries))
	}
}

func TestInputsKeyNullAndUnknownStructuralTypesDoNotCollide(t *testing.T) {
	foo := cty.Object(map[string]cty.Type{"foo": cty.String})
	bar := cty.Object(map[string]cty.Type{"bar": cty.Number})
	require.NotEqual(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.NullVal(foo)}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.NullVal(bar)}),
	)
	require.NotEqual(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.UnknownVal(foo)}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.UnknownVal(bar)}),
	)
	require.NotEqual(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.NullVal(cty.Tuple([]cty.Type{cty.String}))}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.NullVal(cty.Tuple([]cty.Type{cty.Number}))}),
	)
	require.NotEqual(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.ListValEmpty(foo)}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.ListValEmpty(bar)}),
	)
	require.Equal(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.NullVal(foo)}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.NullVal(cty.Object(map[string]cty.Type{"foo": cty.String}))}),
	)
}

func TestInputsKeyNonFiniteNumbersDoNotCollideWithUnknown(t *testing.T) {
	positiveInfinity := cty.NumberVal(new(big.Float).SetInf(false))
	negativeInfinity := cty.NumberVal(new(big.Float).SetInf(true))
	unknown := cty.UnknownVal(cty.Number)

	keys := []inputsDigest{
		canonicalInputsKey(map[string]cty.Value{"v": positiveInfinity}),
		canonicalInputsKey(map[string]cty.Value{"v": negativeInfinity}),
		canonicalInputsKey(map[string]cty.Value{"v": unknown}),
	}
	require.NotEqual(t, keys[0], keys[1])
	require.NotEqual(t, keys[0], keys[2])
	require.NotEqual(t, keys[1], keys[2])
}

func TestInputsKeyMemoizesCollectionInputsOnly(t *testing.T) {
	var memo keyMemo
	memo.inputsKey(map[string]cty.Value{
		"config": cty.ObjectVal(map[string]cty.Value{
			"nested": cty.ListVal([]cty.Value{cty.StringVal("x")}),
		}),
		"name": cty.StringVal("plain"),
	})
	if len(memo.entries) != 1 {
		t.Fatalf("memoized %d collections, want the top-level collection input only", len(memo.entries))
	}
}

func TestEvaluateModuleSharedConfigDigestedOnce(t *testing.T) {
	const keys = 64
	root := t.TempDir()
	stack := writeModule(t, root, "stack", map[string]string{
		"config.json": jsonObject(keys),
		"main.tf": `
locals {
  config = jsondecode(file("${path.module}/config.json"))
}
module "acct" {
  source   = "../leaf"
  for_each = { for i in range(40) : format("k%03d", i) => i }
  name     = each.key
  config   = local.config
}
`,
	})
	writeModule(t, root, "leaf", map[string]string{
		"main.tf": `
variable "name" {}
variable "config" {}
resource "aws_s3_bucket" "b" {
  bucket = "${var.name}-${var.config.k0000}"
  size   = length(var.config)
}
`,
	})

	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 40)
	names := make(map[string]struct{}, len(resources))
	for _, r := range resources {
		names[r.Attributes["bucket"].AsString()] = struct{}{}
		require.True(t, r.Attributes["size"].RawEquals(cty.NumberIntVal(keys)))
	}
	require.Len(t, names, 40)
	require.Len(t, e.keyMemo.entries, 1)
}

func TestEvalObjectLength(t *testing.T) {
	objectType := cty.Object(map[string]cty.Type{"known": cty.String, "unknown": cty.String})
	for _, tc := range []struct {
		name string
		src  string
		vars map[string]cty.Value
		ok   bool
		want cty.Value
	}{
		{
			name: "object",
			src:  `length(var.config)`,
			vars: map[string]cty.Value{"config": cty.ObjectVal(map[string]cty.Value{
				"known": cty.StringVal("x"), "unknown": cty.StringVal("y"),
			})},
			ok:   true,
			want: cty.NumberIntVal(2),
		},
		{
			name: "partly unknown object",
			src:  `length(var.config)`,
			vars: map[string]cty.Value{"config": cty.ObjectVal(map[string]cty.Value{
				"known": cty.StringVal("x"), "unknown": cty.UnknownVal(cty.String),
			})},
			ok:   true,
			want: cty.NumberIntVal(2),
		},
		{
			name: "null object",
			src:  `length(var.config)`,
			vars: map[string]cty.Value{"config": cty.NullVal(objectType)},
			ok:   true,
			want: cty.DynamicVal,
		},
		{
			name: "unknown object",
			src:  `length(var.config)`,
			vars: map[string]cty.Value{"config": cty.UnknownVal(objectType)},
			ok:   true,
			want: cty.UnknownVal(cty.Number),
		},
		{
			name: "list",
			src:  `length(var.config)`,
			vars: map[string]cty.Value{"config": cty.ListVal([]cty.Value{cty.StringVal("x")})},
			ok:   true,
			want: cty.NumberIntVal(1),
		},
		{
			name: "string",
			src:  `length(var.config)`,
			vars: map[string]cty.Value{"config": cty.StringVal("ab")},
			ok:   true,
			want: cty.NumberIntVal(2),
		},
		{
			name: "expanded argument stays on the normal path",
			src:  `length(var.items...)`,
			vars: map[string]cty.Value{"items": cty.ListVal([]cty.Value{cty.StringVal("x")})},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expr, diags := hclsyntax.ParseExpression([]byte(tc.src), "test.tf", hcl.InitialPos)
			require.False(t, diags.HasErrors())
			got, ok := evalLength(expr, &hcl.EvalContext{Variables: map[string]cty.Value{
				"var": cty.ObjectVal(tc.vars),
			}})
			require.Equal(t, tc.ok, ok)
			if ok {
				require.True(t, got.RawEquals(tc.want))
			}
		})
	}
}

func keyingAlloc(t *testing.T, cfg cty.Value, n int) uint64 {
	t.Helper()
	inputs := make([]map[string]cty.Value, n)
	for i := range inputs {
		inputs[i] = map[string]cty.Value{
			"config": cfg,
			"n":      cty.NumberIntVal(int64(i)),
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var memo keyMemo
	var last inputsDigest
	for _, in := range inputs {
		last = memo.inputsKey(in)
	}
	runtime.KeepAlive(last)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func objectWithKeys(n int, first string) cty.Value {
	attrs := make(map[string]cty.Value, n)
	for i := range n {
		v := "value"
		if i == 0 && first != "" {
			v = first
		}
		attrs[fmt.Sprintf("k%04d", i)] = cty.StringVal(v)
	}
	return cty.ObjectVal(attrs)
}

func jsonObject(n int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"k%04d":"v%04d"`, i, i)
	}
	b.WriteByte('}')
	return b.String()
}

func canonicalInputsKey(inputs map[string]cty.Value) inputsDigest {
	return (*keyMemo)(nil).inputsKey(inputs)
}

func encodeCtyForKey(v cty.Value) string {
	var b strings.Builder
	(*keyMemo)(nil).writeValue(stringWriter{&b}, v, false)
	return b.String()
}

type stringWriter struct{ b *strings.Builder }

func (w stringWriter) WriteString(s string) { _, _ = w.b.WriteString(s) }
