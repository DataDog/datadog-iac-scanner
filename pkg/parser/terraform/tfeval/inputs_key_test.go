/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"reflect"
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
	first, _ := memo.inputsKey(context.Background(), map[string]cty.Value{
		"config": cfg,
		"n":      cty.NumberIntVal(0),
	})
	if again, _ := memo.inputsKey(context.Background(), map[string]cty.Value{
		"config": cfg,
		"n":      cty.NumberIntVal(0),
	}); again != first {
		t.Fatal("the same inputs produced a different key")
	}
	if got, _ := memo.inputsKey(context.Background(), map[string]cty.Value{
		"config": cfg,
		"n":      cty.NumberIntVal(1),
	}); got == first {
		t.Fatal("a different instance reused the first key")
	}
	if got, _ := memo.inputsKey(context.Background(), map[string]cty.Value{
		"config": objectWithKeys(500, "other"),
		"n":      cty.NumberIntVal(0),
	}); got == first {
		t.Fatal("a different collection produced the same key")
	}
	if len(memo.entries) != 2 {
		t.Fatalf("memoized %d collections, want the two distinct configs", len(memo.entries))
	}
}

func TestInputsKeyEmptyListsOfDifferentTypesDoNotCollide(t *testing.T) {
	var memo keyMemo
	strings, _ := memo.inputsKey(context.Background(), map[string]cty.Value{"v": cty.ListValEmpty(cty.String)})
	numbers, _ := memo.inputsKey(context.Background(), map[string]cty.Value{"v": cty.ListValEmpty(cty.Number)})
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
	_, _ = memo.inputsKey(context.Background(), map[string]cty.Value{
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
			ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
				"var":  cty.ObjectVal(tc.vars),
				"path": cty.EmptyObjectVal,
			}}
			got, ok := evalLength(expr, ctx)
			require.Equal(t, tc.ok, ok)
			if ok {
				require.True(t, got.RawEquals(tc.want))
				got = New().evalExprMemo(expr, ctx, &bodyState{memo: newInvariantMemo()})
				require.True(t, got.RawEquals(tc.want), "resource attributes must preserve length semantics")
			}
		})
	}
}

func TestEvalExprMemo_ObjectLengthDoesNotScale(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte("length(var.config)"), "test.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	allocsFor := func(size int) float64 {
		ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
			"var":  cty.ObjectVal(map[string]cty.Value{"config": objectWithKeys(size, "")}),
			"path": cty.EmptyObjectVal,
		}}
		var got cty.Value
		allocs := testing.AllocsPerRun(3, func() {
			e := New()
			for range 50 {
				got = e.evalExprMemo(expr, ctx, &bodyState{memo: newInvariantMemo()})
			}
		})
		require.True(t, got.RawEquals(cty.NumberIntVal(int64(size))))
		return allocs
	}
	one, many := allocsFor(1), allocsFor(10000)
	require.LessOrEqual(t, many, one*2, "object length must not walk the shared object's values")
}

// Each operation evaluates one attribute in 50 module instances sharing the
// same object. Reading its length should not walk the object's values.
func BenchmarkEvalExprMemo_ObjectLength(b *testing.B) {
	expr, diags := hclsyntax.ParseExpression([]byte("length(var.config)"), "test.tf", hcl.InitialPos)
	require.False(b, diags.HasErrors())
	for _, size := range []int{1, 10000} {
		b.Run(fmt.Sprintf("keys=%d", size), func(b *testing.B) {
			ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
				"var":  cty.ObjectVal(map[string]cty.Value{"config": objectWithKeys(size, "")}),
				"path": cty.EmptyObjectVal,
			}}
			want := cty.NumberIntVal(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				e := New()
				for range 50 {
					got := e.evalExprMemo(expr, ctx, &bodyState{memo: newInvariantMemo()})
					if !got.RawEquals(want) {
						b.Fatal("incorrect object length")
					}
				}
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
		last, _ = memo.inputsKey(context.Background(), in)
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
	key, _ := (*keyMemo)(nil).inputsKey(context.Background(), inputs)
	return key
}

func encodeCtyForKey(v cty.Value) string {
	var b strings.Builder
	(*keyMemo)(nil).writeValue(context.Background(), stringWriter{&b}, v, false)
	return b.String()
}

type stringWriter struct{ b *strings.Builder }

func (w stringWriter) WriteString(s string) { _, _ = w.b.WriteString(s) }

func TestInputsKeyNumericContext(t *testing.T) {
	values := []cty.Value{
		cty.NumberVal(new(big.Float).SetPrec(64).SetFloat64(1.5)),
		cty.NumberVal(new(big.Float).SetPrec(512).SetFloat64(1.5)),
		cty.NumberVal(new(big.Float).SetPrec(64).SetMode(big.ToZero).SetFloat64(1.5)),
		cty.NumberVal(new(big.Float).SetFloat64(0)),
		cty.NumberVal(new(big.Float).SetFloat64(math.Copysign(0, -1))),
		cty.NumberIntVal(1), cty.NumberIntVal(-1), cty.StringVal("1"),
		cty.UnknownVal(cty.Number), cty.NullVal(cty.Number),
		cty.NumberVal(new(big.Float).SetInf(false)), cty.NumberVal(new(big.Float).SetInf(true)),
	}
	for i, value := range values {
		before := value.GoString()
		key := canonicalInputsKey(map[string]cty.Value{"v": value})
		for j, other := range values {
			if i != j {
				require.NotEqual(t, key, canonicalInputsKey(map[string]cty.Value{"v": other}))
			}
		}
		if value.Type() == cty.Number && value.IsKnown() && !value.IsNull() {
			copy := cty.NumberVal(value.AsBigFloat())
			require.Equal(t, key, canonicalInputsKey(map[string]cty.Value{"v": copy}))
			require.Equal(t, value.AsBigFloat().Prec(), copy.AsBigFloat().Prec())
		}
		require.Equal(t, before, value.GoString())
	}
	// Equal values produced by the same numeric context remain shareable.
	require.Equal(t, canonicalInputsKey(map[string]cty.Value{"v": cty.NumberIntVal(3).Divide(cty.NumberIntVal(2))}), canonicalInputsKey(map[string]cty.Value{"v": cty.NumberVal(new(big.Float).SetPrec(64).SetFloat64(1.5))}))
}

func TestInputsKeyNumericExponentEncoding(t *testing.T) {
	for _, exponent := range []int{-1 << 28, -32768, -1, 0, 1, 32768, 1 << 28} {
		value := cty.NumberVal(new(big.Float).SetMantExp(new(big.Float).SetInt64(3), exponent))
		encoded := encodeCtyForKey(value)
		require.Less(t, len(encoded), 64)
		require.NotEqual(t, encoded, encodeCtyForKey(value.Negate()))
		var memo keyMemo
		key, ok := memo.inputsKey(context.Background(), map[string]cty.Value{"v": value})
		require.True(t, ok)
		again, ok := memo.inputsKey(context.Background(), map[string]cty.Value{"v": value})
		require.True(t, ok)
		require.Equal(t, key, again)
	}
}

func TestInputsKeyUncacheableValues(t *testing.T) {
	opaque := "opaque"
	capsule := cty.CapsuleVal(cty.Capsule("test capsule", reflect.TypeOf(opaque)), &opaque)
	for _, value := range []cty.Value{capsule, cty.NullVal(capsule.Type()), cty.UnknownVal(capsule.Type()), cty.UnknownVal(cty.List(capsule.Type())), cty.ListValEmpty(capsule.Type()), cty.NumberIntVal(2).Mark("sensitive"), cty.TupleVal([]cty.Value{cty.NumberIntVal(2).Mark("sensitive")}), cty.ObjectVal(map[string]cty.Value{"n": cty.NumberIntVal(2)}).Mark("sensitive")} {
		var memo keyMemo
		_, ok := memo.inputsKey(context.Background(), map[string]cty.Value{"v": value})
		require.False(t, ok)
		require.Empty(t, memo.entries)
	}
	module := writeModule(t, t.TempDir(), "module", map[string]string{"main.tf": `variable "value" {}
locals { result = var.value + 1 }
resource "test_resource" "example" { value = local.result }
`})
	e := New()
	for _, mark := range []string{"sensitive", "other"} {
		resources, _, _, err := e.EvaluateModule(context.Background(), module, map[string]cty.Value{"value": cty.NumberIntVal(2).Mark(mark)})
		require.NoError(t, err)
		require.Len(t, resources, 1)
		value, marks := resources[0].Attributes["value"].Unmark()
		require.True(t, value.RawEquals(cty.NumberIntVal(3)))
		require.Contains(t, marks, mark)
		require.Zero(t, e.EvalCacheSize())
	}
	resources, _, _, err := e.EvaluateModule(context.Background(), module, map[string]cty.Value{"value": cty.NumberIntVal(2)})
	require.NoError(t, err)
	require.False(t, resources[0].Attributes["value"].IsMarked())
	require.Equal(t, 1, e.EvalCacheSize())

}

func TestEvalCacheNumericContext(t *testing.T) {
	module := writeModule(t, t.TempDir(), "module", map[string]string{"main.tf": `variable "config" {}
locals { quotient = var.config.x / var.config.y }
output "quotient" { value = local.quotient }
output "text" { value = tostring(var.config.x) }
`})
	shared := New()
	for _, input := range []struct {
		name string
		x, y *big.Float
	}{
		{"low precision", new(big.Float).SetPrec(64).SetInt64(1), new(big.Float).SetPrec(64).SetInt64(3)},
		{"high precision", new(big.Float).SetPrec(1024).SetInt64(1), new(big.Float).SetPrec(1024).SetInt64(3)},
		{"zero", new(big.Float).SetFloat64(0), new(big.Float).SetInt64(1)},
		{"negative zero", new(big.Float).SetFloat64(math.Copysign(0, -1)), new(big.Float).SetInt64(1)},
	} {
		t.Run(input.name, func(t *testing.T) {
			inputs := map[string]cty.Value{"config": cty.ObjectVal(map[string]cty.Value{"x": cty.NumberVal(input.x), "y": cty.NumberVal(input.y)})}
			_, freshOutputs, _, err := New().EvaluateModule(context.Background(), module, inputs)
			require.NoError(t, err)
			_, outputs, _, err := shared.EvaluateModule(context.Background(), module, inputs)
			require.NoError(t, err)
			require.True(t, freshOutputs["quotient"].RawEquals(outputs["quotient"]))
			require.Equal(t, freshOutputs["quotient"].AsBigFloat().Prec(), outputs["quotient"].AsBigFloat().Prec())
			require.Equal(t, freshOutputs["text"].AsString(), outputs["text"].AsString())
			entries := shared.EvalCacheSize()
			_, _, _, err = shared.EvaluateModule(context.Background(), module, inputs)
			require.NoError(t, err)
			require.Equal(t, entries, shared.EvalCacheSize())
		})
	}
	require.Equal(t, 4, shared.EvalCacheSize())
}

func BenchmarkInputsKeyNumbers(b *testing.B) {
	for _, exponent := range []int{-32768, 0, 32768} {
		b.Run(fmt.Sprint(exponent), func(b *testing.B) {
			value := cty.NumberVal(new(big.Float).SetMantExp(new(big.Float).SetInt64(3), exponent))
			inputs := map[string]cty.Value{"v": value}
			var memo keyMemo
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, ok := memo.inputsKey(context.Background(), inputs); !ok {
					b.Fatal("key unexpectedly ineligible")
				}
			}
		})
	}
}

func TestEvalCacheUnknownContext(t *testing.T) {
	collection := func(ty cty.Type, lower, upper int) cty.Value {
		return cty.UnknownVal(ty).Refine().NotNull().CollectionLengthLowerBound(lower).CollectionLengthUpperBound(upper).NewValue()
	}
	for _, test := range []struct {
		name, expression string
		values           []cty.Value
	}{
		{"map membership", `length(local.wrapped.value)`, []cty.Value{collection(cty.Map(cty.String), 1, 1), collection(cty.Map(cty.String), 2, 2), cty.UnknownVal(cty.Map(cty.String))}},
		{"list shape", `length(local.wrapped.value)`, []cty.Value{collection(cty.List(cty.String), 1, 3), collection(cty.List(cty.String), 2, 4), cty.UnknownVal(cty.List(cty.String))}},
		{"set shape", `length(local.wrapped.value)`, []cty.Value{collection(cty.Set(cty.String), 2, 2), collection(cty.Set(cty.String), 3, 3), cty.UnknownVal(cty.Set(cty.String))}},
		{"boolean nullability", `local.wrapped.value == null`, []cty.Value{cty.UnknownVal(cty.Bool), cty.UnknownVal(cty.Bool).RefineNotNull(), cty.True}},
		{"string prefix", `local.wrapped.value == "public"`, []cty.Value{cty.UnknownVal(cty.String).Refine().NotNull().StringPrefixFull("pub").NewValue(), cty.UnknownVal(cty.String).Refine().NotNull().StringPrefixFull("private").NewValue(), cty.UnknownVal(cty.String)}},
		{"numeric bounds", `local.wrapped.value > 0`, []cty.Value{cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeLowerBound(cty.NumberIntVal(10), true).NewValue(), cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeUpperBound(cty.NumberIntVal(-10), true).NewValue(), cty.UnknownVal(cty.Number)}},
		{"numeric endpoints", `local.wrapped.value == 0`, []cty.Value{cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeLowerBound(cty.Zero, true).NewValue(), cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeLowerBound(cty.Zero, false).NewValue(), cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeUpperBound(cty.Zero, false).NewValue()}},
		{"object nullability", `local.wrapped.value == null`, []cty.Value{cty.UnknownVal(cty.Object(map[string]cty.Type{"enabled": cty.Bool})), cty.UnknownVal(cty.Object(map[string]cty.Type{"enabled": cty.Bool})).RefineNotNull(), cty.ObjectVal(map[string]cty.Value{"enabled": cty.UnknownVal(cty.Bool)})}},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := writeModule(t, t.TempDir(), "module", map[string]string{"main.tf": `variable "input" {}
locals { wrapped = { value = var.input.value } }
output "input" { value = local.wrapped.value }
output "predicate" { value = ` + test.expression + ` }
`})
			for _, layer := range []string{"module cache", "local memo"} {
				t.Run(layer, func(t *testing.T) {
					shared := New()
					for _, value := range test.values {
						before := value.GoString()
						inputs := map[string]cty.Value{"input": cty.ObjectVal(map[string]cty.Value{"value": value})}
						_, freshOutputs, _, err := New().EvaluateModule(context.Background(), module, inputs)
						require.NoError(t, err)
						if layer == "local memo" {
							clear(shared.cache)
						}
						_, outputs, _, err := shared.EvaluateModule(context.Background(), module, inputs)
						require.NoError(t, err)
						for name, want := range freshOutputs {
							require.True(t, want.RawEquals(outputs[name]), "output %s differs from fresh evaluation", name)
						}
						entries, memoEntries := shared.EvalCacheSize(), shared.LocalMemoSize()
						require.Positive(t, memoEntries, "unknown contexts must exercise local memoization")
						if layer == "local memo" {
							clear(shared.cache)
						}
						// Reconstruct the outer object: equality of the abstract context,
						// rather than storage identity, permits reuse.
						_, againOutputs, _, err := shared.EvaluateModule(context.Background(), module, map[string]cty.Value{"input": cty.ObjectVal(map[string]cty.Value{"value": value})})
						require.NoError(t, err)
						for name, want := range freshOutputs {
							require.True(t, want.RawEquals(againOutputs[name]), "repeated output %s differs", name)
						}
						require.Equal(t, entries, shared.EvalCacheSize())
						require.Equal(t, memoEntries, shared.LocalMemoSize())
						require.Equal(t, before, value.GoString())
					}
				})
			}
		})
	}
}

func TestInputsKeyRefinedNumericBounds(t *testing.T) {
	for _, exponent := range []int{-1 << 28, 0, 1 << 28} {
		bound := cty.NumberVal(new(big.Float).SetMantExp(new(big.Float).SetInt64(3), exponent))
		inclusive := cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeLowerBound(bound, true).NewValue()
		exclusive := cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeLowerBound(bound, false).NewValue()
		encoded := encodeCtyForKey(inclusive)
		require.Less(t, len(encoded), 256)
		require.NotEqual(t, encoded, encodeCtyForKey(exclusive))
		require.Equal(t, encoded, encodeCtyForKey(cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeLowerBound(bound, true).NewValue()))
	}
}

func BenchmarkInputsKeyUnknownValues(b *testing.B) {
	for _, test := range []struct {
		name  string
		value cty.Value
	}{
		{"unrefined string", cty.UnknownVal(cty.String)},
		{"unrefined map", cty.UnknownVal(cty.Map(cty.String))},
		{"refined map", cty.UnknownVal(cty.Map(cty.String)).Refine().NotNull().CollectionLength(3).NewValue()},
		{"refined number", cty.UnknownVal(cty.Number).Refine().NotNull().NumberRangeLowerBound(cty.Zero, true).NewValue()},
	} {
		b.Run(test.name, func(b *testing.B) {
			inputs := map[string]cty.Value{"v": test.value}
			var memo keyMemo
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, ok := memo.inputsKey(context.Background(), inputs); !ok {
					b.Fatal("unknown context unexpectedly ineligible")
				}
			}
		})
	}
}

func TestEvalCacheUnknownInputsShareAcrossCalls(t *testing.T) {
	root := t.TempDir()
	caller := writeModule(t, root, "caller", map[string]string{"main.tf": `variable "input" {}
module "copies" {
 source="../child"
 count=64
 input=var.input
}`})
	writeModule(t, root, "child", map[string]string{"main.tf": `variable "input" {}
resource "test_resource" "example" { value=length(var.input) }`})
	for _, input := range []cty.Value{cty.UnknownVal(cty.Map(cty.String)), cty.UnknownVal(cty.Map(cty.String)).Refine().NotNull().CollectionLength(3).NewValue()} {
		e := New()
		resources, _, _, err := e.EvaluateModule(context.Background(), caller, map[string]cty.Value{"input": input})
		require.NoError(t, err)
		require.Len(t, resources, 64)
		require.Equal(t, 2, e.EvalCacheSize(), "one caller and one shared child evaluation")
		addresses := map[string]bool{}
		for _, resource := range resources {
			addresses[resource.ModuleAddress] = true
			require.True(t, input.Length().RawEquals(resource.Attributes["value"]))
		}
		require.Len(t, addresses, 64)
	}
}
