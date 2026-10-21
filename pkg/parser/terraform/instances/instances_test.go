/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package instances

import (
	"fmt"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func resolve(t *testing.T, src string, ctx *hcl.EvalContext, maxShape int) Plan {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "test.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	count, forEach := Attributes(file.Body.(*hclsyntax.Body))
	return Resolve(count, forEach, ctx, maxShape)
}

func TestResolveCount(t *testing.T) {
	for _, tt := range []struct {
		expr       string
		requested  int
		unresolved bool
	}{
		{"3", 3, false},
		{`"2"`, 2, false},
		{"0", 0, false},
		{"-2", 0, false},
		{fmt.Sprint(MaxPerBlock), MaxPerBlock, false},
		{fmt.Sprint(MaxPerBlock + 1), MaxPerBlock + 1, false},
		{"1.5", 0, true},
		{`"1.5"`, 0, true},
		{`"invalid"`, 0, true},
		{"true", 0, true},
		{"null", 0, true},
		{"9223372036854775808", 0, true},
		{"input", 0, true},
		{"missing", 0, true},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"input": cty.UnknownVal(cty.Number)}}
			plan := resolve(t, "count = "+tt.expr, ctx, 512)
			require.Equal(t, KindCount, plan.Kind)
			require.Equal(t, tt.unresolved, plan.Unresolved)
			require.Equal(t, tt.requested, plan.Requested)
			require.Len(t, plan.Items, min(tt.requested, MaxPerBlock))
			require.Equal(t, tt.requested > MaxPerBlock, plan.Truncated())
			require.Nil(t, plan.ForEachKeys)
			for i, item := range plan.Items {
				name, value := plan.Variable(item)
				require.Equal(t, KindCount, name)
				require.True(t, cty.NumberIntVal(int64(i)).RawEquals(item.Key))
				require.True(t, item.Key.RawEquals(value.GetAttr("index")))
			}
			if tt.unresolved {
				name, value := plan.Variable(Item{})
				require.Equal(t, KindCount, name)
				require.True(t, cty.UnknownVal(cty.Number).RawEquals(value.GetAttr("index")))
			}
		})
	}
}

func TestResolveForEach(t *testing.T) {
	unknown := cty.UnknownVal(cty.String)
	marked := cty.StringVal("secret").Mark("sensitive")
	for _, tt := range []struct {
		name       string
		input      cty.Value
		unresolved bool
		keys       []string
	}{
		{"object", cty.ObjectVal(map[string]cty.Value{"b": cty.NumberIntVal(2), "a": cty.NumberIntVal(1)}), false, []string{"a", "b"}},
		{"map with unknown value", cty.MapVal(map[string]cty.Value{"a": unknown}), false, []string{"a"}},
		{"map with marked value", cty.MapVal(map[string]cty.Value{"a": marked}), false, []string{"a"}},
		{"string set", cty.SetVal([]cty.Value{cty.StringVal("b"), cty.StringVal("a")}), false, []string{"a", "b"}},
		{"empty object", cty.EmptyObjectVal, false, nil},
		{"empty map", cty.MapValEmpty(cty.String), false, nil},
		{"empty string set", cty.SetValEmpty(cty.String), false, nil},
		// The evaluator accepts empty sets before validating element keys.
		{"empty numeric set", cty.SetValEmpty(cty.Number), false, nil},
		{"numeric set", cty.SetVal([]cty.Value{cty.NumberIntVal(1)}), true, nil},
		{"set with unknown key", cty.SetVal([]cty.Value{unknown}), true, nil},
		{"set with null key", cty.SetVal([]cty.Value{cty.NullVal(cty.String)}), true, nil},
		{"tuple", cty.TupleVal([]cty.Value{cty.StringVal("a")}), true, nil},
		{"list", cty.ListVal([]cty.Value{cty.StringVal("a")}), true, nil},
		{"null", cty.NullVal(cty.Map(cty.String)), true, nil},
		{"unknown", cty.UnknownVal(cty.Map(cty.String)), true, nil},
		{"dynamic", cty.DynamicVal, true, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"input": tt.input}}
			plan := resolve(t, "for_each = input", ctx, 512)
			require.Equal(t, KindForEach, plan.Kind)
			require.Equal(t, tt.unresolved, plan.Unresolved)
			require.Equal(t, len(tt.keys), plan.Requested)
			require.Len(t, plan.Items, len(tt.keys))
			require.False(t, plan.Truncated())
			require.Nil(t, plan.ForEachKeys)
			for i, item := range plan.Items {
				require.Equal(t, cty.StringVal(tt.keys[i]), item.Key)
				name, value := plan.Variable(item)
				require.Equal(t, "each", name)
				require.True(t, item.Key.RawEquals(value.GetAttr("key")))
				var want cty.Value
				switch {
				case tt.input.Type().IsSetType():
					want = item.Key
				case tt.input.Type().IsObjectType():
					want = tt.input.GetAttr(tt.keys[i])
				default:
					want = tt.input.Index(item.Key)
				}
				require.True(t, want.RawEquals(value.GetAttr("value")), "%#v", value)
			}
			if tt.unresolved {
				name, value := plan.Variable(Item{})
				require.Equal(t, "each", name)
				require.True(t, cty.UnknownVal(cty.String).RawEquals(value.GetAttr("key")))
				require.True(t, cty.DynamicVal.RawEquals(value.GetAttr("value")))
			}
		})
	}
	plan := resolve(t, "for_each = missing", nil, 512)
	require.True(t, plan.Unresolved)
	require.Empty(t, plan.Items)
}

func TestResolveForEachTruncatedShapes(t *testing.T) {
	const maxShape = 512
	for _, n := range []int{MaxPerBlock, MaxPerBlock + 1, maxShape, maxShape + 1} {
		for _, set := range []bool{false, true} {
			t.Run(fmt.Sprintf("size=%d/set=%v", n, set), func(t *testing.T) {
				values := make(map[string]cty.Value, n)
				setValues := make([]cty.Value, n)
				for i := range n {
					key := fmt.Sprintf("k%04d", i)
					values[key] = cty.NumberIntVal(int64(i))
					setValues[i] = cty.StringVal(key)
				}
				input := cty.MapVal(values)
				if set {
					input = cty.SetVal(setValues)
				}
				ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"input": input}}
				plan := resolve(t, "for_each = input", ctx, maxShape)
				require.False(t, plan.Unresolved)
				require.Equal(t, n, plan.Requested)
				require.Len(t, plan.Items, MaxPerBlock)
				require.Equal(t, n > MaxPerBlock, plan.Truncated())
				if n > MaxPerBlock && n <= maxShape {
					require.Len(t, plan.ForEachKeys, n)
					for i, key := range plan.ForEachKeys {
						require.Equal(t, cty.StringVal(fmt.Sprintf("k%04d", i)), key)
					}
				} else {
					require.Nil(t, plan.ForEachKeys)
				}
				require.Equal(t, cty.StringVal("k0049"), plan.Items[MaxPerBlock-1].Key)
			})
		}
	}
}

func TestResolveCountPrecedenceAndNoExpansion(t *testing.T) {
	for _, expr := range []string{"0", "missing"} {
		plan := resolve(t, "count = "+expr+"\nfor_each = { a = 1 }", nil, 512)
		require.Equal(t, KindCount, plan.Kind)
		require.Empty(t, plan.Items)
		require.Equal(t, expr == "missing", plan.Unresolved)
	}
	plan := resolve(t, `name = "single"`, nil, 512)
	require.Empty(t, plan.Kind)
	require.False(t, plan.Unresolved)
	require.False(t, plan.Truncated())
	name, value := plan.Variable(Item{})
	require.Empty(t, name)
	require.Equal(t, cty.NilVal, value)
}
