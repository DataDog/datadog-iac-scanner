/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package instances

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func resolve(t *testing.T, src string, ctx *hcl.EvalContext) Plan {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "test.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	count, forEach := Attributes(file.Body.(*hclsyntax.Body))
	return Resolve(context.Background(), count, forEach, ctx)
}

func TestResolveCount(t *testing.T) {
	for _, tt := range []struct {
		expr      string
		instances int
		state     State
	}{
		{"3", 3, Known},
		{`"2"`, 2, Known},
		{"0", 0, Known},
		{"-2", 0, Invalid},
		{"50", 50, Known},
		{"600", 600, Known},
		{"1.5", 0, Invalid},
		{`"1.5"`, 0, Invalid},
		{`"invalid"`, 0, Invalid},
		{"true", 0, Invalid},
		{"null", 0, Invalid},
		{"9223372036854775808", 0, Invalid},
		{"input", 0, Unknown},
		{"missing", 0, Unknown},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"input": cty.UnknownVal(cty.Number)}}
			plan := resolve(t, "count = "+tt.expr, ctx)
			require.Equal(t, KindCount, plan.Kind)
			require.Equal(t, tt.state, plan.State)
			require.Equal(t, tt.state == Invalid, len(plan.Diagnostics) > 0)
			require.Equal(t, cty.NilVal, plan.collection)
			require.Equal(t, tt.instances, plan.Len())
			i := 0
			for item := range plan.Instances() {
				name, value := plan.Variable(item)
				require.Equal(t, KindCount, name)
				require.True(t, cty.NumberIntVal(int64(i)).RawEquals(item.Key))
				require.True(t, item.Key.RawEquals(value.GetAttr("index")))
				i++
			}
			if tt.state != Known {
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
		name  string
		input cty.Value
		state State
		keys  []string
	}{
		{"object", cty.ObjectVal(map[string]cty.Value{"b": cty.NumberIntVal(2), "a": cty.NumberIntVal(1)}), Known, []string{"a", "b"}},
		{"map with unknown value", cty.MapVal(map[string]cty.Value{"a": unknown}), Known, []string{"a"}},
		{"map with marked value", cty.MapVal(map[string]cty.Value{"a": marked}), Known, []string{"a"}},
		{"string set", cty.SetVal([]cty.Value{cty.StringVal("b"), cty.StringVal("a")}), Known, []string{"a", "b"}},
		{"empty object", cty.EmptyObjectVal, Known, nil},
		{"empty map", cty.MapValEmpty(cty.String), Known, nil},
		{"empty string set", cty.SetValEmpty(cty.String), Known, nil},
		// The evaluator accepts empty sets before validating element keys.
		{"empty numeric set", cty.SetValEmpty(cty.Number), Known, nil},
		{"numeric set", cty.SetVal([]cty.Value{cty.NumberIntVal(1)}), Invalid, nil},
		{"set with unknown key", cty.SetVal([]cty.Value{unknown}), Unknown, nil},
		{"set with null key", cty.SetVal([]cty.Value{cty.NullVal(cty.String)}), Invalid, nil},
		{"tuple", cty.TupleVal([]cty.Value{cty.StringVal("a")}), Invalid, nil},
		{"list", cty.ListVal([]cty.Value{cty.StringVal("a")}), Invalid, nil},
		{"null", cty.NullVal(cty.Map(cty.String)), Invalid, nil},
		{"unknown", cty.UnknownVal(cty.Map(cty.String)), Unknown, nil},
		{"dynamic", cty.DynamicVal, Unknown, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"input": tt.input}}
			plan := resolve(t, "for_each = input", ctx)
			require.Equal(t, KindForEach, plan.Kind)
			require.Equal(t, tt.state, plan.State)
			require.Equal(t, tt.state == Invalid, len(plan.Diagnostics) > 0)
			require.Equal(t, len(tt.keys), plan.Len())
			i := 0
			for item := range plan.Instances() {
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
				i++
			}
			if tt.state != Known {
				name, value := plan.Variable(Item{})
				require.Equal(t, "each", name)
				require.True(t, cty.UnknownVal(cty.String).RawEquals(value.GetAttr("key")))
				require.True(t, cty.DynamicVal.RawEquals(value.GetAttr("value")))
			}
		})
	}
	plan := resolve(t, "for_each = missing", nil)
	require.NotEqual(t, Known, plan.State)
	require.Equal(t, cty.NilVal, plan.collection)
}

// Every instance of a collection is expanded, however large.
func TestResolveForEachExpandsEveryInstance(t *testing.T) {
	for _, n := range []int{50, 51, 512, 1200} {
		t.Run(fmt.Sprintf("size=%d", n), func(t *testing.T) {
			values := make(map[string]cty.Value, n)
			for i := range n {
				values[fmt.Sprintf("k%04d", i)] = cty.NumberIntVal(int64(i))
			}
			ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"input": cty.MapVal(values)}}
			plan := resolve(t, "for_each = input", ctx)
			require.Equal(t, Known, plan.State)
			require.Equal(t, n, plan.Len())
			i := 0
			for item := range plan.Instances() {
				require.Equal(t, cty.StringVal(fmt.Sprintf("k%04d", i)), item.Key)
				i++
			}
		})
	}
}

func TestResolveForEach_CanceledContextDoesNotAllocate(t *testing.T) {
	n := 10_000
	values := make(map[string]cty.Value, n)
	for i := range n {
		values[fmt.Sprintf("k%04d", i)] = cty.NumberIntVal(int64(i))
	}
	evalCtx := &hcl.EvalContext{Variables: map[string]cty.Value{"input": cty.MapVal(values)}}
	file, diags := hclsyntax.ParseConfig([]byte("for_each = input"), "test.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	count, forEach := Attributes(file.Body.(*hclsyntax.Body))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	plan := Resolve(canceled, count, forEach, evalCtx)
	require.Equal(t, KindForEach, plan.Kind)
	require.NotEqual(t, Known, plan.State)
	require.Equal(t, cty.NilVal, plan.collection)
}

func TestResolveConflictingAndAbsentExpansion(t *testing.T) {
	for _, expr := range []string{"0", "missing"} {
		plan := resolve(t, "count = "+expr+"\nfor_each = { a = 1 }", nil)
		require.Equal(t, KindCount, plan.Kind)
		require.Equal(t, cty.NilVal, plan.collection)
		require.Equal(t, Invalid, plan.State)
		require.NotEmpty(t, plan.Diagnostics)
	}
	plan := resolve(t, `name = "single"`, nil)
	require.Empty(t, plan.Kind)
	require.Equal(t, Known, plan.State)
	name, value := plan.Variable(Item{})
	require.Empty(t, name)
	require.Equal(t, cty.NilVal, value)
}

// Planning and early termination never materialize an uncapped count inventory.
func TestResolveCountLazyIteration(t *testing.T) {
	plan := resolve(t, "count = 1000000000000000", nil)
	require.Equal(t, Known, plan.State)
	require.Equal(t, 1_000_000_000_000_000, plan.Len())
	visited := 0
	for item := range plan.Instances() {
		require.True(t, cty.NumberIntVal(int64(visited)).RawEquals(item.Key))
		visited++
		if visited == 3 {
			break
		}
	}
	require.Equal(t, 3, visited)
	require.Equal(t, 1_000_000_000_000_000, plan.Len())
}
