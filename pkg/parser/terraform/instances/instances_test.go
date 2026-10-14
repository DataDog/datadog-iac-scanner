/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package instances

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func body(t *testing.T, src string) *hclsyntax.Body {
	t.Helper()
	f, diags := hclsyntax.ParseConfig([]byte(src), "t.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	return f.Body.(*hclsyntax.Body)
}

func resolve(t *testing.T, src string, ctx *hcl.EvalContext) Plan {
	t.Helper()
	count, forEach := Attributes(body(t, src))
	return Resolve(count, forEach, ctx)
}

func TestResolveCount(t *testing.T) {
	plan := resolve(t, "count = 3", nil)
	require.Equal(t, KindCount, plan.Kind)
	require.True(t, plan.Expands())
	require.Len(t, plan.Items, 3)
	name, value := plan.Variable(plan.Items[2])
	require.Equal(t, "count", name)
	require.True(t, cty.NumberIntVal(2).Equals(value.GetAttr("index")).True())

	require.Empty(t, resolve(t, "count = 0", nil).Items)
	require.True(t, resolve(t, "count = 0", nil).Expands())
	require.Empty(t, resolve(t, "count = -2", nil).Items)
}

func TestResolveCountTruncates(t *testing.T) {
	plan := resolve(t, "count = 80", nil)
	require.Len(t, plan.Items, MaxPerBlock)
	require.Equal(t, 80, plan.Requested)
	require.True(t, plan.Truncated())
}

func TestResolveForEach(t *testing.T) {
	plan := resolve(t, `for_each = { a = 1, b = 2 }`, nil)
	require.Equal(t, KindForEach, plan.Kind)
	require.Len(t, plan.Items, 2)
	name, value := plan.Variable(plan.Items[0])
	require.Equal(t, "each", name)
	require.Equal(t, cty.StringVal("a"), value.GetAttr("key"))
	require.True(t, cty.NumberIntVal(1).RawEquals(value.GetAttr("value")) || cty.NumberIntVal(1).Equals(value.GetAttr("value")).True())

	set := resolve(t, `for_each = var.s`, &hcl.EvalContext{Variables: map[string]cty.Value{
		"var": cty.ObjectVal(map[string]cty.Value{"s": cty.SetVal([]cty.Value{cty.StringVal("x")})}),
	}})
	require.Len(t, set.Items, 1)
	_, v := set.Variable(set.Items[0])
	require.Equal(t, v.GetAttr("key"), v.GetAttr("value"))

	require.Empty(t, resolve(t, `for_each = {}`, nil).Items)
}

func TestResolveUnresolved(t *testing.T) {
	for _, src := range []string{
		"count = var.n",
		`count = "x"`,
		"for_each = var.m",
		"for_each = [1, 2]",
	} {
		plan := resolve(t, src, nil)
		require.True(t, plan.Unresolved, src)
		require.False(t, plan.Expands(), src)
	}
}

func TestResolveNeither(t *testing.T) {
	plan := resolve(t, `name = "x"`, nil)
	require.Empty(t, plan.Kind)
	require.False(t, plan.Expands())
}

func TestReadsInstance(t *testing.T) {
	require.True(t, ReadsInstance(body(t, `name = "n-${count.index}"`)))
	require.True(t, ReadsInstance(body(t, "block {\n  v = each.value\n}")))
	require.False(t, ReadsInstance(body(t, `name = "n"`+"\ncount = 2")))
	require.False(t, ReadsInstance(body(t, `name = local.count`)))
}

func TestReadsInstanceExpr(t *testing.T) {
	b := body(t, "a = count.index\nb = 1")
	require.True(t, ReadsInstanceExpr(b.Attributes["a"].Expr))
	require.False(t, ReadsInstanceExpr(b.Attributes["b"].Expr))
}
