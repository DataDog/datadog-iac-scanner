/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dynamicblock

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func dynamicBlock(t *testing.T, forEach string) *hclsyntax.Block {
	t.Helper()
	src := `dynamic "ingress" {
  for_each = ` + forEach + `
  content {}
}`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	return file.Body.(*hclsyntax.Body).Blocks[0]
}

func listOf(n int) cty.Value {
	elems := make([]cty.Value, n)
	for i := range elems {
		elems[i] = cty.NumberIntVal(int64(i))
	}
	return cty.TupleVal(elems)
}

// A resolved for_each yields every block it declares, in order, however many.
func TestExpand_YieldsEveryBlock(t *testing.T) {
	const n = 5000
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"items": listOf(n)}}
	got := Expand(dynamicBlock(t, "items"), ctx)
	require.True(t, got.Resolved)
	require.Len(t, got.Iterators, n)
	require.True(t, got.Iterators[n-1].GetAttr("value").RawEquals(cty.NumberIntVal(n-1)))
}

func TestExpand_UnresolvedStaysAsWritten(t *testing.T) {
	got := Expand(dynamicBlock(t, "var.missing"), &hcl.EvalContext{})
	require.False(t, got.Resolved)
	require.Empty(t, got.Iterators)
}
