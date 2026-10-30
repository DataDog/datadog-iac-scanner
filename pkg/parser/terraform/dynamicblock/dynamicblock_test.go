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

// Every resolved element is expanded, however many: a cap would leave generated
// blocks without their content and their findings unreported.
func TestExpand_ExpandsEveryElement(t *testing.T) {
	for _, n := range []int{1, 256, 257, 1025} {
		ctx := &hcl.EvalContext{Variables: map[string]cty.Value{"items": listOf(n)}}
		got := Expand(dynamicBlock(t, "items"), ctx)
		require.True(t, got.Resolved)
		require.Len(t, got.Iterators, n)
	}
}

func TestExpand_Unresolved(t *testing.T) {
	got := Expand(dynamicBlock(t, "var.missing"), &hcl.EvalContext{})
	require.False(t, got.Resolved)
	require.Empty(t, got.Iterators)
}
