/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"math"
	"math/big"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// expansionState is what a count or for_each argument resolved to.
type expansionState int

const (
	// expansionKnown is a valid count or for_each whose every instance is known.
	expansionKnown expansionState = iota
	// expansionNotKnown is an argument that depends on values evaluation does
	// not have, such as a computed attribute; Terraform would only know it
	// at apply time.
	expansionNotKnown
	// expansionInvalid is an argument Terraform rejects: a null, negative or
	// fractional count, or a for_each that is not a map or a set of strings.
	expansionInvalid
)

// countValue resolves a count argument as Terraform does: a whole,
// non-negative number, converted from a string if need be.
func countValue(expr hclsyntax.Expression, ctx *hcl.EvalContext) (int, expansionState) {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() {
		return 0, expansionNotKnown
	}
	v, _ = v.Unmark()
	if v.IsNull() {
		return 0, expansionInvalid
	}
	n, err := convert.Convert(v, cty.Number)
	if err != nil || !n.IsKnown() || n.IsNull() {
		return 0, expansionInvalid
	}
	bf := n.AsBigFloat()
	if !bf.IsInt() || bf.Sign() < 0 {
		return 0, expansionInvalid
	}
	i, acc := bf.Int64()
	if acc != big.Exact || i > math.MaxInt32 {
		return 0, expansionInvalid
	}
	return int(i), expansionKnown
}

// forEachValue resolves a for_each argument as Terraform does: a map, an
// object, or a set of strings, whose keys are all known.
func forEachValue(expr hclsyntax.Expression, ctx *hcl.EvalContext) (cty.Value, expansionState) {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() {
		return cty.NilVal, expansionNotKnown
	}
	v, _ = v.UnmarkDeep()
	if v.IsNull() {
		return cty.NilVal, expansionInvalid
	}
	t := v.Type()
	switch {
	case t.IsMapType() || t.IsObjectType():
		return v, expansionKnown
	case t.IsSetType():
		if !v.IsWhollyKnown() {
			return cty.NilVal, expansionNotKnown
		}
		et := t.ElementType()
		if et != cty.String && et != cty.DynamicPseudoType && v.LengthInt() > 0 {
			return cty.NilVal, expansionInvalid
		}
		for it := v.ElementIterator(); it.Next(); {
			k, _ := it.Element()
			if k.IsNull() || k.Type() != cty.String {
				return cty.NilVal, expansionInvalid
			}
		}
		return v, expansionKnown
	}
	return cty.NilVal, expansionInvalid
}
