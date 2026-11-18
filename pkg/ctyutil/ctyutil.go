/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package ctyutil

import (
	"math/big"
	"strconv"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Materialized reports whether v is known and non-null. cty's integration methods
// (AsString, LengthInt, ElementIterator, AsValueSlice, …) panic on null even when
// IsWhollyKnown() is true.
func Materialized(v cty.Value) bool {
	return v.IsKnown() && !v.IsNull()
}

// ConcreteString returns a Go string when v is a materialized cty.String.
func ConcreteString(v cty.Value) (string, bool) {
	if !Materialized(v) || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

// StringFromAttribute evaluates attr under ctx and returns a concrete string, or "".
func StringFromAttribute(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) string {
	if attr == nil {
		return ""
	}
	val, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() {
		return ""
	}
	s, ok := ConcreteString(val)
	if !ok {
		return ""
	}
	return s
}

// FormatIndexKey renders a materialized string or number index for HCL traversals.
func FormatIndexKey(key cty.Value) (string, bool) {
	if !Materialized(key) {
		return "", false
	}
	switch key.Type() {
	case cty.String:
		return `["` + key.AsString() + `"]`, true
	case cty.Number:
		return "[" + key.AsBigFloat().Text('f', -1) + "]", true
	default:
		return "", false
	}
}

// LiteralInt parses a materialized number or decimal string as int (e.g. count).
func LiteralInt(v cty.Value) (int, bool) {
	if !Materialized(v) {
		return 0, false
	}
	switch v.Type() {
	case cty.Number:
		bf := v.AsBigFloat()
		if !bf.IsInt() {
			return 0, false
		}
		i, acc := bf.Int64()
		if acc != big.Exact {
			return 0, false
		}
		return int(i), true
	case cty.String:
		n, err := strconv.Atoi(v.AsString())
		return n, err == nil
	default:
		return 0, false
	}
}

// ContainsNestedUnknown reports whether a wholly-known value still contains unknown
// or dynamic-typed elements that must be preserved as source references.
func ContainsNestedUnknown(v cty.Value) bool {
	if v.IsNull() {
		return false
	}
	if !v.IsKnown() || v.Type().HasDynamicTypes() {
		return true
	}
	if !v.Type().IsPrimitiveType() {
		return collectionContainsNestedUnknown(v)
	}
	return false
}

func collectionContainsNestedUnknown(v cty.Value) bool {
	if !Materialized(v) {
		return false
	}
	var elems []cty.Value
	switch {
	case v.Type().IsTupleType() || v.Type().IsListType() || v.Type().IsSetType():
		elems = v.AsValueSlice()
	case v.Type().IsObjectType() || v.Type().IsMapType():
		elems = make([]cty.Value, 0, len(v.AsValueMap()))
		for _, elem := range v.AsValueMap() {
			elems = append(elems, elem)
		}
	default:
		return false
	}
	for _, elem := range elems {
		if nestedUnknown(elem) {
			return true
		}
	}
	return false
}

func nestedUnknown(v cty.Value) bool {
	if v.Type().HasDynamicTypes() || !v.IsKnown() {
		return true
	}
	if v.Type().IsPrimitiveType() {
		return false
	}
	return collectionContainsNestedUnknown(v)
}
