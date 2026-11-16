/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// inputsWithRanges splits the inputs value by key. Each key keeps the range
// of the item setting it when the expression shows one, the attribute's
// range otherwise.
func inputsWithRanges(attr *hclsyntax.Attribute, value cty.Value) map[string]Input {
	if value == cty.NilVal || !value.IsKnown() || value.IsNull() {
		return nil
	}
	ty := value.Type()
	if !ty.IsObjectType() && !ty.IsMapType() {
		return nil
	}
	inputs := map[string]Input{}
	for it := value.ElementIterator(); it.Next(); {
		k, v := it.Element()
		name, ok := knownString(k)
		if !ok {
			continue
		}
		item, found := findItem(attr.Expr, name)
		if !found {
			inputs[name] = Input{Value: v, Range: attr.SrcRange}
			continue
		}
		inputs[name] = Input{
			Value:     v,
			Range:     hcl.RangeBetween(item.KeyExpr.Range(), item.ValueExpr.Range()),
			ValuesKey: valuesKey(item.ValueExpr),
		}
	}
	return inputs
}

// findItem finds the object item setting key in an object constructor, or
// in the object constructors merge() combines, the last one winning.
func findItem(expr hclsyntax.Expression, key string) (hclsyntax.ObjectConsItem, bool) {
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsExpr:
		var found hclsyntax.ObjectConsItem
		ok := false
		for _, item := range e.Items {
			if objectKey(item.KeyExpr) == key {
				found, ok = item, true
			}
		}
		return found, ok
	case *hclsyntax.FunctionCallExpr:
		if e.Name != "merge" {
			return hclsyntax.ObjectConsItem{}, false
		}
		for i := len(e.Args) - 1; i >= 0; i-- {
			if item, ok := findItem(e.Args[i], key); ok {
				return item, true
			}
		}
	case *hclsyntax.ParenthesesExpr:
		return findItem(e.Expression, key)
	}
	return hclsyntax.ObjectConsItem{}, false
}

// valuesKey is the stack value expr reads as is: values.<key>.
func valuesKey(expr hclsyntax.Expression) string {
	traversal, ok := expr.(*hclsyntax.ScopeTraversalExpr)
	if !ok || traversal.Traversal.RootName() != "values" || len(traversal.Traversal) != 2 {
		return ""
	}
	if attr, ok := traversal.Traversal[1].(hcl.TraverseAttr); ok {
		return attr.Name
	}
	return ""
}

// objectKey is an object item's key when it is static.
func objectKey(expr hclsyntax.Expression) string {
	if wrapped, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		if name := hcl.ExprAsKeyword(wrapped.Wrapped); name != "" && !wrapped.ForceNonLiteral {
			return name
		}
		expr = wrapped.Wrapped
	}
	value, diags := expr.Value(nil)
	if diags.HasErrors() {
		return ""
	}
	name, _ := knownString(value)
	return name
}
