/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package instances resolves Terraform count and for_each expressions into
// instance plans, without evaluating block bodies.
package instances

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	// KindCount and KindForEach name the meta-argument a block expands by.
	KindCount   = "count"
	KindForEach = "for_each"
)

// Item is one instance's index or collection key and, for for_each, its value.
type Item struct {
	Key, Value cty.Value
}

// Plan describes an expansion independently of the caller's evaluation context.
type Plan struct {
	// Kind is empty for a block without count or for_each.
	Kind string
	// Unresolved means the expression failed or its instance keys are unknown
	// or invalid. No concrete Items are returned in this case.
	Unresolved bool
	Items      []Item
}

// Attributes picks the count and for_each expressions of an HCL body.
func Attributes(body *hclsyntax.Body) (count, forEach hcl.Expression) {
	if attr, ok := body.Attributes[KindCount]; ok {
		count = attr.Expr
	}
	if attr, ok := body.Attributes[KindForEach]; ok {
		forEach = attr.Expr
	}
	return count, forEach
}

// Resolve expands the supplied expressions (nil when absent). Count takes
// precedence if both are present, matching the module evaluator's fallback for
// invalid configurations. Every known instance is expanded: a cap would leave
// instances without their real address and their findings unreported. Values
// retain their cty marks, including marks on each.value.
func Resolve(count, forEach hcl.Expression, ctx *hcl.EvalContext) Plan {
	if count != nil {
		return resolveCount(count, ctx)
	}
	if forEach != nil {
		return resolveForEach(forEach, ctx)
	}
	return Plan{}
}

func resolveCount(expr hcl.Expression, ctx *hcl.EvalContext) Plan {
	v, diags := expr.Value(ctx)
	n, ok := 0, false
	if !diags.HasErrors() {
		n, ok = ctyutil.LiteralInt(v)
	}
	if !ok {
		return Plan{Kind: KindCount, Unresolved: true}
	}
	if n <= 0 {
		return Plan{Kind: KindCount}
	}
	items := make([]Item, n)
	for i := range items {
		index := cty.NumberIntVal(int64(i))
		items[i] = Item{Key: index, Value: index}
	}
	return Plan{Kind: KindCount, Items: items}
}

func resolveForEach(expr hcl.Expression, ctx *hcl.EvalContext) Plan {
	unknown := Plan{Kind: KindForEach, Unresolved: true}
	v, diags := expr.Value(ctx)
	if diags.HasErrors() || !ForEachCollection(v) {
		return unknown
	}
	if v.LengthInt() == 0 {
		return Plan{Kind: KindForEach}
	}
	items := make([]Item, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		key, value := it.Element()
		if _, ok := ctyutil.ConcreteString(key); !ok {
			// A collection with any key that is not a concrete string is not a
			// for_each Terraform itself would accept; resolve it as unknown.
			return Plan{Kind: KindForEach, Unresolved: true}
		}
		items = append(items, Item{Key: key, Value: value})
	}
	return Plan{Kind: KindForEach, Items: items}
}

// ForEachCollection reports whether v is a known, non-null map, object or set
// with known length. Keys are validated during expansion; values may be unknown.
func ForEachCollection(v cty.Value) bool {
	if !ctyutil.Materialized(v) || !v.CanIterateElements() || !v.Length().IsKnown() {
		return false
	}
	t := v.Type()
	return t.IsObjectType() || t.IsMapType() || t.IsSetType()
}

// Variable returns the count.index or each.key/each.value binding for item.
// For an unresolved plan, item is ignored and the binding is unknown. For a
// block without either meta-argument, it returns an empty name and cty.NilVal.
func (p *Plan) Variable(item Item) (name string, value cty.Value) {
	if p.Kind == KindCount {
		index := item.Key
		if p.Unresolved {
			index = cty.UnknownVal(cty.Number)
		}
		return KindCount, cty.ObjectVal(map[string]cty.Value{"index": index})
	}
	if p.Kind == KindForEach {
		key, value := item.Key, item.Value
		if p.Unresolved {
			key, value = cty.UnknownVal(cty.String), cty.DynamicVal
		}
		return "each", cty.ObjectVal(map[string]cty.Value{"key": key, "value": value})
	}
	return "", cty.NilVal
}
