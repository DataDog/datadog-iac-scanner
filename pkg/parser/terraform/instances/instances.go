/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package instances resolves Terraform count and for_each expressions into
// instance plans, without evaluating block bodies.
package instances

import (
	"context"

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
	// or invalid. No concrete instances are returned in this case.
	Unresolved bool
	// count is the size of a resolved count. Its instances are produced by At,
	// so a large count is not allocated before the caller can stop.
	count int
	// Items holds a resolved for_each. A count leaves it empty.
	Items []Item
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
// invalid configurations. Values retain their cty marks, including marks on
// each.value. A canceled scanCtx stops for_each before the instance slice is
// allocated and during enumeration; the plan is then unresolved so callers do
// not treat the interruption as a known-empty expansion.
func Resolve(scanCtx context.Context, count, forEach hcl.Expression, evalCtx *hcl.EvalContext) Plan {
	if count != nil {
		return resolveCount(count, evalCtx)
	}
	if forEach != nil {
		return resolveForEach(scanCtx, forEach, evalCtx)
	}
	return Plan{}
}

func countValue(expr hcl.Expression, ctx *hcl.EvalContext) (int, bool) {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return 0, false
	}
	return ctyutil.LiteralInt(v)
}

func resolveCount(expr hcl.Expression, ctx *hcl.EvalContext) Plan {
	n, ok := countValue(expr, ctx)
	if !ok {
		return Plan{Kind: KindCount, Unresolved: true}
	}
	if n <= 0 {
		return Plan{Kind: KindCount}
	}
	return Plan{Kind: KindCount, count: n}
}

// Len is the number of concrete instances. A count reports its size without
// allocating them.
func (p Plan) Len() int {
	if p.Kind == KindCount && !p.Unresolved {
		return p.count
	}
	return len(p.Items)
}

// At returns instance i. i is valid in [0, Len).
func (p Plan) At(i int) Item {
	if p.Kind == KindCount && !p.Unresolved {
		index := cty.NumberIntVal(int64(i))
		return Item{Key: index, Value: index}
	}
	return p.Items[i]
}

func resolveForEach(scanCtx context.Context, expr hcl.Expression, evalCtx *hcl.EvalContext) Plan {
	unknown := Plan{Kind: KindForEach, Unresolved: true}
	if scanCtx.Err() != nil {
		return unknown
	}
	v, diags := expr.Value(evalCtx)
	if diags.HasErrors() || !ForEachCollection(v) {
		return unknown
	}
	if v.LengthInt() == 0 {
		return Plan{Kind: KindForEach}
	}
	if scanCtx.Err() != nil {
		return unknown
	}
	// Grown with append, not sized from the collection: the caller stops
	// enumerating as soon as the scan context is done.
	var items []Item
	for it := v.ElementIterator(); it.Next(); {
		if scanCtx.Err() != nil {
			return unknown
		}
		key, value := it.Element()
		if _, ok := ctyutil.ConcreteString(key); !ok {
			// A collection with any key that is not a concrete string is not a
			// for_each Terraform itself would accept; resolve it as unknown.
			return unknown
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
