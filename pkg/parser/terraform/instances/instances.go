/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package instances resolves Terraform count and for_each expressions into
// bounded instance plans, without evaluating block bodies or charging budgets.
package instances

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// MaxPerBlock caps the instances expanded from one count or for_each block.
const MaxPerBlock = 50

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
	// Requested is the full instance count before the per-block cap, when known.
	Requested int
	Items     []Item
	// ForEachKeys retains all keys only for truncated collections small enough
	// to preserve their output shape. Otherwise it is nil.
	ForEachKeys []cty.Value
}

// Truncated reports whether a known expansion exceeded the per-block cap.
func (p *Plan) Truncated() bool { return p.Requested > MaxPerBlock }

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
// invalid configurations. maxShape bounds retention of truncated for_each keys;
// callers may use these keys to pad unevaluated outputs with unknown values.
// Values retain their cty marks, including marks on each.value.
func Resolve(count, forEach hcl.Expression, ctx *hcl.EvalContext, maxShape int) Plan {
	if count != nil {
		return resolveCount(count, ctx)
	}
	if forEach != nil {
		return resolveForEach(forEach, ctx, maxShape)
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
	requested := max(n, 0)
	items := make([]Item, min(requested, MaxPerBlock))
	for i := range items {
		index := cty.NumberIntVal(int64(i))
		items[i] = Item{Key: index, Value: index}
	}
	return Plan{Kind: KindCount, Requested: requested, Items: items}
}

func resolveForEach(expr hcl.Expression, ctx *hcl.EvalContext, maxShape int) Plan {
	unknown := Plan{Kind: KindForEach, Unresolved: true}
	v, diags := expr.Value(ctx)
	if diags.HasErrors() || !ForEachCollection(v) {
		return unknown
	}
	requested := v.LengthInt()
	if requested == 0 {
		return Plan{Kind: KindForEach}
	}
	plan, ok := expandForEach(v, requested, maxShape)
	if !ok {
		return unknown
	}
	return plan
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

func expandForEach(v cty.Value, requested, maxShape int) (Plan, bool) {
	expandTo := min(requested, MaxPerBlock)
	keepKeys := requested > MaxPerBlock && requested <= maxShape
	plan := Plan{Kind: KindForEach, Requested: requested, Items: make([]Item, 0, expandTo)}
	if keepKeys {
		plan.ForEachKeys = make([]cty.Value, 0, requested)
	}
	for it := v.ElementIterator(); it.Next(); {
		key, value := it.Element()
		if _, ok := ctyutil.ConcreteString(key); !ok {
			return Plan{}, false
		}
		if keepKeys {
			plan.ForEachKeys = append(plan.ForEachKeys, key)
		}
		if len(plan.Items) < expandTo {
			plan.Items = append(plan.Items, Item{Key: key, Value: value})
			continue
		}
		if !keepKeys {
			break
		}
	}
	return plan, true
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
