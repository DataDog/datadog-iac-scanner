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
	"fmt"
	"iter"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/gocty"
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

// State separates established instance keys, unresolved keys and failed expansion.
type State uint8

const (
	Known State = iota
	Unknown
	// Invalid retains either an invalid configuration or an explicitly unsupported operation.
	Invalid
)

// Diagnostic is a frozen expansion error, without an expression or evaluation context.
type Diagnostic struct {
	Summary, Detail string
	Subject         hcl.Range
}

// Plan describes an expansion independently of the caller's evaluation context.
type Plan struct {
	// Kind is empty for a block without count or for_each.
	Kind        string
	State       State
	Diagnostics []Diagnostic
	// count is the size of a resolved count. Its instances are produced lazily,
	// so a large count is not allocated before the caller can stop.
	count int
	// collection shares the immutable for_each value; iteration does not copy it.
	collection cty.Value
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

// Resolve expands the supplied expressions (nil when absent). Conflicting
// meta-arguments and invalid values retain a producer diagnostic. Iteration
// preserves marks on each.value and shares the immutable collection. A canceled
// scanCtx yields Unknown rather than a known-empty expansion.
func Resolve(scanCtx context.Context, count, forEach hcl.Expression, evalCtx *hcl.EvalContext) (plan Plan) {
	// An expression or validation pass may finish after cancellation. Never
	// publish that interrupted work as a completed empty or invalid inventory.
	defer func() {
		if scanCtx.Err() != nil {
			plan = Plan{Kind: plan.Kind, State: Unknown}
		}
	}()

	if count != nil && forEach != nil {
		return invalidPlan(KindCount, count, "count and for_each cannot be used together.")
	}
	if scanCtx.Err() != nil {
		kind := ""
		if count != nil {
			kind = KindCount
		} else if forEach != nil {
			kind = KindForEach
		}
		return Plan{Kind: kind, State: Unknown}
	}
	if count != nil {
		return resolveCount(count, evalCtx)
	}
	if forEach != nil {
		return resolveForEach(scanCtx, forEach, evalCtx)
	}
	return Plan{}
}

func invalidPlan(kind string, expr hcl.Expression, detail string) Plan {
	return Plan{Kind: kind, State: Invalid, Diagnostics: []Diagnostic{{
		Summary: "Invalid " + kind + " argument", Detail: detail, Subject: expr.Range(),
	}}}
}

func expressionPlan(kind string, expr hcl.Expression, ctx *hcl.EvalContext) (cty.Value, Plan) {
	value, diagnostics := partial.Evaluate(expr, ctx)
	plan := Plan{Kind: kind}
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity != hcl.DiagError {
			continue
		}
		subject := expr.Range()
		if diagnostic.Subject != nil {
			subject = *diagnostic.Subject
		}
		plan.Diagnostics = append(plan.Diagnostics, Diagnostic{Summary: diagnostic.Summary, Detail: diagnostic.Detail, Subject: subject})
	}
	if len(plan.Diagnostics) > 0 {
		plan.State = Invalid
	}
	return value, plan
}

func resolveCount(expr hcl.Expression, ctx *hcl.EvalContext) Plan {
	value, plan := expressionPlan(KindCount, expr, ctx)
	if plan.State == Invalid {
		return plan
	}
	value, _ = value.Unmark()
	number, err := convert.Convert(value, cty.Number)
	if err != nil {
		return invalidPlan(KindCount, expr, "A non-negative whole number is required.")
	}
	if number.IsNull() {
		return invalidPlan(KindCount, expr, "count cannot be null; a non-negative whole number is required.")
	}
	if !number.IsKnown() {
		plan.State = Unknown
		return plan
	}
	var n int
	if err := gocty.FromCtyValue(number, &n); err != nil {
		return invalidPlan(KindCount, expr, fmt.Sprintf("count must fit a non-negative whole number: %s.", err))
	}
	if n < 0 {
		return invalidPlan(KindCount, expr, "count must be greater than or equal to zero.")
	}
	plan.count = n
	return plan
}

// Len reports the number of established instances without allocating them.
func (p *Plan) Len() int {
	if p.State != Known {
		return 0
	}
	if p.Kind == KindCount {
		return p.count
	}
	if p.collection != cty.NilVal {
		return p.collection.LengthInt()
	}
	return 0
}

// Instances visits established keys in deterministic order without retaining a
// second instance inventory. Breaking the range stops even an uncapped count.
func (p *Plan) Instances() iter.Seq[Item] {
	return func(yield func(Item) bool) {
		if p.State != Known {
			return
		}
		if p.Kind == KindCount {
			for i := range p.count {
				key := cty.NumberIntVal(int64(i))
				if !yield(Item{Key: key, Value: key}) {
					return
				}
			}
			return
		}
		if p.collection == cty.NilVal {
			return
		}
		for iterator := p.collection.ElementIterator(); iterator.Next(); {
			key, value := iterator.Element()
			if !yield(Item{Key: key, Value: value}) {
				return
			}
		}
	}
}

func resolveForEach(scanCtx context.Context, expr hcl.Expression, evalCtx *hcl.EvalContext) Plan {
	value, plan := expressionPlan(KindForEach, expr, evalCtx)
	if plan.State == Invalid {
		return plan
	}
	if value.IsMarked() {
		return Plan{Kind: KindForEach, State: Invalid, Diagnostics: []Diagnostic{{
			Summary: "Unsupported for_each expansion",
			Detail:  "The scanner cannot establish the meaning of marked instance keys.", Subject: expr.Range(),
		}}}
	}
	if value.IsNull() {
		return invalidPlan(KindForEach, expr, "for_each cannot be null; a map or set of strings is required.")
	}
	typ := value.Type()
	if typ != cty.DynamicPseudoType && !typ.IsObjectType() && !typ.IsMapType() && !typ.IsSetType() {
		return invalidPlan(KindForEach, expr, "for_each requires a map or set of strings.")
	}
	if !value.IsKnown() || !value.Length().IsKnown() {
		plan.State = Unknown
		return plan
	}
	if value.LengthInt() == 0 {
		return plan
	}
	if typ.IsSetType() {
		return resolveForEachSet(scanCtx, expr, value)
	}
	plan.collection = value
	return plan
}

// Set members are also instance keys, unlike unknown values in a known map.
func resolveForEachSet(ctx context.Context, expr hcl.Expression, value cty.Value) Plan {
	if !value.IsWhollyKnown() {
		return Plan{Kind: KindForEach, State: Unknown}
	}
	if value.Type().ElementType() != cty.String {
		return invalidPlan(KindForEach, expr, "for_each set elements must be strings.")
	}
	for iterator := value.ElementIterator(); iterator.Next(); {
		if ctx.Err() != nil {
			return Plan{Kind: KindForEach, State: Unknown}
		}
		key, _ := iterator.Element()
		if key.IsNull() {
			return invalidPlan(KindForEach, expr, "for_each keys cannot be null.")
		}
	}
	return Plan{Kind: KindForEach, collection: value}
}

// Variable returns the count.index or each.key/each.value binding for item.
// For an unresolved plan, item is ignored and the binding is unknown. For a
// block without either meta-argument, it returns an empty name and cty.NilVal.
func (p *Plan) Variable(item Item) (name string, value cty.Value) {
	if p.Kind == KindCount {
		index := item.Key
		if p.State != Known {
			index = cty.UnknownVal(cty.Number)
		}
		return KindCount, cty.ObjectVal(map[string]cty.Value{"index": index})
	}
	if p.Kind == KindForEach {
		key, value := item.Key, item.Value
		if p.State != Known {
			key, value = cty.UnknownVal(cty.String), cty.DynamicVal
		}
		return "each", cty.ObjectVal(map[string]cty.Value{"key": key, "value": value})
	}
	return "", cty.NilVal
}
