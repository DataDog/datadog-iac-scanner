/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package instances resolves the count and for_each of a resource or data
// block into the instances Terraform creates from it. The plain converter and
// the module evaluator share it so both expand a block the same way.
package instances

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// MaxPerBlock caps the instances one count or for_each block is expanded into.
// A block asking for more keeps the first MaxPerBlock instances, and is also
// scanned as written.
const MaxPerBlock = 50

// MaxPerFile caps the instances, beyond each block's first, that the resources
// and data of one file expand into, so many blocks that each expand cannot
// multiply into an unbounded number of documents. A block that does not fit
// stays as written.
const MaxPerFile = 5000

const (
	// KindCount and KindForEach name the meta-argument a block expands by.
	KindCount   = "count"
	KindForEach = "for_each"

	// eachVariable is the name a for_each instance reads its key and value by.
	eachVariable = "each"
)

// Item is one instance of an expanded block.
type Item struct {
	// Key is the index of a count instance or the key of a for_each instance.
	Key cty.Value
	// Value is the element of a for_each instance; it is Key for a set.
	Value cty.Value
}

// Plan is how a block's count or for_each expands.
type Plan struct {
	// Kind is KindCount or KindForEach, or empty for a block that has neither.
	Kind string
	// Unresolved is set when the expansion cannot be determined, so the block
	// stands for an unknown number of instances and is read as written.
	Unresolved bool
	// Requested is the number of instances asked for, whether or not they are
	// all in Items.
	Requested int
	// Items holds the instances, at most MaxPerBlock of them.
	Items []Item
}

// Truncated reports whether the block asks for more instances than Items holds.
func (p Plan) Truncated() bool { return p.Requested > len(p.Items) }

// Expands reports whether the block resolves to instances that can be told
// apart, as opposed to a block without count and for_each or an unresolved one.
func (p Plan) Expands() bool { return p.Kind != "" && !p.Unresolved }

// Resolve expands a block from its count and for_each expressions, either of
// which is nil when the block does not set it.
func Resolve(count, forEach hcl.Expression, ctx *hcl.EvalContext) Plan {
	if count != nil {
		return resolveCount(count, ctx)
	}
	if forEach != nil {
		return resolveForEach(forEach, ctx)
	}
	return Plan{}
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

func resolveCount(expr hcl.Expression, ctx *hcl.EvalContext) Plan {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return Plan{Kind: KindCount, Unresolved: true}
	}
	n, ok := Count(v)
	if !ok {
		return Plan{Kind: KindCount, Unresolved: true}
	}
	n = max(n, 0)
	plan := Plan{Kind: KindCount, Requested: n, Items: make([]Item, 0, min(n, MaxPerBlock))}
	for i := 0; i < min(n, MaxPerBlock); i++ {
		index := cty.NumberIntVal(int64(i))
		plan.Items = append(plan.Items, Item{Key: index, Value: index})
	}
	return plan
}

func resolveForEach(expr hcl.Expression, ctx *hcl.EvalContext) Plan {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return Plan{Kind: KindForEach, Unresolved: true}
	}
	v, _ = v.UnmarkDeep()
	if !ForEachCollection(v) {
		return Plan{Kind: KindForEach, Unresolved: true}
	}
	plan := Plan{Kind: KindForEach, Requested: v.LengthInt()}
	for it := v.ElementIterator(); it.Next() && len(plan.Items) < MaxPerBlock; {
		key, value := it.Element()
		if _, ok := ctyutil.ConcreteString(key); !ok {
			return Plan{Kind: KindForEach, Unresolved: true}
		}
		plan.Items = append(plan.Items, Item{Key: key, Value: value})
	}
	return plan
}

// Count reports the number a count argument evaluates to.
func Count(v cty.Value) (int, bool) {
	v, _ = v.UnmarkDeep()
	return ctyutil.LiteralInt(v)
}

// ForEachCollection reports whether v is a for_each argument whose keys are
// all known: a map, an object or a set.
func ForEachCollection(v cty.Value) bool {
	if !ctyutil.Materialized(v) || !v.CanIterateElements() || !v.Length().IsKnown() {
		return false
	}
	t := v.Type()
	return t.IsObjectType() || t.IsMapType() || t.IsSetType()
}

// Variable is the name an instance reads its position through, and its value:
// count.index for a count instance, each.key and each.value for a for_each one.
func (p Plan) Variable(item Item) (name string, value cty.Value) {
	if p.Kind == KindCount {
		return KindCount, cty.ObjectVal(map[string]cty.Value{"index": item.Key})
	}
	return eachVariable, cty.ObjectVal(map[string]cty.Value{"key": item.Key, "value": item.Value})
}

// ReadsInstance reports whether any expression under body reads count or each,
// the only way an instance can differ from the others.
func ReadsInstance(body *hclsyntax.Body) bool {
	reads := false
	_ = hclsyntax.VisitAll(body, func(node hclsyntax.Node) hcl.Diagnostics {
		if expr, ok := node.(*hclsyntax.ScopeTraversalExpr); ok {
			switch expr.Traversal.RootName() {
			case KindCount, eachVariable:
				reads = true
			}
		}
		return nil
	})
	return reads
}

// ReadsInstanceExpr is ReadsInstance for expressions that are not HCL syntax,
// such as the values of a JSON configuration.
func ReadsInstanceExpr(exprs ...hcl.Expression) bool {
	for _, expr := range exprs {
		for _, traversal := range expr.Variables() {
			switch traversal.RootName() {
			case KindCount, eachVariable:
				return true
			}
		}
	}
	return false
}
