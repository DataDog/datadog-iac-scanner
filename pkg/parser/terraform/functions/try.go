/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"errors"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/customdecode"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// TryFunc is Terraform's try. A resource or data instance only holds its
// configured attributes, so an argument failing on another of its attributes
// reads one computed at apply and makes the result unknown, as in a plan,
// instead of falling through to the next argument.
var TryFunc = function.New(&function.Spec{
	VarParam: &function.Parameter{Name: "expressions", Type: customdecode.ExpressionClosureType},
	Type: func(args []cty.Value) (cty.Type, error) {
		v, err := try(args)
		if err != nil {
			return cty.NilType, err
		}
		return v.Type(), nil
	},
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return try(args)
	},
})

// CanFunc is Terraform's can, unknown on a computed attribute as TryFunc.
var CanFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "expression", Type: customdecode.ExpressionClosureType}},
	Type:   function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		v, failed := tryValue(customdecode.ExpressionClosureFromVal(args[0]))
		switch {
		case failed:
			return cty.False, nil
		case !v.IsWhollyKnown():
			return cty.UnknownVal(cty.Bool), nil
		}
		return cty.True, nil
	},
})

func try(args []cty.Value) (cty.Value, error) {
	if len(args) == 0 {
		return cty.NilVal, errors.New("at least one argument is required")
	}
	for _, arg := range args {
		v, failed := tryValue(customdecode.ExpressionClosureFromVal(arg))
		if failed {
			continue
		}
		if !v.IsWhollyKnown() {
			return cty.DynamicVal, nil
		}
		return v, nil
	}
	return cty.NilVal, errors.New("no expression succeeded")
}

// tryValue evaluates a try or can argument; failed says it errors, and a read
// of a computed attribute is an unknown value rather than an error.
func tryValue(closure *customdecode.ExpressionClosure) (v cty.Value, failed bool) {
	v, diags := closure.Value()
	if !diags.HasErrors() {
		return v, false
	}
	// An independent error (bad index, type mismatch) must fail even when the
	// expression also mentions a computed attribute. Only a failure explained
	// by a computed instance-attribute read is plan-unknown.
	if definiteEvalFailure(closure.Expression, closure.EvalContext) {
		return cty.NilVal, true
	}
	for _, traversal := range closure.Expression.Variables() {
		if readsComputedAttribute(traversal, closure.EvalContext) {
			return cty.DynamicVal, false
		}
	}
	return cty.NilVal, true
}

// definiteEvalFailure reports errors that are not "this attribute is computed
// at apply": an index outside a known collection length, or a missing key of a
// value the configuration already holds.
func definiteEvalFailure(expr hcl.Expression, ctx *hcl.EvalContext) bool {
	switch e := expr.(type) {
	case *hclsyntax.IndexExpr:
		return indexOutOfRange(e.Collection, e.Key, ctx) ||
			definiteEvalFailure(e.Collection, ctx) || definiteEvalFailure(e.Key, ctx)
	case *hclsyntax.RelativeTraversalExpr:
		return relativeIndexOutOfRange(e, ctx) || definiteEvalFailure(e.Source, ctx)
	case *hclsyntax.ScopeTraversalExpr:
		return missingConfiguredKey(e.Traversal, ctx)
	case *hclsyntax.ConditionalExpr:
		return definiteConditionalFailure(e, ctx)
	case *hclsyntax.ParenthesesExpr:
		return definiteEvalFailure(e.Expression, ctx)
	}
	for _, operand := range operands(expr) {
		if definiteEvalFailure(operand, ctx) {
			return true
		}
	}
	return false
}

// definiteConditionalFailure walks only the selected branch when the
// condition is a known bool; otherwise only the condition itself.
func definiteConditionalFailure(e *hclsyntax.ConditionalExpr, ctx *hcl.EvalContext) bool {
	cond, diags := e.Condition.Value(ctx)
	if diags.HasErrors() || !cond.IsKnown() || cond.Type() != cty.Bool || cond.IsNull() {
		return definiteEvalFailure(e.Condition, ctx)
	}
	if cond.True() {
		return definiteEvalFailure(e.TrueResult, ctx)
	}
	return definiteEvalFailure(e.FalseResult, ctx)
}

// operands are the expressions expr always evaluates. Conditional and
// parentheses are handled in definiteEvalFailure; try/can arguments are
// skipped because they guard their own failures.
func operands(expr hcl.Expression) []hclsyntax.Expression {
	switch e := expr.(type) {
	case *hclsyntax.FunctionCallExpr:
		name := e.Name
		if name == "try" || name == "can" {
			return nil
		}
		return e.Args
	case *hclsyntax.BinaryOpExpr:
		return []hclsyntax.Expression{e.LHS, e.RHS}
	case *hclsyntax.UnaryOpExpr:
		return []hclsyntax.Expression{e.Val}
	case *hclsyntax.TupleConsExpr:
		return e.Exprs
	case *hclsyntax.ObjectConsExpr:
		out := make([]hclsyntax.Expression, 0, 2*len(e.Items))
		for _, item := range e.Items {
			out = append(out, item.KeyExpr, item.ValueExpr)
		}
		return out
	case *hclsyntax.TemplateExpr:
		return e.Parts
	}
	return nil
}

func indexOutOfRange(collection, key hcl.Expression, ctx *hcl.EvalContext) bool {
	coll, collDiags := collection.Value(ctx)
	idx, idxDiags := key.Value(ctx)
	if idxDiags.HasErrors() || !idx.IsKnown() || idx.IsNull() {
		return false
	}
	// A collection that failed only because an element is computed can still
	// have a known length (a tuple constructor). Prefer that length when Value
	// fails.
	if n, ok := knownCollectionLen(collection, coll, collDiags); ok {
		return indexBeyond(n, idx)
	}
	return false
}

func relativeIndexOutOfRange(e *hclsyntax.RelativeTraversalExpr, ctx *hcl.EvalContext) bool {
	if len(e.Traversal) == 0 {
		return false
	}
	src, srcDiags := e.Source.Value(ctx)
	n, ok := knownCollectionLen(e.Source, src, srcDiags)
	if !ok {
		return false
	}
	step, isIndex := e.Traversal[0].(hcl.TraverseIndex)
	if !isIndex || !step.Key.IsKnown() || step.Key.IsNull() {
		return false
	}
	return indexBeyond(n, step.Key)
}

// knownCollectionLen is the length of collection expr, of value v: its
// known length, or the element count of a tuple constructor whose value
// failed only because an element did.
func knownCollectionLen(expr hcl.Expression, v cty.Value, diags hcl.Diagnostics) (int, bool) {
	if !diags.HasErrors() && v.IsKnown() && !v.IsNull() {
		ty := v.Type()
		switch {
		case ty.IsTupleType():
			return ty.Length(), true
		case ty.IsListType() || ty.IsSetType():
			return v.LengthInt(), true
		}
	}
	if e, ok := expr.(*hclsyntax.TupleConsExpr); ok {
		return len(e.Exprs), true
	}
	return 0, false
}

func indexBeyond(length int, idx cty.Value) bool {
	if idx.Type() != cty.Number {
		return false
	}
	f, _ := idx.AsBigFloat().Float64()
	i := int(f)
	return float64(i) != f || i < 0 || i >= length
}

func missingConfiguredKey(traversal hcl.Traversal, ctx *hcl.EvalContext) bool {
	if !instanceTraversal(traversal) {
		return false
	}
	val, ok := lookupRoot(ctx, traversal.RootName())
	if !ok {
		return false
	}
	nameIndex := instanceNameIndex(traversal)
	atInstance := false
	for i, step := range traversal[1:] {
		next, stepDiags := step.TraversalStep(val)
		if stepDiags.HasErrors() {
			_, isAttr := step.(hcl.TraverseAttr)
			// Past the instance object, a missing key is a real error.
			return isAttr && !atInstance && knownObject(val)
		}
		val = next
		atInstance = instanceAfterStep(i, nameIndex, step, val, atInstance)
	}
	return false
}

// notInstanceRoots are the reference roots that never name a resource or data
// instance. A missing module output is an error in Terraform too.
var notInstanceRoots = map[string]bool{
	"var": true, "local": true, "each": true, "count": true, "path": true,
	"terraform": true, "self": true, "module": true,
}

// readsComputedAttribute reports whether traversal fails on an attribute of a
// resource, data or ephemeral instance. A missing key of a value the
// configuration already holds, such as a key of a configured map, is an
// error, so try and can take the next argument. A missing resource or an
// index out of range still fails.
func readsComputedAttribute(traversal hcl.Traversal, ctx *hcl.EvalContext) bool {
	if !instanceTraversal(traversal) {
		return false
	}
	val, ok := lookupRoot(ctx, traversal.RootName())
	if !ok {
		return false
	}
	nameIndex := instanceNameIndex(traversal)
	atInstance := false
	for i, step := range traversal[1:] {
		next, diags := step.TraversalStep(val)
		if diags.HasErrors() {
			return computedAttributeMiss(step, atInstance, val)
		}
		val = next
		atInstance = instanceAfterStep(i, nameIndex, step, val, atInstance)
	}
	return false
}

func instanceTraversal(traversal hcl.Traversal) bool {
	return len(traversal) >= 3 && !traversal.IsRelative() && !notInstanceRoots[traversal.RootName()]
}

// instanceNameIndex is the step, within traversal[1:], that names the instance.
// A resource's name is the first step; data and ephemeral put the type first.
func instanceNameIndex(traversal hcl.Traversal) int {
	if root := traversal.RootName(); root == "data" || root == "ephemeral" {
		return 1
	}
	return 0
}

func computedAttributeMiss(step hcl.Traverser, atInstance bool, val cty.Value) bool {
	_, isAttr := step.(hcl.TraverseAttr)
	return isAttr && atInstance && knownObject(val)
}

// instanceAfterStep reports whether val, the value of step i, is the instance
// object. A later step has entered a nested value, so a missing key there is
// an error rather than a computed attribute.
func instanceAfterStep(i, nameIndex int, step hcl.Traverser, val cty.Value, atInstance bool) bool {
	switch i {
	case nameIndex:
		return knownObject(val)
	case nameIndex + 1:
		_, isIndex := step.(hcl.TraverseIndex)
		return isIndex && knownObject(val)
	default:
		if i > nameIndex {
			return false
		}
		return atInstance
	}
}

func knownObject(val cty.Value) bool {
	return val.IsKnown() && !val.IsNull() && val.Type().IsObjectType()
}

func lookupRoot(ctx *hcl.EvalContext, name string) (cty.Value, bool) {
	for ; ctx != nil; ctx = ctx.Parent() {
		if v, ok := ctx.Variables[name]; ok {
			return v, true
		}
	}
	return cty.NilVal, false
}
