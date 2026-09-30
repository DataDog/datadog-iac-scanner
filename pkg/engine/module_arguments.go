/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

const (
	moduleVariableRoot = "var"
	moduleLocalRoot    = "local"
	resourceEachRoot   = "each"
	moduleCountRoot    = "count"
	dynamicBlockType   = "dynamic"
	dynamicContentType = "content"
	dynamicIterator    = "iterator"
	forEachAttribute   = "for_each"
	moduleSourceArg    = "source"
)

// attributeVariables is an attribute's line range and the module variables its value reads.
type attributeVariables struct {
	lineStart int
	lineEnd   int
	names     []string
}

// resourceArguments binds each attribute of a module resource to the root
// call-site argument that sets it, following var.* and local.* references up
// the call chain. Attributes whose value does not come from exactly one
// argument of the root call are left out, so their findings keep the root
// call's source line.
func (t *moduleAttributionCache) resourceArguments(r *tfeval.ResolvedResource, rootCallFile string) []model.ModuleArgument {
	if t == nil || r.Body == nil || len(r.CallChain) == 0 {
		return nil
	}
	attrs := t.resourceAttributes(r.Body, r.Locals)
	if len(attrs) == 0 {
		return nil
	}
	args := make([]model.ModuleArgument, 0, len(attrs))
	for i := range attrs {
		location, ok := t.traceCallArgument(r.CallChain, attrs[i].names, rootCallFile)
		if !ok {
			continue
		}
		args = append(args, model.ModuleArgument{
			LineStart: attrs[i].lineStart,
			LineEnd:   attrs[i].lineEnd,
			CallSite:  location,
		})
	}
	if len(args) == 0 {
		return nil
	}
	return slices.Clip(args)
}

func (t *moduleAttributionCache) resourceAttributes(
	body *hclsyntax.Body, locals map[string]hclsyntax.Expression,
) []attributeVariables {
	if attrs, ok := t.attributes[body]; ok {
		return attrs
	}
	attrs := make([]attributeVariables, 0, len(body.Attributes))
	t.collectAttributeVariables(body, locals, resourceEachRoot, t.forEachVariables(body, locals), &attrs)
	if len(attrs) == 0 {
		attrs = nil
	}
	t.attributes[body] = attrs
	return attrs
}

func (t *moduleAttributionCache) argumentVariables(
	arg *hclsyntax.Attribute, locals map[string]hclsyntax.Expression,
) []string {
	if names, ok := t.arguments[arg]; ok {
		return names
	}
	w := readsWalker{anyIterator: true}
	w.walk(arg.Expr)
	names := t.walkedVariables(&w, locals)
	if w.readsRoot {
		// The value depends on the module call's iteration, which the call
		// chain does not follow.
		names = nil
	}
	t.arguments[arg] = names
	return names
}

// traceCallArgument follows module variable names from the leaf call up to the
// root call and returns the location of the root argument they resolve to.
// A value reading several variables, or one the call leaves to its default,
// is not set by a single argument and is not traced.
func (t *moduleAttributionCache) traceCallArgument(
	chain []tfeval.CallSite, names []string, rootCallFile string,
) (model.SourceLocation, bool) {
	for level := len(chain) - 1; level >= 0; level-- {
		body := chain[level].Body
		if body == nil || len(names) != 1 {
			return model.SourceLocation{}, false
		}
		arg, ok := body.Attributes[names[0]]
		if !ok {
			return model.SourceLocation{}, false
		}
		if level == 0 {
			return attributeLocation(arg, rootCallFile), true
		}
		names = t.argumentVariables(arg, chain[level].CallerLocals)
	}
	return model.SourceLocation{}, false
}

func attributeLocation(attr *hclsyntax.Attribute, filename string) model.SourceLocation {
	return model.SourceLocation{
		Filename:    filename,
		LineStart:   attr.SrcRange.Start.Line,
		LineEnd:     attr.SrcRange.End.Line,
		ColumnStart: attr.SrcRange.Start.Column,
		ColumnEnd:   attr.SrcRange.End.Column,
	}
}

// collectAttributeVariables records every attribute of body and its nested
// blocks that reads module variables. Reading the iteration value of an
// enclosing for_each also reads that for_each's variables.
func (t *moduleAttributionCache) collectAttributeVariables(
	body *hclsyntax.Body,
	locals map[string]hclsyntax.Expression,
	iterator string,
	iterated []string,
	out *[]attributeVariables,
) {
	if len(iterated) == 0 {
		iterator = ""
	}
	for _, attr := range body.Attributes {
		names, readsIterator := t.expressionVariables(attr.Expr, iterator, locals)
		if readsIterator {
			names = appendMissing(names, iterated)
		}
		if len(names) > 0 {
			*out = append(*out, attributeVariables{
				lineStart: attr.SrcRange.Start.Line,
				lineEnd:   attr.SrcRange.End.Line,
				names:     names,
			})
		}
	}
	for _, block := range body.Blocks {
		if block.Type != dynamicBlockType || len(block.Labels) == 0 {
			t.collectAttributeVariables(block.Body, locals, iterator, iterated, out)
			continue
		}
		name := block.Labels[0]
		if attr, ok := block.Body.Attributes[dynamicIterator]; ok {
			if traversal, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() {
				name = traversal.RootName()
			}
		}
		for _, content := range block.Body.Blocks {
			if content.Type == dynamicContentType {
				t.collectAttributeVariables(content.Body, locals, name, t.forEachVariables(block.Body, locals), out)
			}
		}
	}
}

func (t *moduleAttributionCache) forEachVariables(
	body *hclsyntax.Body, locals map[string]hclsyntax.Expression,
) []string {
	if attr, ok := body.Attributes[forEachAttribute]; ok {
		names, _ := t.expressionVariables(attr.Expr, "", locals)
		return names
	}
	return nil
}

// expressionVariables returns the distinct module variables expr reads,
// directly or through the module's locals, and whether it reads root.
func (t *moduleAttributionCache) expressionVariables(
	expr hclsyntax.Expression, root string, locals map[string]hclsyntax.Expression,
) (names []string, readsRoot bool) {
	w := readsWalker{root: root}
	w.walk(expr)
	return t.walkedVariables(&w, locals), w.readsRoot
}

// walkedVariables returns the module variables w read, directly or through
// the module's locals.
func (t *moduleAttributionCache) walkedVariables(w *readsWalker, locals map[string]hclsyntax.Expression) []string {
	names := w.names
	for _, local := range w.locals {
		names = appendMissing(names, t.localVariables(local, locals))
	}
	return names
}

// localVariables returns the module variables a local value reads. A local
// referring back to itself reads nothing further.
func (t *moduleAttributionCache) localVariables(name string, locals map[string]hclsyntax.Expression) []string {
	expr, ok := locals[name]
	if !ok {
		return nil
	}
	if names, ok := t.locals[expr]; ok {
		return names
	}
	t.locals[expr] = nil
	names, _ := t.expressionVariables(expr, "", locals)
	t.locals[expr] = names
	return names
}

// appendMissing appends the names of extra absent from names. It never
// appends to extra, which may be shared.
func appendMissing(names, extra []string) []string {
	for _, name := range extra {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// readsWalker finds the scope traversals of an expression. It runs once per
// attribute of every instantiated resource block, so it walks the common
// expression types directly: Expression.Variables and hclsyntax.VisitAll
// allocate for every node they visit.
type readsWalker struct {
	root   string
	names  []string
	locals []string
	// anyIterator makes reads of each and count set readsRoot, whatever root is.
	anyIterator bool
	readsRoot   bool
	// shadowed holds the names bound by the for expressions being walked.
	shadowed []string
}

// nolint:gocyclo
func (w *readsWalker) walk(expr hclsyntax.Expression) {
	switch e := expr.(type) {
	case nil, *hclsyntax.LiteralValueExpr, *hclsyntax.AnonSymbolExpr:
	case *hclsyntax.ScopeTraversalExpr:
		w.traversal(e.Traversal)
	case *hclsyntax.RelativeTraversalExpr:
		w.walk(e.Source)
	case *hclsyntax.IndexExpr:
		w.walk(e.Collection)
		w.walk(e.Key)
	case *hclsyntax.SplatExpr:
		w.walk(e.Source)
		w.walk(e.Each)
	case *hclsyntax.FunctionCallExpr:
		for _, arg := range e.Args {
			w.walk(arg)
		}
	case *hclsyntax.ConditionalExpr:
		w.walk(e.Condition)
		w.walk(e.TrueResult)
		w.walk(e.FalseResult)
	case *hclsyntax.BinaryOpExpr:
		w.walk(e.LHS)
		w.walk(e.RHS)
	case *hclsyntax.UnaryOpExpr:
		w.walk(e.Val)
	case *hclsyntax.ParenthesesExpr:
		w.walk(e.Expression)
	case *hclsyntax.TupleConsExpr:
		for _, item := range e.Exprs {
			w.walk(item)
		}
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			w.walk(item.KeyExpr)
			w.walk(item.ValueExpr)
		}
	case *hclsyntax.ObjectConsKeyExpr:
		if !e.ForceNonLiteral && hcl.ExprAsKeyword(e.Wrapped) != "" {
			return
		}
		w.walk(e.Wrapped)
	case *hclsyntax.TemplateExpr:
		for _, part := range e.Parts {
			w.walk(part)
		}
	case *hclsyntax.TemplateWrapExpr:
		w.walk(e.Wrapped)
	case *hclsyntax.TemplateJoinExpr:
		w.walk(e.Tuple)
	case *hclsyntax.ForExpr:
		w.walk(e.CollExpr)
		scope := len(w.shadowed)
		w.shadowed = append(w.shadowed, e.KeyVar, e.ValVar)
		w.walk(e.KeyExpr)
		w.walk(e.ValExpr)
		w.walk(e.CondExpr)
		w.shadowed = w.shadowed[:scope]
	default:
		for _, traversal := range scopeTraversals(expr) {
			w.traversal(traversal)
		}
	}
}

// scopeTraversals covers expression types readsWalker does not know. It is
// kept apart so the walker itself is not captured by a closure and stays on
// the stack.
func scopeTraversals(expr hclsyntax.Expression) []hcl.Traversal {
	var traversals []hcl.Traversal
	_ = hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
		if scope, ok := node.(*hclsyntax.ScopeTraversalExpr); ok {
			traversals = append(traversals, scope.Traversal)
		}
		return nil
	})
	return traversals
}

func (w *readsWalker) traversal(traversal hcl.Traversal) {
	if len(traversal) == 0 {
		return
	}
	if len(w.shadowed) > 0 && slices.Contains(w.shadowed, traversal.RootName()) {
		return
	}
	switch traversal.RootName() {
	case moduleVariableRoot:
		w.names = appendStep(w.names, traversal)
	case moduleLocalRoot:
		w.locals = appendStep(w.locals, traversal)
	case w.root:
		w.readsRoot = w.root != ""
	case resourceEachRoot, moduleCountRoot:
		if w.anyIterator {
			w.readsRoot = true
		}
	}
}

func appendStep(names []string, traversal hcl.Traversal) []string {
	if len(traversal) < 2 {
		return names
	}
	if step, ok := traversal[1].(hcl.TraverseAttr); ok && !slices.Contains(names, step.Name) {
		names = append(names, step.Name)
	}
	return names
}
