/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	moduleVariableRoot = "var"
	moduleLocalRoot    = "local"
	resourceEachRoot   = "each"
	dynamicBlockType   = "dynamic"
	dynamicContentType = "content"
	dynamicIterator    = "iterator"
	forEachAttribute   = "for_each"
	moduleSourceArg    = "source"
)

// inputReads is what a value reads of its module's inputs. value holds the
// inputs the value is built from and selector the inputs that only chose it
// among alternatives. ambiguous is set when a choice between alternatives
// reading different inputs could not be resolved from the evaluated values.
type inputReads struct {
	value     []string
	selector  []string
	ambiguous bool
}

func (r *inputReads) empty() bool {
	return len(r.value) == 0 && len(r.selector) == 0
}

func (r *inputReads) add(o inputReads) {
	r.value = appendMissing(r.value, o.value)
	r.selector = appendMissing(r.selector, o.selector)
	r.ambiguous = r.ambiguous || o.ambiguous
}

// addSelector records o as having only chosen the value, not built it.
func (r *inputReads) addSelector(o inputReads) {
	r.selector = appendMissing(appendMissing(r.selector, o.value), o.selector)
	r.ambiguous = r.ambiguous || o.ambiguous
}

// single returns the one input the value is built from. A value reading no
// input but chosen by one, such as a module default picked because the caller
// passed null, is not set by that input.
func (r *inputReads) single() (string, bool) {
	if r.ambiguous || len(r.value) != 1 {
		return "", false
	}
	return r.value[0], true
}

// shared returns r with its slices clipped, so a later append on a copy
// never writes into a cached array.
func (r inputReads) shared() inputReads {
	r.value = slices.Clip(r.value)
	r.selector = slices.Clip(r.selector)
	return r
}

func sameReads(a, b *inputReads) bool {
	return sameNames(a.value, b.value) && sameNames(a.selector, b.selector)
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, name := range a {
		if !slices.Contains(b, name) {
			return false
		}
	}
	return true
}

// attributeReads is the line range of an attribute, or of a dynamic block's
// header, with the module inputs its value reads.
type attributeReads struct {
	lineStart int
	lineEnd   int
	reads     inputReads
}

// bodyReads is the attributes of a resource body reading module inputs.
// iterationDependent is set when resolving a choice read the instance's each
// or count value, so other instances of the block may resolve differently.
type bodyReads struct {
	attrs              []attributeReads
	iterationDependent bool
}

type bodyCacheKey struct {
	body  *hclsyntax.Body
	scope *tfeval.ModuleScope
}

type argumentCacheKey struct {
	arg   *hclsyntax.Attribute
	scope *tfeval.ModuleScope
}

type localCacheKey struct {
	expr  hclsyntax.Expression
	scope *tfeval.ModuleScope
}

// resourceArguments tells, for each attribute of a module resource reading
// module inputs, whether a single root call argument sets it, following var.*
// and local.* references up the call chain. Attributes reading no input are
// left out: the module sets them.
func (t *moduleAttributionCache) resourceArguments(r *tfeval.ResolvedResource, rootCallFile string) []model.ModuleArgument {
	if t == nil || r.Body == nil || len(r.CallChain) == 0 {
		return nil
	}
	attrs := t.resourceAttributes(r).attrs
	if len(attrs) == 0 {
		return nil
	}
	args := make([]model.ModuleArgument, 0, len(attrs))
	for i := range attrs {
		arg := model.ModuleArgument{LineStart: attrs[i].lineStart, LineEnd: attrs[i].lineEnd}
		if location, ok := t.traceCallArgument(r.CallChain, attrs[i].reads, rootCallFile); ok {
			arg.Control = model.ArgumentControlCaller
			arg.CallSite = location
		}
		args = append(args, arg)
	}
	return args
}

func (t *moduleAttributionCache) resourceAttributes(r *tfeval.ResolvedResource) bodyReads {
	if r == t.lastResource {
		return t.lastReads
	}
	key := bodyCacheKey{body: r.Body, scope: r.Scope}
	if cached, ok := t.attributes[key]; ok && !cached.iterationDependent {
		return cached
	}
	a := t.analyzer(r.Scope, r.Iteration)
	if attr, ok := r.Body.Attributes[forEachAttribute]; ok {
		_, evaluated := r.Iteration[resourceEachRoot]
		a.iterators = append(a.iterators, iteratorReads{
			name: resourceEachRoot, reads: a.reads(attr.Expr).shared(), evaluated: evaluated,
		})
	}
	var attrs []attributeReads
	a.collectBody(r.Body, &attrs)
	out := bodyReads{attrs: slices.Clip(attrs), iterationDependent: a.usedIteration}
	t.attributes[key] = out
	t.lastResource, t.lastReads = r, out
	return out
}

// traceCallArgument follows the input a value is built from up the call chain
// and returns the location of the root argument setting it. A value built from
// several inputs, one the call leaves to its default, or one an intermediate
// module sets itself is not set by a single root argument.
func (t *moduleAttributionCache) traceCallArgument(
	chain []tfeval.CallSite, reads inputReads, rootCallFile string,
) (model.SourceLocation, bool) {
	for level := len(chain) - 1; level >= 0; level-- {
		name, ok := reads.single()
		site := &chain[level]
		if !ok || site.Body == nil {
			return model.SourceLocation{}, false
		}
		arg, ok := site.Body.Attributes[name]
		if !ok {
			return model.SourceLocation{}, false
		}
		if level == 0 {
			return attributeLocation(arg, rootCallFile), true
		}
		reads = t.argumentReads(site, arg)
	}
	return model.SourceLocation{}, false
}

// argumentReads is what a module call argument reads of the calling module's
// inputs. The call's each value reads its for_each; its count index reads
// nothing the caller sets.
func (t *moduleAttributionCache) argumentReads(site *tfeval.CallSite, arg *hclsyntax.Attribute) inputReads {
	key := argumentCacheKey{arg: arg, scope: site.Caller}
	if reads, ok := t.arguments[key]; ok {
		return reads
	}
	a := t.analyzer(site.Caller, nil)
	if attr, ok := site.Body.Attributes[forEachAttribute]; ok {
		a.iterators = append(a.iterators, iteratorReads{name: resourceEachRoot, reads: a.reads(attr.Expr).shared()})
	}
	reads := a.reads(arg.Expr).shared()
	t.arguments[key] = reads
	return reads
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

// iteratorReads binds an iterator in scope (each, or a dynamic block's
// iterator) to what its collection reads. evaluated is set when the
// instance's iteration holds its value.
type iteratorReads struct {
	name      string
	reads     inputReads
	evaluated bool
}

// valueAnalyzer finds the module inputs expressions read, resolving choices
// between alternatives (conditionals, coalesce, try, lookup) with the values
// the module was evaluated with. It runs once per attribute of every
// instantiated resource block, so it walks the common expression types
// directly: Expression.Variables and hclsyntax.VisitAll allocate for every
// node they visit.
type valueAnalyzer struct {
	cache     *moduleAttributionCache
	scope     *tfeval.ModuleScope
	iteration map[string]cty.Value
	// iterators holds the iterators of the enclosing for_each and dynamic
	// blocks, innermost last.
	iterators []iteratorReads
	// shadowed holds the names bound by the for expressions being walked.
	shadowed []string
	evalCtx  *hcl.EvalContext
	// usedIteration is set once a choice was resolved with each or count.
	usedIteration bool
}

func (t *moduleAttributionCache) analyzer(scope *tfeval.ModuleScope, iteration map[string]cty.Value) *valueAnalyzer {
	return &valueAnalyzer{cache: t, scope: scope, iteration: iteration}
}

// collectBody records every attribute of body and its nested blocks that
// reads module inputs. A dynamic block's iterator reads what its for_each
// reads, through every enclosing iterator.
func (a *valueAnalyzer) collectBody(body *hclsyntax.Body, out *[]attributeReads) {
	for _, attr := range body.Attributes {
		if reads := a.reads(attr.Expr); !reads.empty() {
			*out = append(*out, attributeReads{
				lineStart: attr.SrcRange.Start.Line,
				lineEnd:   attr.SrcRange.End.Line,
				reads:     reads,
			})
		}
	}
	for _, block := range body.Blocks {
		if block.Type != dynamicBlockType || len(block.Labels) == 0 {
			a.collectBody(block.Body, out)
			continue
		}
		a.collectDynamic(block, out)
	}
}

// collectDynamic records a dynamic block's header, which reports reach when
// they flag the generated block as a whole, and the attributes of its content
// with its iterator in scope.
func (a *valueAnalyzer) collectDynamic(block *hclsyntax.Block, out *[]attributeReads) {
	name := block.Labels[0]
	if attr, ok := block.Body.Attributes[dynamicIterator]; ok {
		if traversal, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() {
			name = traversal.RootName()
		}
	}
	var reads inputReads
	if attr, ok := block.Body.Attributes[forEachAttribute]; ok {
		reads = a.reads(attr.Expr).shared()
	}
	headerEnd := block.OpenBraceRange.Start.Line
	for _, content := range block.Body.Blocks {
		if content.Type == dynamicContentType {
			headerEnd = max(headerEnd, content.OpenBraceRange.Start.Line)
		}
	}
	if !reads.empty() {
		*out = append(*out, attributeReads{lineStart: block.TypeRange.Start.Line, lineEnd: headerEnd, reads: reads})
	}
	depth := len(a.iterators)
	a.iterators = append(a.iterators, iteratorReads{name: name, reads: reads})
	for _, content := range block.Body.Blocks {
		if content.Type == dynamicContentType {
			a.collectBody(content.Body, out)
		}
	}
	a.iterators = a.iterators[:depth]
}

// nolint:gocyclo
func (a *valueAnalyzer) reads(expr hclsyntax.Expression) inputReads {
	var r inputReads
	switch e := expr.(type) {
	case nil, *hclsyntax.LiteralValueExpr, *hclsyntax.AnonSymbolExpr:
	case *hclsyntax.ScopeTraversalExpr:
		return a.traversal(e.Traversal)
	case *hclsyntax.RelativeTraversalExpr:
		return a.reads(e.Source)
	case *hclsyntax.IndexExpr:
		r = a.reads(e.Collection)
		r.addSelector(a.reads(e.Key))
	case *hclsyntax.SplatExpr:
		r = a.reads(e.Source)
		r.add(a.reads(e.Each))
	case *hclsyntax.FunctionCallExpr:
		return a.call(e)
	case *hclsyntax.ConditionalExpr:
		return a.conditional(e)
	case *hclsyntax.BinaryOpExpr:
		r = a.reads(e.LHS)
		r.add(a.reads(e.RHS))
	case *hclsyntax.UnaryOpExpr:
		return a.reads(e.Val)
	case *hclsyntax.ParenthesesExpr:
		return a.reads(e.Expression)
	case *hclsyntax.TupleConsExpr:
		for _, item := range e.Exprs {
			r.add(a.reads(item))
		}
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			r.add(a.reads(item.KeyExpr))
			r.add(a.reads(item.ValueExpr))
		}
	case *hclsyntax.ObjectConsKeyExpr:
		if !e.ForceNonLiteral && hcl.ExprAsKeyword(e.Wrapped) != "" {
			return r
		}
		return a.reads(e.Wrapped)
	case *hclsyntax.TemplateExpr:
		for _, part := range e.Parts {
			r.add(a.reads(part))
		}
	case *hclsyntax.TemplateWrapExpr:
		return a.reads(e.Wrapped)
	case *hclsyntax.TemplateJoinExpr:
		return a.reads(e.Tuple)
	case *hclsyntax.ForExpr:
		r = a.reads(e.CollExpr)
		scope := len(a.shadowed)
		a.shadowed = append(a.shadowed, e.KeyVar, e.ValVar)
		r.add(a.reads(e.KeyExpr))
		r.add(a.reads(e.ValExpr))
		r.addSelector(a.reads(e.CondExpr))
		a.shadowed = a.shadowed[:scope]
	default:
		for _, traversal := range scopeTraversals(expr) {
			r.add(a.traversal(traversal))
		}
	}
	return r
}

// scopeTraversals covers expression types valueAnalyzer does not know. It is
// kept apart so the analyzer itself is not captured by a closure.
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

func (a *valueAnalyzer) traversal(traversal hcl.Traversal) inputReads {
	var r inputReads
	if len(traversal) == 0 {
		return r
	}
	root := traversal.RootName()
	if slices.Contains(a.shadowed, root) {
		return r
	}
	for i := len(a.iterators) - 1; i >= 0; i-- {
		if a.iterators[i].name == root {
			return a.iterators[i].reads
		}
	}
	switch root {
	case moduleVariableRoot:
		r.value = appendStep(r.value, traversal)
	case moduleLocalRoot:
		if name := stepName(traversal); name != "" {
			return a.local(name)
		}
	}
	return r
}

// local returns what a local value reads. A local referring back to itself
// reads nothing further.
func (a *valueAnalyzer) local(name string) inputReads {
	if a.scope == nil {
		return inputReads{}
	}
	expr, ok := a.scope.Locals[name]
	if !ok {
		return inputReads{}
	}
	key := localCacheKey{expr: expr, scope: a.scope}
	if reads, ok := a.cache.locals[key]; ok {
		return reads
	}
	a.cache.locals[key] = inputReads{}
	// Locals cannot read iterators or for expression variables of the
	// expression reading them, so they are walked in the module's own scope.
	reads := a.cache.analyzer(a.scope, nil).reads(expr).shared()
	a.cache.locals[key] = reads
	return reads
}

func (a *valueAnalyzer) call(e *hclsyntax.FunctionCallExpr) inputReads {
	if !e.ExpandFinal {
		switch e.Name {
		case "coalesce":
			return a.firstOf(e.Args, absentForCoalesce)
		case "coalescelist":
			return a.firstOf(e.Args, emptyForCoalesceList)
		case "try":
			return a.firstEvaluated(e.Args)
		case "lookup":
			if len(e.Args) == 3 {
				return a.lookup(e.Args[0], e.Args[1], e.Args[2])
			}
		}
	}
	var r inputReads
	for _, arg := range e.Args {
		r.add(a.reads(arg))
	}
	return r
}

func (a *valueAnalyzer) conditional(e *hclsyntax.ConditionalExpr) inputReads {
	condition := a.reads(e.Condition)
	if v, ok := a.value(e.Condition); ok && !v.IsNull() && v.Type() == cty.Bool {
		branch := e.FalseResult
		if v.True() {
			branch = e.TrueResult
		}
		r := a.reads(branch)
		r.addSelector(condition)
		return r
	}
	return a.unresolved(condition, e.TrueResult, e.FalseResult)
}

func absentForCoalesce(v cty.Value) bool {
	return v.IsNull() || (v.Type() == cty.String && v.AsString() == "")
}

func emptyForCoalesceList(v cty.Value) bool {
	if v.IsNull() {
		return true
	}
	ty := v.Type()
	return (ty.IsListType() || ty.IsTupleType()) && v.LengthInt() == 0
}

// firstOf resolves coalesce-like calls: the first argument not skipped is the
// value, the skipped ones only chose it. The last argument is the value once
// reached, whatever it holds.
func (a *valueAnalyzer) firstOf(args []hclsyntax.Expression, skip func(cty.Value) bool) inputReads {
	var skipped inputReads
	for i, arg := range args {
		if i < len(args)-1 {
			v, ok := a.value(arg)
			if !ok {
				return a.unresolved(skipped, args[i:]...)
			}
			if skip(v) {
				skipped.addSelector(a.reads(arg))
				continue
			}
		}
		r := a.reads(arg)
		r.addSelector(skipped)
		return r
	}
	return skipped
}

// firstEvaluated resolves try: the first argument evaluating without error is
// the value. Arguments whose evaluation depends on something not kept after
// evaluation, such as a resource attribute, leave the choice unresolved.
func (a *valueAnalyzer) firstEvaluated(args []hclsyntax.Expression) inputReads {
	var skipped inputReads
	for i, arg := range args {
		if i < len(args)-1 {
			if !a.evaluable(arg) {
				return a.unresolved(skipped, args[i:]...)
			}
			v, diags := arg.Value(a.context())
			if diags.HasErrors() {
				skipped.addSelector(a.reads(arg))
				continue
			}
			if !v.IsWhollyKnown() {
				return a.unresolved(skipped, args[i:]...)
			}
		}
		r := a.reads(arg)
		r.addSelector(skipped)
		return r
	}
	return skipped
}

func (a *valueAnalyzer) lookup(collection, key, fallback hclsyntax.Expression) inputReads {
	keyReads := a.reads(key)
	if found, ok := a.hasKey(collection, key); ok {
		chosen, other := collection, fallback
		if !found {
			chosen, other = fallback, collection
		}
		r := a.reads(chosen)
		r.addSelector(keyReads)
		if !found {
			r.addSelector(a.reads(other))
		}
		return r
	}
	return a.unresolved(keyReads, collection, fallback)
}

func (a *valueAnalyzer) hasKey(collection, key hclsyntax.Expression) (found, ok bool) {
	m, ok := a.value(collection)
	if !ok || m.IsNull() {
		return false, false
	}
	k, ok := a.value(key)
	if !ok || k.IsNull() || k.Type() != cty.String {
		return false, false
	}
	ty := m.Type()
	switch {
	case ty.IsObjectType():
		return ty.HasAttribute(k.AsString()), true
	case ty.IsMapType():
		has := m.HasIndex(k)
		if !has.IsKnown() {
			return false, false
		}
		return has.True(), true
	}
	return false, false
}

// unresolved is a choice among alternatives that could not be resolved: the
// value reads all of them, and is ambiguous unless they all read the same
// inputs.
func (a *valueAnalyzer) unresolved(selector inputReads, alternatives ...hclsyntax.Expression) inputReads {
	var r inputReads
	for i, alt := range alternatives {
		reads := a.reads(alt)
		if i == 0 {
			r = reads
			continue
		}
		if !sameReads(&r, &reads) {
			r.ambiguous = true
		}
		r.add(reads)
	}
	r.addSelector(selector)
	return r
}

// value evaluates expr with the module's var and local values and the
// instance's iteration, or reports false when expr reads anything else or
// does not evaluate to a known value.
func (a *valueAnalyzer) value(expr hclsyntax.Expression) (cty.Value, bool) {
	if !a.evaluable(expr) {
		return cty.NilVal, false
	}
	v, diags := expr.Value(a.context())
	if diags.HasErrors() || !v.IsKnown() {
		return cty.NilVal, false
	}
	v, _ = v.UnmarkDeep()
	return v, true
}

// evaluable reports whether expr only reads what the analyzer can evaluate it
// with, so an evaluation error is the expression's own and not a reference
// the analyzer does not hold, such as a resource attribute or a dynamic
// block's iterator.
func (a *valueAnalyzer) evaluable(expr hclsyntax.Expression) bool {
	ctx := a.context()
	var bound []string
	ok := true
	usedIteration := false
	_ = hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
		switch n := node.(type) {
		case *hclsyntax.ForExpr:
			bound = append(bound, n.KeyVar, n.ValVar)
		case *hclsyntax.FunctionCallExpr:
			if _, known := ctx.Functions[n.Name]; !known {
				ok = false
			}
		case *hclsyntax.ScopeTraversalExpr:
			root := n.Traversal.RootName()
			if slices.Contains(bound, root) {
				return nil
			}
			if slices.Contains(a.shadowed, root) || a.unevaluatedIterator(root) {
				ok = false
				return nil
			}
			if _, known := ctx.Variables[root]; !known {
				ok = false
				return nil
			}
			if _, iterated := a.iteration[root]; iterated {
				usedIteration = true
			}
		}
		return nil
	})
	if ok && usedIteration {
		a.usedIteration = true
	}
	return ok
}

// unevaluatedIterator reports whether root names an iterator in scope whose
// values are not kept after evaluation, such as a dynamic block's.
func (a *valueAnalyzer) unevaluatedIterator(root string) bool {
	for i := len(a.iterators) - 1; i >= 0; i-- {
		if a.iterators[i].name == root {
			return !a.iterators[i].evaluated
		}
	}
	return false
}

func (a *valueAnalyzer) context() *hcl.EvalContext {
	if a.evalCtx != nil {
		return a.evalCtx
	}
	vars := make(map[string]cty.Value, 2+len(a.iteration))
	if a.scope != nil {
		if a.scope.Var != cty.NilVal {
			vars[moduleVariableRoot] = a.scope.Var
		}
		if a.scope.Local != cty.NilVal {
			vars[moduleLocalRoot] = a.scope.Local
		}
	}
	for name, v := range a.iteration {
		vars[name] = v
	}
	a.evalCtx = &hcl.EvalContext{Variables: vars, Functions: functions.TerraformFuncs}
	return a.evalCtx
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

func appendStep(names []string, traversal hcl.Traversal) []string {
	if name := stepName(traversal); name != "" && !slices.Contains(names, name) {
		names = append(names, name)
	}
	return names
}

func stepName(traversal hcl.Traversal) string {
	if len(traversal) < 2 {
		return ""
	}
	if step, ok := traversal[1].(hcl.TraverseAttr); ok {
		return step.Name
	}
	return ""
}
