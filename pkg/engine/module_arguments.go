/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"maps"
	"slices"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

const (
	moduleVariableRoot = "var"
	moduleLocalRoot    = "local"
	moduleCallRoot     = "module"
	maxLocalHops       = 8
	mergeFunction      = "merge"
	toSetFunction      = "toset"
	resourceEachRoot   = "each"
	dynamicBlockType   = "dynamic"
	dynamicContentType = "content"
	dynamicIterator    = "iterator"
	dynamicLabels      = "labels"
	forEachAttribute   = "for_each"
	moduleSourceArg    = "source"
)

// inputReads is what a value reads of its module's inputs. value holds the
// inputs the value is built from and selector the inputs that only chose it
// among alternatives. ambiguous is set when a choice between alternatives
// reading different inputs could not be resolved from the evaluated values.
type inputReads struct {
	value     []valueRead
	selector  []string
	ambiguous bool
}

// valueRead is an input a value is built from. member narrows it to one
// member read through (var.obj.attr); it is empty when the input is read
// whole.
type valueRead struct {
	name   string
	member string
}

func (r *inputReads) empty() bool {
	return len(r.value) == 0 && len(r.selector) == 0 && !r.ambiguous
}

func (r *inputReads) add(o inputReads) {
	r.value = appendValues(r.value, o.value)
	r.selector = appendMissing(r.selector, o.selector)
	r.ambiguous = r.ambiguous || o.ambiguous
}

// addSelector records o as having only chosen the value, not built it.
func (r *inputReads) addSelector(o inputReads) {
	r.selector = appendMissing(appendMissing(r.selector, valueNames(o.value)), o.selector)
	r.ambiguous = r.ambiguous || o.ambiguous
}

// single returns the one input the value is built from. A value reading no
// input but chosen by one, such as a module default picked because the caller
// passed null, is not set by that input.
func (r *inputReads) single() (valueRead, bool) {
	if r.ambiguous || len(r.value) != 1 {
		return valueRead{}, false
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

// appendValues appends the inputs of extra absent from values. An input read
// through different members is read whole. It never modifies values or
// extra, which may be shared.
func appendValues(values, extra []valueRead) []valueRead {
	cloned := false
	for _, v := range extra {
		i := slices.IndexFunc(values, func(have valueRead) bool { return have.name == v.name })
		switch {
		case i < 0:
			values = append(values, v)
		case values[i].member != v.member && values[i].member != "":
			if !cloned {
				values, cloned = slices.Clone(values), true
			}
			values[i].member = ""
		}
	}
	return values
}

func valueNames(values []valueRead) []string {
	names := make([]string, len(values))
	for i, v := range values {
		names[i] = v.name
	}
	return names
}

func sameReads(a, b *inputReads) bool {
	return sameNames(valueNames(a.value), valueNames(b.value)) && sameNames(a.selector, b.selector)
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
	// module marks an item of a multi-line value reading no module input.
	module bool
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
	// iteration identifies the instance when resolving the block read it.
	iteration string
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
		if attrs[i].module {
			arg.Control = model.ArgumentControlModule
		} else if location, ok := t.traceCallArgument(r.CallChain, attrs[i].reads, rootCallFile, r.Scope); ok {
			arg.Control = model.ArgumentControlCaller
			arg.CallSite = location
		}
		args = append(args, arg)
	}
	return args
}

func (t *moduleAttributionCache) resourceAttributes(r *tfeval.ResolvedResource) bodyReads {
	key := bodyCacheKey{body: r.Body, scope: r.Scope}
	if cached, ok := t.attributes[key]; ok && !cached.iterationDependent {
		return cached
	}
	key.iteration = iterationKey(r.Iteration)
	if key.iteration != "" {
		if cached, ok := t.attributes[key]; ok {
			return cached
		}
	}
	a := t.analyzer(r.Scope, r.Iteration)
	if attr, ok := r.Body.Attributes[forEachAttribute]; ok {
		a.forEach = attr
		a.iterators = append(a.iterators, a.eachIterator(attr.Expr, r.Iteration[resourceEachRoot]))
	}
	var attrs []attributeReads
	a.collectBody(r.Body, &attrs)
	slices.SortStableFunc(attrs, func(x, y attributeReads) int {
		if x.lineStart != y.lineStart {
			return x.lineStart - y.lineStart
		}
		return x.lineEnd - y.lineEnd
	})
	out := bodyReads{attrs: slices.Clip(attrs), iterationDependent: a.usedIteration}
	if !out.iterationDependent {
		key.iteration = ""
	}
	t.attributes[key] = out
	return out
}

// iterationKey identifies an instance by its each key or count index, which
// with the block and scope fixes every value the instance iterates.
func iterationKey(iteration map[string]cty.Value) string {
	var key string
	if each, ok := iteration[resourceEachRoot]; ok {
		key += "each:" + valueKey(each, "key")
	}
	if count, ok := iteration["count"]; ok {
		key += "count:" + valueKey(count, "index")
	}
	return key
}

func valueKey(obj cty.Value, attr string) string {
	if !obj.Type().IsObjectType() || !obj.Type().HasAttribute(attr) {
		return "?"
	}
	v, _ := obj.GetAttr(attr).UnmarkDeep()
	switch {
	case !v.IsKnown() || v.IsNull():
		return "?"
	case v.Type() == cty.String:
		return strconv.Quote(v.AsString()) + ";"
	case v.Type() == cty.Number:
		return v.AsBigFloat().Text('f', -1) + ";"
	}
	return "?"
}

// traceCallArgument follows the input a value is built from up the call chain
// and returns the location of the root argument setting it. A value built from
// several inputs, one the call leaves to its default, or one an intermediate
// module sets itself is not set by a single root argument.
func (t *moduleAttributionCache) traceCallArgument(
	chain []tfeval.CallSite, reads inputReads, rootCallFile string, leaf *tfeval.ModuleScope,
) (model.SourceLocation, bool) {
	for level := len(chain) - 1; level >= 0; level-- {
		input, ok := reads.single()
		site := &chain[level]
		if !ok || site.Body == nil {
			return model.SourceLocation{}, false
		}
		name := input.name
		arg, ok := site.Body.Attributes[name]
		if !ok {
			return model.SourceLocation{}, false
		}
		callee := leaf
		if level < len(chain)-1 {
			callee = chain[level+1].Caller
		}
		if t.argumentUnused(site, arg, input, callee) {
			return model.SourceLocation{}, false
		}
		if level == 0 {
			return attributeLocation(arg, rootCallFile), true
		}
		reads = t.argumentReads(site, arg)
	}
	return model.SourceLocation{}, false
}

// argumentUnused reports whether the module sets the value although the call
// passes the argument: the caller passed null and the module took its
// default, or only passed an object without the member the module reads,
// leaving that member to its default.
func (t *moduleAttributionCache) argumentUnused(
	site *tfeval.CallSite, arg *hclsyntax.Attribute, input valueRead, callee *tfeval.ModuleScope,
) bool {
	v, ok := t.argumentValue(site, arg)
	if !ok {
		return false
	}
	if v.IsNull() {
		return moduleHoldsValue(callee, input.name)
	}
	member := input.member
	if member == "" {
		return false
	}
	switch ty := v.Type(); {
	case ty.IsObjectType():
		return !ty.HasAttribute(member) || v.GetAttr(member).IsNull()
	case ty.IsMapType():
		has := v.HasIndex(cty.StringVal(member))
		if !has.IsKnown() {
			return false
		}
		if has.False() {
			return true
		}
		element := v.Index(cty.StringVal(member))
		return element.IsKnown() && element.IsNull()
	}
	return false
}

// argumentValue is the evaluated value of a call argument, memoized because
// every attribute traced through the argument asks for it.
func (t *moduleAttributionCache) argumentValue(site *tfeval.CallSite, arg *hclsyntax.Attribute) (cty.Value, bool) {
	key := argumentCacheKey{arg: arg, scope: site.Caller}
	if cached, ok := t.argumentValues[key]; ok {
		return cached.value, cached.ok
	}
	v, ok := t.analyzer(site.Caller, nil).value(arg.Expr)
	t.argumentValues[key] = argumentValue{value: v, ok: ok}
	return v, ok
}

type argumentValue struct {
	value cty.Value
	ok    bool
}

// moduleHoldsValue reports whether the module's input name evaluated to a
// value, which an argument passed as null cannot be.
func moduleHoldsValue(scope *tfeval.ModuleScope, name string) bool {
	if scope == nil || scope.Var == cty.NilVal || !scope.Var.Type().IsObjectType() ||
		!scope.Var.Type().HasAttribute(name) {
		return false
	}
	v := scope.Var.GetAttr(name)
	return v.IsKnown() && !v.IsNull()
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
		a.iterators = append(a.iterators, iteratorReads{name: resourceEachRoot, reads: a.collectionReads(attr.Expr)})
	}
	reads := a.reads(arg.Expr).shared()
	if a.mixedCollection(arg.Expr) {
		// Part of what the call passes is the calling module's own.
		reads.ambiguous = true
	}
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
	// split is set when the instance's key and value are known to come from
	// different parts of the collection.
	split                bool
	keyReads, valueReads inputReads
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
	// forEach is the for_each attribute of the resource being analyzed.
	forEach *hclsyntax.Attribute
}

func (t *moduleAttributionCache) analyzer(scope *tfeval.ModuleScope, iteration map[string]cty.Value) *valueAnalyzer {
	return &valueAnalyzer{cache: t, scope: scope, iteration: iteration}
}

// collectBody records every attribute of body and its nested blocks that
// reads module inputs. A dynamic block's iterator reads what its for_each
// reads, through every enclosing iterator.
func (a *valueAnalyzer) collectBody(body *hclsyntax.Body, out *[]attributeReads) {
	for _, attr := range body.Attributes {
		isForEach := attr == a.forEach
		var reads inputReads
		if isForEach {
			// The collection is the same for every instance and can be large,
			// so it is read once and its lines are attributed as a whole.
			reads = a.cachedCollectionReads(attr.Expr)
		} else {
			reads = a.reads(attr.Expr)
		}
		if reads.empty() {
			continue
		}
		*out = append(*out, attributeReads{
			lineStart: attr.SrcRange.Start.Line,
			lineEnd:   attr.SrcRange.End.Line,
			reads:     reads,
		})
		if !isForEach {
			a.collectItems(attr.Expr, out)
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

// collectItems records the items of a value spread over several lines, each
// on lines of its own, so a finding on one is attributed by what that item
// reads and not by the whole value.
func (a *valueAnalyzer) collectItems(expr hclsyntax.Expression, out *[]attributeReads) {
	type item struct {
		key, value hclsyntax.Expression
	}
	var items []item
	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		a.collectItems(e.Expression, out)
		return
	case *hclsyntax.FunctionCallExpr:
		for _, arg := range e.Args {
			a.collectItems(arg, out)
		}
		return
	case *hclsyntax.ConditionalExpr:
		a.collectItems(e.TrueResult, out)
		a.collectItems(e.FalseResult, out)
		return
	case *hclsyntax.ObjectConsExpr:
		for _, it := range e.Items {
			items = append(items, item{key: it.KeyExpr, value: it.ValueExpr})
		}
	case *hclsyntax.TupleConsExpr:
		for _, value := range e.Exprs {
			items = append(items, item{value: value})
		}
	default:
		return
	}
	last := expr.Range().Start.Line
	for _, it := range items {
		start := it.value.Range().Start.Line
		if it.key != nil {
			start = it.key.Range().Start.Line
		}
		if start <= last {
			return
		}
		last = it.value.Range().End.Line
	}
	for _, it := range items {
		var reads inputReads
		start := it.value.Range().Start.Line
		if it.key != nil {
			start = it.key.Range().Start.Line
			reads = a.reads(it.key)
		}
		reads.add(a.reads(it.value))
		*out = append(*out, attributeReads{
			lineStart: start,
			lineEnd:   it.value.Range().End.Line,
			reads:     reads,
			module:    reads.empty(),
		})
		a.collectItems(it.value, out)
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
		reads = a.collectionReads(attr.Expr)
	}
	headerEnd := block.OpenBraceRange.Start.Line
	for _, content := range block.Body.Blocks {
		if content.Type == dynamicContentType {
			headerEnd = max(headerEnd, content.OpenBraceRange.Start.Line)
		}
	}
	// labels shape the generated block but not its iteration values.
	header := reads.shared()
	if attr, ok := block.Body.Attributes[dynamicLabels]; ok {
		header.add(a.reads(attr.Expr).shared())
	}
	if !header.empty() {
		*out = append(*out, attributeReads{lineStart: block.TypeRange.Start.Line, lineEnd: headerEnd, reads: header})
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
		if it := &a.iterators[i]; it.name == root {
			if it.split && len(traversal) > 1 {
				switch stepString(traversal[1]) {
				case "key":
					return it.keyReads
				case "value":
					return it.valueReads
				}
			}
			return it.reads
		}
	}
	switch root {
	case moduleVariableRoot:
		name := stepName(traversal)
		if name == "" {
			// The whole of var, or a member chosen at run time.
			r.ambiguous = true
			return r
		}
		member := ""
		if len(traversal) > 2 {
			member = stepString(traversal[2])
		}
		r.value = []valueRead{{name: name, member: member}}
	case moduleLocalRoot:
		name := stepName(traversal)
		if name == "" {
			r.ambiguous = true
			return r
		}
		return a.local(name)
	case moduleCallRoot:
		// An output of another module, which may be built from the caller's
		// inputs.
		r.ambiguous = true
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
	w := evaluableWalker{a: a, ctx: a.context()}
	_ = hclsyntax.Walk(expr, &w)
	if !w.notOK && w.usedIteration {
		a.usedIteration = true
	}
	return !w.notOK
}

// evaluableWalker tracks the for expression variables in scope as it walks.
type evaluableWalker struct {
	a             *valueAnalyzer
	ctx           *hcl.EvalContext
	bound         []string
	notOK         bool
	usedIteration bool
}

func (w *evaluableWalker) Enter(node hclsyntax.Node) hcl.Diagnostics {
	switch n := node.(type) {
	case *hclsyntax.ForExpr:
		// The collection is evaluated outside the variables the expression
		// binds, which the walk below cannot tell apart.
		outer := evaluableWalker{a: w.a, ctx: w.ctx, bound: slices.Clone(w.bound)}
		_ = hclsyntax.Walk(n.CollExpr, &outer)
		w.notOK = w.notOK || outer.notOK
		w.usedIteration = w.usedIteration || outer.usedIteration
		w.bound = append(w.bound, n.KeyVar, n.ValVar)
	case *hclsyntax.FunctionCallExpr:
		if _, known := w.ctx.Functions[n.Name]; !known {
			w.notOK = true
		}
	case *hclsyntax.ScopeTraversalExpr:
		root := n.Traversal.RootName()
		if slices.Contains(w.bound, root) {
			return nil
		}
		if slices.Contains(w.a.shadowed, root) || w.a.unevaluatedIterator(root) {
			w.notOK = true
			return nil
		}
		if _, known := w.ctx.Variables[root]; !known {
			w.notOK = true
			return nil
		}
		if _, iterated := w.a.iteration[root]; iterated {
			w.usedIteration = true
		}
	}
	return nil
}

func (w *evaluableWalker) Exit(node hclsyntax.Node) hcl.Diagnostics {
	if _, isFor := node.(*hclsyntax.ForExpr); isFor {
		w.bound = w.bound[:len(w.bound)-2]
	}
	return nil
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

func stepName(traversal hcl.Traversal) string {
	if len(traversal) < 2 {
		return ""
	}
	return stepString(traversal[1])
}

// stepString returns the name a traversal step selects when it is a constant.
func stepString(step hcl.Traverser) string {
	switch s := step.(type) {
	case hcl.TraverseAttr:
		return s.Name
	case hcl.TraverseIndex:
		if s.Key.IsKnown() && !s.Key.IsNull() && s.Key.Type() == cty.String {
			return s.Key.AsString()
		}
	}
	return ""
}

// eachIterator binds each to what the for_each collection reads. For an
// instance with a known key, the key and value read only the part of the
// collection holding that key, so an instance the module defines in a
// collection the caller adds to is not attributed to the caller.
func (a *valueAnalyzer) eachIterator(expr hclsyntax.Expression, each cty.Value) iteratorReads {
	it := iteratorReads{name: resourceEachRoot, reads: a.cachedCollectionReads(expr), evaluated: each != cty.NilVal}
	if !it.evaluated || !each.Type().IsObjectType() || !each.Type().HasAttribute("key") {
		return it
	}
	key, _ := each.GetAttr("key").UnmarkDeep()
	if !key.IsKnown() || key.IsNull() || key.Type() != cty.String {
		return it
	}
	if entry, ok := a.eachEntry(expr, key.AsString()); ok {
		it.split, it.keyReads, it.valueReads = true, entry.key, entry.value
		a.usedIteration = true
	}
	return it
}

// collectionReads is what a for_each collection reads. A collection built
// from both module inputs and values of the module's own cannot tell which an
// iteration came from when the instance is not known, so it is ambiguous.
func (a *valueAnalyzer) collectionReads(expr hclsyntax.Expression) inputReads {
	reads := a.reads(expr).shared()
	if a.mixedCollection(expr) {
		reads.ambiguous = true
	}
	return reads
}

// throughLocals replaces a reference to one of the module's locals by the
// expression defining it, as often as it refers to another.
func (a *valueAnalyzer) throughLocals(expr hclsyntax.Expression) hclsyntax.Expression {
	for range maxLocalHops {
		ref, ok := expr.(*hclsyntax.ScopeTraversalExpr)
		if !ok || a.scope == nil || ref.Traversal.RootName() != moduleLocalRoot || len(ref.Traversal) != 2 ||
			slices.Contains(a.shadowed, moduleLocalRoot) {
			return expr
		}
		defined, ok := a.scope.Locals[stepName(ref.Traversal)]
		if !ok {
			return expr
		}
		expr = defined
	}
	return expr
}

// cachedCollectionReads is collectionReads memoized per collection, which
// every instance of a block reads again.
func (a *valueAnalyzer) cachedCollectionReads(expr hclsyntax.Expression) inputReads {
	key := localCacheKey{expr: expr, scope: a.scope}
	if reads, ok := a.cache.collections[key]; ok {
		return reads
	}
	reads := a.collectionReads(expr)
	a.cache.collections[key] = reads
	return reads
}

// mixedCollection reports whether the entries of a collection literal, or of
// the literals merged into it, read module inputs for some and not others.
func (a *valueAnalyzer) mixedCollection(expr hclsyntax.Expression) bool {
	var operands []hclsyntax.Expression
	switch e := a.throughLocals(expr).(type) {
	case *hclsyntax.ParenthesesExpr:
		return a.mixedCollection(e.Expression)
	case *hclsyntax.TupleConsExpr:
		operands = e.Exprs
	case *hclsyntax.ObjectConsExpr:
		return a.mixedObject(e)
	case *hclsyntax.FunctionCallExpr:
		if e.ExpandFinal || !collectionCombinators[e.Name] {
			return false
		}
		operands = e.Args
	default:
		return false
	}
	reading, other := false, false
	for _, operand := range operands {
		if a.mixedCollection(operand) {
			return true
		}
		if a.contributesNothing(operand) {
			continue
		}
		if reads := a.reads(operand); reads.empty() {
			other = true
		} else {
			reading = true
		}
	}
	return reading && other
}

func (a *valueAnalyzer) mixedObject(e *hclsyntax.ObjectConsExpr) bool {
	reading, other := false, false
	for _, item := range e.Items {
		reads := a.reads(item.KeyExpr)
		reads.add(a.reads(item.ValueExpr))
		reading, other = reading || !reads.empty(), other || reads.empty()
		if a.mixedCollection(item.ValueExpr) {
			return true
		}
	}
	return reading && other
}

// contributesNothing reports whether an operand of a collection evaluates to
// an empty collection, which adds no entry of its own.
func (a *valueAnalyzer) contributesNothing(operand hclsyntax.Expression) bool {
	if literal, ok := operand.(*hclsyntax.TupleConsExpr); ok {
		return len(literal.Exprs) == 0
	}
	if literal, ok := operand.(*hclsyntax.ObjectConsExpr); ok {
		return len(literal.Items) == 0
	}
	if reads := a.reads(operand); !reads.empty() {
		return false
	}
	v, ok := a.value(a.throughLocals(operand))
	if !ok || v.IsNull() {
		return false
	}
	switch ty := v.Type(); {
	case ty.IsObjectType():
		return len(ty.AttributeTypes()) == 0
	case ty.IsTupleType() || ty.IsListType() || ty.IsSetType() || ty.IsMapType():
		return v.LengthInt() == 0
	}
	return false
}

// collectionCombinators are the functions building a collection from the
// collections or elements they are given. Choices between alternatives are
// resolved by reads with the evaluated values instead.
var collectionCombinators = map[string]bool{
	"merge": true, "concat": true, "flatten": true, "setunion": true, "distinct": true,
	"tolist": true, "toset": true, "tomap": true,
}

// eachEntry is what the key and the value of one instance of a for_each
// collection read.
type eachEntry struct {
	key, value inputReads
}

// eachIndex is the entries of a for_each collection by instance key, or not
// ok when they cannot be told apart.
type eachIndex struct {
	entries map[string]eachEntry
	ok      bool
}

// eachEntry finds what the instance with the given key reads. The index of the
// collection is built once, so every instance looks its entry up.
func (a *valueAnalyzer) eachEntry(expr hclsyntax.Expression, key string) (eachEntry, bool) {
	cacheKey := localCacheKey{expr: expr, scope: a.scope}
	index, cached := a.cache.eachIndexes[cacheKey]
	if !cached {
		index.entries, index.ok = a.eachEntries(expr)
		a.cache.eachIndexes[cacheKey] = index
	}
	if !index.ok {
		return eachEntry{}, false
	}
	entry, ok := index.entries[key]
	return entry, ok
}

// eachEntries indexes a for_each collection, looking through object
// literals, merge and toset of a list literal. Any other collection is
// indexed by its evaluated value.
func (a *valueAnalyzer) eachEntries(expr hclsyntax.Expression) (map[string]eachEntry, bool) {
	expr = a.throughLocals(expr)
	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return a.eachEntries(e.Expression)
	case *hclsyntax.ObjectConsExpr:
		entries := make(map[string]eachEntry, len(e.Items))
		for _, item := range e.Items {
			name, ok := a.staticKey(item.KeyExpr)
			if !ok {
				return nil, false
			}
			entries[name] = eachEntry{key: a.reads(item.KeyExpr).shared(), value: a.reads(item.ValueExpr).shared()}
		}
		return entries, true
	case *hclsyntax.FunctionCallExpr:
		if entries, ok, known := a.callEntries(e); known {
			return entries, ok
		}
	}
	return a.valueEntries(expr)
}

// callEntries indexes merge and toset of a list literal. known is false for
// any other call.
func (a *valueAnalyzer) callEntries(e *hclsyntax.FunctionCallExpr) (entries map[string]eachEntry, ok, known bool) {
	if e.ExpandFinal {
		return nil, false, false
	}
	switch {
	case e.Name == mergeFunction:
		entries = make(map[string]eachEntry)
		for _, arg := range e.Args {
			part, ok := a.eachEntries(arg)
			if !ok {
				return nil, false, true
			}
			maps.Copy(entries, part)
		}
		return entries, true, true
	case e.Name == toSetFunction && len(e.Args) == 1:
		list, isList := e.Args[0].(*hclsyntax.TupleConsExpr)
		if !isList {
			return nil, false, false
		}
		entries = make(map[string]eachEntry, len(list.Exprs))
		for _, element := range list.Exprs {
			v, ok := a.value(element)
			if !ok || v.IsNull() || v.Type() != cty.String {
				return nil, false, true
			}
			reads := a.reads(element).shared()
			name := v.AsString()
			if earlier, duplicate := entries[name]; duplicate {
				// Two elements make the same instance, so neither alone does.
				reads = earlier.value
				reads.ambiguous = true
			}
			entries[name] = eachEntry{key: reads, value: reads}
		}
		return entries, true, true
	}
	return nil, false, false
}

// valueEntries indexes a collection by its evaluated value, every entry
// reading what the whole collection reads.
func (a *valueAnalyzer) valueEntries(expr hclsyntax.Expression) (map[string]eachEntry, bool) {
	collection, ok := a.value(expr)
	if !ok || collection.IsNull() {
		return nil, false
	}
	var keys []string
	switch ty := collection.Type(); {
	case ty.IsObjectType():
		for name := range ty.AttributeTypes() {
			keys = append(keys, name)
		}
	case ty.IsMapType():
		for it := collection.ElementIterator(); it.Next(); {
			k, _ := it.Element()
			keys = append(keys, k.AsString())
		}
	default:
		return nil, false
	}
	reads := a.reads(expr).shared()
	entries := make(map[string]eachEntry, len(keys))
	for _, k := range keys {
		entries[k] = eachEntry{key: reads, value: reads}
	}
	return entries, true
}

// staticKey returns the name an object literal's key expression gives.
func (a *valueAnalyzer) staticKey(key hclsyntax.Expression) (string, bool) {
	if wrapped, ok := key.(*hclsyntax.ObjectConsKeyExpr); ok {
		if !wrapped.ForceNonLiteral {
			if keyword := hcl.ExprAsKeyword(wrapped.Wrapped); keyword != "" {
				return keyword, true
			}
		}
		key = wrapped.Wrapped
	}
	v, ok := a.value(key)
	if !ok || v.IsNull() {
		return "", false
	}
	v, err := convert.Convert(v, cty.String)
	if err != nil || !v.IsKnown() || v.IsNull() {
		return "", false
	}
	return v.AsString(), true
}
