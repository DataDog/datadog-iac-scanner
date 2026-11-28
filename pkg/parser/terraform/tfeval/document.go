/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// UnknownAttributePlaceholder is stored for an unresolved value that has no
// source text to render, so keys stay present and MissingAttribute checks do not
// treat it as absent (which would false-positive).
const UnknownAttributePlaceholder = partial.UnknownPlaceholder

// AttributesToDocument converts a resolved resource's attributes into the
// map[string]interface{} shape the rule pipeline consumes. Every attribute is
// always included: the parts of a value evaluation could not resolve are
// rendered as their "${expr}" text, as the plain parser does, so presence-based
// rules do not fire false positives on unresolved expressions and a string
// interpolating an unresolved value still carries the rest of its content.
func AttributesToDocument(r *ResolvedResource) map[string]interface{} {
	return AttributesToDocumentWithContext(context.Background(), r)
}

// AttributesToDocumentWithContext is AttributesToDocument with cancellation for
// any data-source expansion needed to render unresolved document references.
func AttributesToDocumentWithContext(ctx context.Context, r *ResolvedResource) map[string]interface{} {
	doc := attributesToDocument(r.Attributes, r.Body, r.DynamicCounts, r.documentScope, newRenderer(ctx, r))
	_ = enrichResourceDocument(ctx, r, doc)
	return doc
}

func enrichResourceDocument(ctx context.Context, r *ResolvedResource, doc map[string]interface{}) bool {
	before, existed := doc["certificate_body"]
	// Keep the legacy certificate representation for every evaluated resource,
	// including effective override bodies. Use the expression's own file when
	// fields come from different configuration files.
	if !r.Data && r.Body != nil && r.Scope != nil && r.Scope.fsys != nil {
		if attr := r.Body.Attributes["certificate_body"]; attr != nil {
			terraform.EnrichResourceCertificate(ctx, r.Scope.fsys, doc, attr.SrcRange.Filename,
				writtenCertificate(attr, r.Scope.sources))
		}
	}
	after, exists := doc["certificate_body"]
	_, beforeObject := before.(map[string]interface{})
	_, afterObject := after.(map[string]interface{})
	return existed && exists && !beforeObject && afterObject
}

// The JSON-to-HCL conversion can change expression offsets. Use the original
// attribute range to recover the written certificate expression.
func writtenCertificate(attr *hclsyntax.Attribute, sources map[string][]byte) string {
	if attr == nil || !tfpath.IsJSONConfig(attr.SrcRange.Filename) {
		return ""
	}
	src := sources[attr.SrcRange.Filename]
	start, end := attr.NameRange.End.Byte, attr.SrcRange.End.Byte
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	_, raw, _ := strings.Cut(string(src[start:end]), ":")
	written, _ := strconv.Unquote(strings.TrimSpace(raw))
	return written
}

// newRenderer renders r's attributes in the context they were evaluated in.
type documentRenderer struct {
	*partial.Renderer
	references   *documentReferenceRenderer
	managedRoots map[string]bool
}

type documentPresentation struct {
	ctx          *hcl.EvalContext
	managedRoots map[string]bool
}

// documentPresentation is initialized lazily because the evaluation context is
// authoritative only after module evaluation completes. The cached context is
// read-only and renderer bindings are always added in child scopes.
func (s *ModuleScope) documentPresentation() *documentPresentation {
	s.presentationOnce.Do(func() {
		presentation := *s.evalCtx
		presentation.Variables = maps.Clone(s.evalCtx.Variables)
		managedRoots := make(map[string]bool)
		if s.static != nil && s.static.resources != nil {
			graph := s.static.resources
			for _, block := range graph.blocks[:graph.resources] {
				presentation.Variables[block.Labels[0]] = cty.DynamicVal
				managedRoots[block.Labels[0]] = true
			}
		}
		s.presentation = &documentPresentation{ctx: &presentation, managedRoots: managedRoots}
	})
	return s.presentation
}

func newRenderer(scanCtx context.Context, r *ResolvedResource) *documentRenderer {
	if r == nil || r.Scope == nil || r.Scope.evalCtx == nil {
		return &documentRenderer{Renderer: &partial.Renderer{}}
	}
	references := documentReferences(scanCtx, r.Scope)
	// Evaluation uses concrete sibling values, but legacy rules also join
	// resources through their reference text. Keep those namespaces unknown
	// only in the presentation context; never feed rendered references back
	// into count/for_each, conditions, or native evaluation.
	presentation := r.Scope.documentPresentation()
	rd := &partial.Renderer{
		Ctx: presentation.ctx, Source: partial.FileSources(r.Scope.sources), Reference: references.forFile(nil),
	}
	return &documentRenderer{Renderer: rd.WithBindings(documentIteration(r)), references: references, managedRoots: presentation.managedRoots}
}

func (r *documentRenderer) withSource(src *attrSource) *documentRenderer {
	if src.file == nil && len(src.bindings) == 0 {
		return r
	}
	next := *r
	if src.file != nil {
		rd := *r.Renderer
		rd.Ctx = partial.Scope(rd.Ctx, src.file.bindings)
		if r.references != nil {
			rd.Reference = r.references.forFile(src.file)
		}
		next.Renderer = &rd
	}
	next.Renderer = next.WithBindings(src.bindings)
	return &next
}

// Root resources omit their iteration map during evaluation. Recover its
// bindings from the concrete key and the already narrowed for_each value,
// without evaluating or copying the original collection for every consumer.
func documentIteration(r *ResolvedResource) map[string]cty.Value {
	if r.Iteration != nil {
		return r.Iteration
	}
	if r.InstanceKey == cty.NilVal || !ctyutil.Materialized(r.InstanceKey) {
		return nil
	}
	if r.InstanceKey.Type() == cty.Number {
		return map[string]cty.Value{metaArgCount: cty.ObjectVal(map[string]cty.Value{countIndexKey: r.InstanceKey})}
	}
	value := cty.DynamicVal
	if collection, ok := r.Attributes[metaArgForEach]; ok && ctyutil.Materialized(collection) && collection.CanIterateElements() {
		it := collection.ElementIterator()
		if it.Next() {
			_, value = it.Element()
		}
	}
	return map[string]cty.Value{rootEach: cty.ObjectVal(map[string]cty.Value{forEachKeyKey: r.InstanceKey, forEachValueKey: value})}
}

const (
	maxDocumentReferenceDepth   = 32
	dataAttributeTraversalSteps = 4
)

// documentReferences recovers partial data-source output only when an
// expression places a reference's value into a document. Its values never enter
// the evaluation context. Completed results are memoized by scope; recursion
// state belongs to this rendering, and canceled or truncated results are not shared.
func documentReferences(ctx context.Context, scope *ModuleScope) *documentReferenceRenderer {
	cache := scope.renderedData
	if cache == nil {
		cache = &sync.Map{}
	}
	return &documentReferenceRenderer{
		scope: scope, ctx: ctx, rendered: cache, visiting: map[documentDataKey]bool{}, cacheable: true,
	}
}

type documentReferenceRenderer struct {
	scope     *ModuleScope
	ctx       context.Context
	rendered  *sync.Map
	cacheable bool
	visiting  map[documentDataKey]bool
	depth     int
}

func (r *documentReferenceRenderer) forFile(view *fileInputView) func(hcl.Traversal, *hcl.EvalContext) (cty.Value, bool) {
	return func(t hcl.Traversal, _ *hcl.EvalContext) (cty.Value, bool) {
		return r.resolve(t, view)
	}
}

func (r *documentReferenceRenderer) evaluationContext(view *fileInputView) *hcl.EvalContext {
	if view == nil {
		return r.scope.evalCtx
	}
	return partial.Scope(r.scope.evalCtx, view.bindings)
}

func (r *documentReferenceRenderer) resolve(t hcl.Traversal, view *fileInputView) (cty.Value, bool) {
	if len(t) < 2 {
		return cty.NilVal, false
	}
	if r.depth >= maxDocumentReferenceDepth {
		r.cacheable = false
		return cty.NilVal, false
	}
	r.depth++
	defer func() { r.depth-- }()
	name, ok := t[1].(hcl.TraverseAttr)
	if !ok {
		return cty.NilVal, false
	}
	switch t.RootName() {
	case rootLocal:
		return r.local(t, name.Name, view)
	case blockTypeData:
		return r.data(t, name.Name, view)
	default:
		return cty.NilVal, false
	}
}

func (r *documentReferenceRenderer) local(t hcl.Traversal, name string, view *fileInputView) (cty.Value, bool) {
	expr := r.scope.Locals[name]
	if expr == nil {
		return cty.NilVal, false
	}
	// A module local belongs to its declaration scope, not the consumer loop.
	alias, known := partial.ReferenceTraversal(expr, r.evaluationContext(view))
	if !known {
		return cty.NilVal, false
	}
	combined := append(append(hcl.Traversal{}, alias...), t[2:]...)
	return r.resolve(combined, view)
}

func (r *documentReferenceRenderer) data(t hcl.Traversal, typ string, view *fileInputView) (cty.Value, bool) {
	if len(t) < dataAttributeTraversalSteps {
		return cty.NilVal, false
	}
	label, ok := t[2].(hcl.TraverseAttr)
	if !ok {
		return cty.NilVal, false
	}
	key := documentDataKey{typ: typ, name: label.Name}
	end := 3
	if index, indexed := t[end].(hcl.TraverseIndex); indexed {
		value, _ := index.Key.Unmark()
		if !ctyutil.Materialized(value) {
			return cty.NilVal, false
		}
		key.instance = value.GoString()
		end++
	}
	data, exists := r.scope.dataSources[key]
	if view != nil && view.recomputed[documentDataKey{typ: key.typ, name: key.name}] {
		data, exists = view.data[key]
	}
	if !exists {
		return cty.NilVal, false
	}
	v, ok := r.render(key, data, view)
	if !ok {
		return cty.NilVal, false
	}
	v, diags := t[end:].TraverseRel(v)
	return v, !diags.HasErrors()
}

type documentDataKey struct {
	typ, name, instance string
}

type documentDataSource struct {
	source    localdata.Source
	body      hcl.Body
	iteration map[string]cty.Value
	filename  string
	json      bool
	directed  bool
	files     map[string]*fileInputView
}

func (r *documentReferenceRenderer) render(key documentDataKey, data documentDataSource, view *fileInputView) (cty.Value, bool) {
	cache := r.rendered
	if view != nil {
		cache = &view.rendered
	}
	if v, ok := cache.Load(key); ok {
		return v.(cty.Value), true
	}
	if r.visiting[key] {
		r.cacheable = false
		return cty.NilVal, false
	}
	if r.ctx.Err() != nil {
		return cty.NilVal, false
	}
	r.visiting[key] = true
	defer delete(r.visiting, key)
	renderer := func(expressionView *fileInputView) *partial.Renderer {
		return (&partial.Renderer{
			Ctx: r.evaluationContext(expressionView), Source: partial.FileSources(r.scope.sources),
			Reference: r.forFile(expressionView),
		}).WithBindings(data.iteration)
	}
	rd := renderer(view)
	eval := rd.Render
	if data.json || data.directed {
		eval = func(expr hcl.Expression) (cty.Value, bool) {
			scoped := rd
			if data.directed {
				scoped = renderer(data.files[expr.Range().Filename])
			}
			if data.json {
				return renderDataJSON(scoped, expr, r.scope.sources[data.filename])
			}
			return scoped.Render(expr)
		}
	}
	attrs := data.source(r.ctx, data.body, eval)
	if r.ctx.Err() != nil {
		r.cacheable = false
		return cty.NilVal, false
	}
	values := make(map[string]cty.Value, len(attrs))
	for name, value := range attrs {
		values[name] = cty.StringVal(value)
	}
	v := objectOrEmpty(values)
	if r.cacheable {
		cache.Store(key, v)
	}
	return v, true
}

func renderDataJSON(rd *partial.Renderer, expr hcl.Expression, src []byte) (cty.Value, bool) {
	if inner, vars, ok := partial.Unbind(expr); ok {
		scoped := rd.WithBindings(vars)
		return renderDataJSON(scoped, inner, src)
	}
	return rd.Render(jsonExprToHCL(expr, src))
}

// attrSource locates the HCL that produced a value so unresolved values can fall
// back to their reference text. Exactly one field is set, or none when the value
// cannot be traced back to a specific expression or block.
type attrSource struct {
	scope      *documentScope
	bindings   map[string]cty.Value
	file       *fileInputView
	expr       hclsyntax.Expression // attribute value expression
	body       *hclsyntax.Body      // body of a single nested block
	blocks     []*hclsyntax.Block   // nested blocks sharing one type
	labelDepth int
	// counts is how many elements each of blocks generated, when known: one for
	// a static block, the evaluated count for a dynamic block's content.
	counts []int
	// dynamic is how many blocks each dynamic block of the resource generated.
	dynamic DynamicCounts
	// iterators are the loop variable names of the dynamic blocks whose
	// generated content this source sits in. The renderer's context binds none
	// of them, so an expression reading one must not render through it: parts
	// evaluation had resolved would come back as their text. The value is
	// walked by element instead, keeping what evaluation produced.
	iterators []string
}

// generatedBlockType marks the content of a dynamic block among the blocks of
// an attrSource; no HCL block type contains a space.
const generatedBlockType = "dynamic content"

// blocksFor returns the blocks that produced n elements, one entry per element.
// With the generated counts of the dynamic blocks known, each block is repeated
// as often as it generated, and the sources go unmapped when the counts do not
// add up to n. Without them it falls back to inferring the split from n: every
// source block when the counts line up, the static blocks alone when the
// dynamic ones generated none, or a single dynamic block's content once per
// element it generated, in place. Several dynamic blocks of one type leave that
// inference ambiguous.
func (s *attrSource) blocksFor(n int) []*hclsyntax.Block {
	if blocks, ok := s.blocksFromCounts(n); ok {
		return blocks
	}
	if len(s.blocks) == n {
		return s.blocks
	}
	dynamic := 0
	for _, b := range s.blocks {
		if b.Type == generatedBlockType {
			dynamic++
		}
	}
	static := len(s.blocks) - dynamic
	switch {
	case static == n:
		out := make([]*hclsyntax.Block, 0, static)
		for _, b := range s.blocks {
			if b.Type != generatedBlockType {
				out = append(out, b)
			}
		}
		return out
	case dynamic == 1 && n > static:
		out := make([]*hclsyntax.Block, 0, n)
		for _, b := range s.blocks {
			if b.Type != generatedBlockType {
				out = append(out, b)
				continue
			}
			for range n - static {
				out = append(out, b)
			}
		}
		return out
	}
	return s.blocks
}

// blocksFromCounts expands the source blocks by how many elements each
// generated; ok is false when a count is not known.
func (s *attrSource) blocksFromCounts(n int) (blocks []*hclsyntax.Block, ok bool) {
	if len(s.counts) != len(s.blocks) || s.counts == nil {
		return nil, false
	}
	total := 0
	for _, c := range s.counts {
		if c < 0 {
			return nil, false
		}
		total += c
	}
	if total != n {
		return nil, true
	}
	out := make([]*hclsyntax.Block, 0, n)
	for i, b := range s.blocks {
		for range s.counts[i] {
			out = append(out, b)
		}
	}
	return out, true
}

func attributesToDocument(
	attrs map[string]cty.Value, body *hclsyntax.Body, dynamic DynamicCounts, scope *documentScope, rd *documentRenderer,
) map[string]interface{} {
	return attributesToDocumentWithFacts(attrs, body, dynamic, scope, rd, nil)
}

func attributesToDocumentWithFacts(
	attrs map[string]cty.Value,
	body *hclsyntax.Body,
	dynamic DynamicCounts,
	scope *documentScope,
	rd *documentRenderer,
	facts *terraformValueFacts,
) map[string]interface{} {
	out := make(map[string]interface{}, len(attrs))
	if facts == nil {
		for key, val := range attrs {
			src := sourceFor(body, key, dynamic, nil, scope)
			out[key] = ctyValueToDocument(val, &src, rd)
		}
		return out
	}
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		val := attrs[key]
		src := sourceFor(body, key, dynamic, nil, scope)
		var path model.TerraformFactPath
		if facts.nodes >= maxTerraformFactNodes {
			facts.markTruncated()
		} else {
			path = model.TerraformFactPath{model.TerraformKeySegment(key)}
		}
		out[key] = ctyValueToDocumentWithFacts(val, &src, rd, facts, path)
	}
	return out
}

// sourceFor finds the attribute expression or nested blocks that produced key,
// under the iterators of the dynamic blocks enclosing body.
func sourceFor(body *hclsyntax.Body, key string, dynamic DynamicCounts, iterators []string, scope *documentScope) attrSource {
	if body == nil {
		return attrSource{}
	}
	if attr, ok := body.Attributes[key]; ok && attr != nil {
		var file *fileInputView
		if scope != nil {
			file = scope.files[attr.SrcRange.Filename]
		}
		return attrSource{expr: attr.Expr, iterators: iterators, scope: scope, file: file}
	}
	var blocks []*hclsyntax.Block
	var counts []int
	for _, b := range body.Blocks {
		switch {
		case b.Type == key:
			if count, ok := asWrittenCount(dynamic, b); ok {
				blocks = append(blocks, b)
				counts = append(counts, count)
			}
		case dynamicblock.Is(b) && dynamicblock.GeneratedType(b) == key:
			if scope != nil {
				if generated, ok := scope.generated[b]; ok {
					for _, marker := range generated {
						blocks = append(blocks, marker)
						counts = append(counts, 1)
					}
					continue
				}
			}
			// Every dynamic block of this type stands in as one marker; counts
			// say how many blocks it generated, none when kept as written.
			if marker, ok := generatedMarker(b); ok {
				blocks = append(blocks, marker)
				counts = append(counts, generatedCount(dynamic, b))
				iterators = append(iterators, dynamicblock.IteratorName(b))
			}
		}
	}
	if dynamic == nil {
		counts = nil
	}
	return attrSource{blocks: blocks, counts: counts, dynamic: dynamic, iterators: iterators, scope: scope}
}

// anyLabel stands for a label of a generated block that is only known once
// evaluated, in the labels of its marker.
const anyLabel = "\x00any"

// generatedMarker stands for the blocks a dynamic block generates among the
// blocks of an attrSource. It carries one anyLabel per label the generated
// blocks take, so a labeled dynamic block maps through the same path as a
// labeled static one; ok is false when it cannot, because the labels or the
// content are not statically known.
func generatedMarker(b *hclsyntax.Block) (marker *hclsyntax.Block, ok bool) {
	content := dynamicblock.Content(b)
	if content == nil {
		return nil, false
	}
	var labels []string
	if attr, has := b.Body.Attributes["labels"]; has {
		tuple, isTuple := attr.Expr.(*hclsyntax.TupleConsExpr)
		if !isTuple {
			return nil, false
		}
		labels = make([]string, len(tuple.Exprs))
		for i := range labels {
			labels[i] = anyLabel
		}
	}
	return &hclsyntax.Block{Type: generatedBlockType, Labels: labels, Body: content}, true
}

// generatedCount is how many blocks the dynamic block b generated; a block the
// evaluation never reached generated none.
func generatedCount(dynamic DynamicCounts, b *hclsyntax.Block) int {
	n, ok := dynamic[b]
	if !ok || n == keptAsWritten {
		return 0
	}
	return n
}

// asWrittenCount is how many elements the source b contributes as written under
// its own key: a static block always, a dynamic block only when kept as written.
// An expanded dynamic block contributes nothing under the key, since its blocks
// are generated under their own type.
func asWrittenCount(dynamic DynamicCounts, b *hclsyntax.Block) (int, bool) {
	if !dynamicblock.Is(b) || dynamic == nil {
		return 1, true
	}
	n, seen := dynamic[b]
	switch {
	case !seen:
		return 0, false
	case n == keptAsWritten:
		return 1, true
	case n == unknownDynamicCount:
		return unknownDynamicCount, true
	default:
		return 0, false
	}
}

// ctyValueToDocument converts a cty.Value to a JSON-serializable value, using
// src to recover what an unresolved value looked like in the configuration.
// rd renders unresolved values and retains direct resource references for
// legacy joins. Known collections retain their source mapping for that purpose.
func ctyValueToDocument(v cty.Value, src *attrSource, rd *documentRenderer) interface{} {
	return ctyValueToDocumentWithFacts(v, src, rd, nil, nil)
}

func ctyValueToDocumentWithFacts(
	v cty.Value,
	src *attrSource,
	rd *documentRenderer,
	facts *terraformValueFacts,
	path model.TerraformFactPath,
) interface{} {
	if facts != nil && (len(path) > maxTerraformFactDepth || facts.nodes >= maxTerraformFactNodes) {
		facts.markTruncated()
		return ctyValueToDocument(v, src, rd)
	}
	rendered, renderer, presentation, ok := rd.renderValue(v, src)
	if ok {
		if facts != nil {
			facts.append(path, nativeFactState(v), presentation, model.TerraformChildrenUnknown)
		}
		return rendered
	}
	rd = renderer
	if v == cty.NilVal {
		var renderer *partial.Renderer
		if rd != nil {
			renderer = rd.Renderer
		}
		value, _ := unresolvedToDocumentWithPresentation(src.expr, renderer)
		return value
	}
	if !v.IsKnown() {
		return unresolvedValueToDocument(src, rd, facts, path)
	}
	if v.IsNull() {
		if facts != nil {
			facts.append(path, model.TerraformNativeNull, model.TerraformPresentationNative, model.TerraformChildrenUnknown)
		}
		return nil
	}
	return knownValueToDocument(v, src, rd, facts, path)
}

func unresolvedValueToDocument(
	src *attrSource, rd *documentRenderer, facts *terraformValueFacts, path model.TerraformFactPath,
) interface{} {
	var renderer *partial.Renderer
	if rd != nil {
		renderer = rd.Renderer
	}
	value, presentation := unresolvedToDocumentWithPresentation(src.expr, renderer)
	if facts != nil {
		facts.append(path, model.TerraformNativeUnknown, presentation, model.TerraformChildrenUnknown)
	}
	return value
}

func knownValueToDocument(
	v cty.Value, src *attrSource, rd *documentRenderer, facts *terraformValueFacts, path model.TerraformFactPath,
) interface{} {
	t := v.Type()
	if !isDocumentableType(t) {
		if facts != nil {
			facts.append(path, nativeFactState(v), model.TerraformPresentationUnknownPlaceholder, model.TerraformChildrenUnknown)
		}
		return UnknownAttributePlaceholder
	}
	children, factIndex := knownValueFacts(v, src, facts, path)
	if factsNeedLegacyAggregate(facts, v, path) {
		facts.markTruncated()
		facts.markUnproven(factIndex)
		return ctyValueToDocument(v, src, rd)
	}
	if facts != nil && t.IsSetType() && !v.IsWhollyKnown() {
		// Set display indices can reorder when a member is unknown.
		return ctyValueToDocument(v, src, rd)
	}
	if scalar, ok := ctyScalarToDocument(v); ok {
		return scalar
	}
	if facts != nil && factIndex >= 0 {
		facts.pushAncestor(factIndex)
	}
	value, childState := aggregateValueToDocument(v, src, rd, facts, path, children)
	if facts != nil && factIndex >= 0 {
		facts.popAncestor()
		facts.values[factIndex].Children = childState
	}
	return value
}

func factsNeedLegacyAggregate(facts *terraformValueFacts, v cty.Value, path model.TerraformFactPath) bool {
	if facts == nil || !isDocumentAggregate(v.Type()) || !hasChildren(v) {
		return false
	}
	return len(path) >= maxTerraformFactDepth || facts.nodes >= maxTerraformFactNodes
}

func knownValueFacts(
	v cty.Value, src *attrSource, facts *terraformValueFacts, path model.TerraformFactPath,
) (children model.TerraformChildrenState, factIndex int) {
	if facts == nil {
		return model.TerraformChildrenUnknown, -1
	}
	state := nativeFactState(v)
	presentation := nativeFactPresentation(v, src)
	children = nativeFactChildren(v, src, presentation)
	factIndex = facts.append(path, state, presentation, children)
	return
}

func ctyScalarToDocument(v cty.Value) (interface{}, bool) {
	switch v.Type() {
	case cty.String:
		return v.AsString(), true
	case cty.Bool:
		return v.True(), true
	case cty.Number:
		return json.Number(v.AsBigFloat().Text('f', -1)), true
	default:
		return nil, false
	}
}

func aggregateValueToDocument(
	v cty.Value, src *attrSource, rd *documentRenderer, facts *terraformValueFacts,
	path model.TerraformFactPath, children model.TerraformChildrenState,
) (interface{}, model.TerraformChildrenState) {
	t := v.Type()
	if t.IsTupleType() || t.IsListType() || t.IsSetType() {
		return ctySeqToDocumentWithFacts(v, src, rd, facts, path), children
	}
	if t.IsObjectType() || t.IsMapType() {
		return ctyMapToDocumentWithFacts(v, src, rd, facts, path)
	}
	return UnknownAttributePlaceholder, children
}

func isDocumentAggregate(t cty.Type) bool {
	return t.IsTupleType() || t.IsListType() || t.IsSetType() || t.IsObjectType() || t.IsMapType()
}

func hasChildren(v cty.Value) bool {
	if v == cty.NilVal || v.IsMarked() || !v.IsKnown() || v.IsNull() {
		return false
	}
	t := v.Type()
	switch {
	case t.IsTupleType():
		return t.Length() > 0
	case t.IsObjectType():
		return len(t.AttributeTypes()) > 0
	case t.IsListType(), t.IsSetType(), t.IsMapType():
		return v.LengthInt() > 0
	default:
		return false
	}
}

func isDocumentableType(t cty.Type) bool {
	return isDocumentAggregate(t) || t.Equals(cty.String) || t.Equals(cty.Bool) || t.Equals(cty.Number)
}

func unresolvedToDocumentWithPresentation(expr hclsyntax.Expression, rd *partial.Renderer) (interface{}, model.TerraformPresentation) {
	if expr == nil {
		return UnknownAttributePlaceholder, model.TerraformPresentationUnknownPlaceholder
	}
	if rd == nil {
		rd = &partial.Renderer{}
	}
	if value, ok := rd.Render(expr); ok {
		return ctyValueToDocument(value, &attrSource{}, nil), model.TerraformPresentationSourceExpression
	}
	return UnknownAttributePlaceholder, model.TerraformPresentationUnknownPlaceholder
}

// renderValue handles source-aware presentation before ordinary cty conversion.
// Known collections keep their renderer so nested reference identity survives.
func (rd *documentRenderer) renderValue(
	v cty.Value,
	src *attrSource,
) (interface{}, *documentRenderer, model.TerraformPresentation, bool) {
	if rd == nil {
		return nil, nil, model.TerraformPresentationNative, false
	}
	rd = rd.withSource(src)
	canRender := src.expr != nil && !readsIterator(src.expr, src.iterators)
	if canRender {
		if text, ok := managedReferenceText(src.expr, rd.Ctx, rd.managedRoots); ok {
			return text, nil, model.TerraformPresentationManagedReference, true
		}
	}
	if v.IsWhollyKnown() {
		if !v.CanIterateElements() {
			rd = nil
		}
		return nil, rd, model.TerraformPresentationNative, false
	}
	if canRender {
		if rendered, ok := rd.RenderUnresolved(src.expr); ok {
			return ctyValueToDocument(rendered, &attrSource{}, nil), nil, model.TerraformPresentationSourceExpression, true
		}
	}
	return nil, rd, model.TerraformPresentationNative, false
}

// managedReferenceText preserves exact resource links in the legacy payload,
// including selectors bound by a resource or dynamic-block instance.
func managedReferenceText(expr hclsyntax.Expression, ctx *hcl.EvalContext, managedRoots map[string]bool) (string, bool) {
	if wrap, ok := expr.(*hclsyntax.TemplateWrapExpr); ok {
		expr = wrap.Wrapped
	}
	traversal, ok := partial.ReferenceTraversal(expr, ctx)
	if !ok || !managedRoots[traversal.RootName()] {
		return "", false
	}
	return (&partial.Renderer{}).Text(&hclsyntax.ScopeTraversalExpr{Traversal: traversal})
}

// readsIterator reports whether expr reads one of the dynamic block iterators
// in iterators, which the renderer's context does not bind.
func readsIterator(expr hclsyntax.Expression, iterators []string) bool {
	if len(iterators) == 0 {
		return false
	}
	for _, traversal := range expr.Variables() {
		if slices.Contains(iterators, traversal.RootName()) {
			return true
		}
	}
	return false
}

// ctySeqToDocument converts a tuple/list/set to a slice.
func ctySeqToDocument(v cty.Value, src *attrSource, rd *documentRenderer) []interface{} {
	return ctySeqToDocumentWithFacts(v, src, rd, nil, nil)
}

func ctySeqToDocumentWithFacts(
	v cty.Value,
	src *attrSource,
	rd *documentRenderer,
	facts *terraformValueFacts,
	path model.TerraformFactPath,
) []interface{} {
	if facts != nil && (len(path) >= maxTerraformFactDepth || facts.nodes >= maxTerraformFactNodes) {
		facts.markTruncated()
		return ctySeqToDocument(v, src, rd)
	}
	n := v.LengthInt()
	elemSrcs := seqElementSources(src, n)
	list := make([]interface{}, 0, n)
	for i, it := 0, v.ElementIterator(); it.Next(); i++ {
		_, ev := it.Element()
		var es attrSource
		if i < len(elemSrcs) {
			es = elemSrcs[i]
		}
		childFacts := facts
		childPath, capture := facts.childPath(path, model.TerraformIndexSegment(i))
		if facts != nil && !capture {
			childFacts = nil
		}
		list = append(list, ctyValueToDocumentWithFacts(ev, &es, rd, childFacts, childPath))
	}
	return list
}

// seqElementSources pairs sequence elements with the HCL they came from, which
// only holds when the lengths line up (evaluation preserves element order).
func seqElementSources(src *attrSource, n int) []attrSource {
	if blocks := src.blocksFor(n); len(blocks) == n {
		out := make([]attrSource, n)
		for i, b := range blocks {
			if src.labelDepth >= len(b.Labels) {
				out[i] = blockSource(src, b)
			} else {
				out[i] = attrSource{
					blocks: []*hclsyntax.Block{b}, labelDepth: src.labelDepth, counts: singleCount(src),
					iterators: src.iterators, dynamic: src.dynamic, scope: src.scope,
				}
			}
		}
		return out
	}
	if tuple, ok := src.expr.(*hclsyntax.TupleConsExpr); ok && len(tuple.Exprs) == n {
		out := make([]attrSource, n)
		for i, e := range tuple.Exprs {
			out[i] = attrSource{expr: e, iterators: src.iterators}
		}
		return out
	}
	return nil
}

// blockSource enters one concrete generated block's presentation scope.
func blockSource(src *attrSource, block *hclsyntax.Block) attrSource {
	out := attrSource{body: block.Body, iterators: src.iterators, dynamic: src.dynamic, scope: src.scope}
	if src.scope != nil {
		if child := src.scope.children[block]; child != nil {
			out.scope = child
			out.bindings = child.variables
			out.file = child.file
		}
	}
	return out
}

// ctyMapToDocument converts an object/map to a Go map; non-string or unknown
// keys are skipped (keys are always strings in well-formed Terraform).
func ctyMapToDocument(v cty.Value, src *attrSource, rd *documentRenderer) map[string]interface{} {
	obj, _ := ctyMapToDocumentWithFacts(v, src, rd, nil, nil)
	return obj
}

func ctyMapToDocumentWithFacts(
	v cty.Value,
	src *attrSource,
	rd *documentRenderer,
	facts *terraformValueFacts,
	path model.TerraformFactPath,
) (map[string]interface{}, model.TerraformChildrenState) {
	if facts != nil && (len(path) >= maxTerraformFactDepth || facts.nodes >= maxTerraformFactNodes) {
		facts.markTruncated()
		return ctyMapToDocument(v, src, rd), nativeFactChildren(v, src, nativeFactPresentation(v, src))
	}
	body, rd, src := mapDocumentSource(src, rd)
	items := objectConsSources(src.expr)
	obj := make(map[string]interface{}, v.LengthInt())
	children := model.TerraformChildrenClosed
	for it := v.ElementIterator(); it.Next(); {
		key, ev := it.Element()
		name, ok := ctyutil.ConcreteString(key)
		if !ok {
			children = model.TerraformChildrenOpen
			continue
		}
		childFacts := facts
		childPath, capture := facts.childPath(path, model.TerraformKeySegment(name))
		if facts != nil && (!capture || key.IsMarked()) {
			childFacts = nil
			if key.IsMarked() {
				children = model.TerraformChildrenUnknown
			}
		}
		es := mapElementSource(body, items, src, name)
		obj[name] = ctyValueToDocumentWithFacts(ev, &es, rd, childFacts, childPath)
	}
	return obj, mapChildrenState(children, src.dynamic)
}

func mapDocumentSource(src *attrSource, rd *documentRenderer) (*hclsyntax.Body, *documentRenderer, *attrSource) {
	body := src.body
	if blocks := src.blocksFor(1); body == nil && len(blocks) == 1 && src.labelDepth >= len(blocks[0].Labels) {
		body = blocks[0].Body
		block := blockSource(src, blocks[0])
		if rd != nil {
			rd = rd.withSource(&block)
		}
		src = &block
	}
	return body, rd, src
}

func mapChildrenState(children model.TerraformChildrenState, dynamic DynamicCounts) model.TerraformChildrenState {
	for _, count := range dynamic {
		if count == unknownDynamicCount {
			return model.TerraformChildrenOpen
		}
	}
	return children
}

func mapElementSource(body *hclsyntax.Body, items map[string]hclsyntax.Expression, src *attrSource, name string) attrSource {
	switch {
	case body != nil:
		return sourceFor(body, name, src.dynamic, src.iterators, src.scope)
	case items[name] != nil:
		return attrSource{expr: items[name], iterators: src.iterators}
	case len(src.blocks) > 0:
		return labeledBlockSource(src, name)
	default:
		return attrSource{}
	}
}

func labeledBlockSource(src *attrSource, label string) attrSource {
	blocks := make([]*hclsyntax.Block, 0, len(src.blocks))
	var counts []int
	for i, block := range src.blocks {
		if src.labelDepth >= len(block.Labels) {
			continue
		}
		if got := block.Labels[src.labelDepth]; got == label || got == anyLabel {
			blocks = append(blocks, block)
			if len(src.counts) == len(src.blocks) {
				count := src.counts[i]
				if block.Type == generatedBlockType && (src.scope == nil || src.scope.children[block] == nil) {
					// Only some of the blocks it generated carry this label.
					count = unknownDynamicCount
				}
				counts = append(counts, count)
			}
		}
	}
	return attrSource{
		blocks: blocks, labelDepth: src.labelDepth + 1, counts: counts,
		iterators: src.iterators, dynamic: src.dynamic, scope: src.scope,
	}
}

// singleCount is the counts of a source reduced to one block of its own.
func singleCount(src *attrSource) []int {
	if src.counts == nil {
		return nil
	}
	return []int{1}
}

// objectConsSources maps the statically known keys of an object constructor to
// their value expressions.
func objectConsSources(expr hclsyntax.Expression) map[string]hclsyntax.Expression {
	cons, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return nil
	}
	out := make(map[string]hclsyntax.Expression, len(cons.Items))
	for _, item := range cons.Items {
		k, diags := item.KeyExpr.Value(nil)
		if diags.HasErrors() {
			continue
		}
		key, ok := ctyutil.ConcreteString(k)
		if !ok {
			continue
		}
		out[key] = item.ValueExpr
	}
	return out
}

// RemoteResolver maps a non-local module call to its selected directory and acquired package root.
type RemoteResolver func(
	source, version, callerFile, moduleName string,
) (dir, packageRoot string, ok bool)

func CalledModuleDirs(dir string, resolver RemoteResolver, fsys vfs.FS) []string {
	bodies, _, err := parseDir(context.Background(), dir, "", nil, fsys)
	if err != nil {
		return nil
	}
	return calledModuleDirs(context.Background(), dir, bodies, resolver, fsys)
}

func (e *Evaluator) CalledModuleDirs(dir string) []string {
	return e.CalledModuleDirsWithContext(context.Background(), dir)
}

// CalledModuleDirsWithContext retains the scan's root and confinement cache
// during discovery, which shares parsed directories with module evaluation.
func (e *Evaluator) CalledModuleDirsWithContext(ctx context.Context, dir string) []string {
	parsed := e.parseDir(ctx, dir, "")
	if parsed.err != nil {
		return nil
	}
	return calledModuleDirs(ctx, dir, parsed.bodies, e.remoteResolver, e.fsys)
}

func calledModuleDirs(ctx context.Context, dir string, bodies []*hclsyntax.Body, resolver RemoteResolver, fsys vfs.FS) []string {
	moduleBlocks := collectModuleBlocks(bodies)

	emptyCtx := &hcl.EvalContext{}
	var dirs []string
	for _, mb := range moduleBlocks {
		source := ctyutil.StringFromAttribute(mb.Body.Attributes["source"], emptyCtx)
		if source == "" {
			continue
		}
		if localDir, local, err := tfmodules.LocalModuleDirWithContext(ctx, fsys, dir, source); local {
			if err == nil {
				dirs = append(dirs, localDir)
			}
			continue
		}
		if resolver != nil {
			version := ctyutil.StringFromAttribute(mb.Body.Attributes["version"], emptyCtx)
			if d, _, ok := resolver(source, version, mb.TypeRange.Filename, blockLabel(mb)); ok {
				dirs = append(dirs, d)
			}
		}
	}
	return dirs
}

// CalledLocalDirs returns the resolved directories of every local module called
// from dir. Remote/registry sources are ignored.
func CalledLocalDirs(dir string, fsys vfs.FS) []string {
	return CalledModuleDirs(dir, nil, fsys)
}
