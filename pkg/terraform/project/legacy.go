/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"context"
	"encoding/json"
	slashpath "path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// localNamespace is the root name the module's locals are read through.
const localNamespace = "local"

// JoinRoot joins a scan base and a model-relative file. The model stores
// relative paths with forward slashes. A base that uses forward slashes, as
// the in-memory filesystem does, stays that way: filepath.Join would rewrite
// it to the OS separator and the file would no longer match. A file outside
// the base (a module package) is cleaned of its "..".
func JoinRoot(base, rel string) string {
	rel = filepath.ToSlash(rel)
	if strings.Contains(base, `\`) {
		return filepath.Join(base, filepath.FromSlash(rel))
	}
	if base == "" || base == "." {
		return rel
	}
	return slashpath.Clean(strings.TrimRight(base, "/") + "/" + strings.TrimLeft(rel, "/"))
}

// LegacyOptions configure Legacy.
type LegacyOptions struct {
	// Base is the scan base the block files are relative to.
	Base string
	// Placeholder stands for unknown values nested in an attribute.
	Placeholder string
	// FileID returns the id of the scanned file at an absolute path; blocks
	// of files it does not know are left out.
	FileID func(path string) (string, bool)
	// Taken records root-module files already emitted by an earlier call, so
	// roots evaluated one at a time do not report the same written file twice.
	Taken map[string]struct{}
	// InstanceID returns the id of the document of a module instance from
	// the id of its file; nil appends the root and module address.
	InstanceID func(fileID string, m *model.Module) string
}

// LegacyDoc is one document of Legacy.
type LegacyDoc struct {
	Doc  map[string]any
	Path string
	// Module is the module instance the document holds the blocks of, nil
	// for the root module of a root.
	Module *model.Module
	// Instances names, by the key a block instance has in Doc, the block
	// label and instance key it was written with.
	Instances map[LegacyKey]LegacyInstance
}

// LegacyKey is the block kind, type and document key of an expanded block.
type LegacyKey struct{ Kind, Type, Name string }

// LegacyInstance is the label and count or for_each key of an expanded block.
type LegacyInstance struct{ Label, Suffix string }

// Legacy rebuilds the documents of the rules written before the contract input: one
// document per scanned file, {"id", "file", "resource": {type: {name: {...}}},
// "data", "module", "variable", "output", "provider", "locals"}. A block
// with count or for_each has one entry per instance, keyed by the label and
// the instance key ("b[0]"); a nested block written once is an object, a
// nested block written several times a list. The blocks of a module instance
// are a document of their own, per instance, so each call is evaluated and
// attributed separately. A wholly unknown attribute is its expression as
// "${...}", an unknown part of a value the placeholder. A reference to
// another block of its module keeps its source text wherever it appears, as
// the documents the rules were written against carried it.
func Legacy(roots []*model.Root, opts LegacyOptions) []map[string]any {
	docs := LegacyDocs(roots, opts)
	out := make([]map[string]any, len(docs))
	for i := range docs {
		out[i] = docs[i].Doc
	}
	return out
}

// LegacyDocs is Legacy with what each document was built from.
func LegacyDocs(roots []*model.Root, opts LegacyOptions) []*LegacyDoc {
	conv := value.Converter{Placeholder: opts.Placeholder}
	renders := map[*model.Module]*legacyRender{}
	owners := map[string]*model.Module{}
	docs := map[string]*LegacyDoc{}
	var order []string
	for _, r := range roots {
		for _, m := range r.Modules {
			for _, b := range m.Blocks {
				path := JoinRoot(opts.Base, b.File)
				key, asInstance, skip := legacyDocPlacement(opts, owners, path, r, m, b)
				if skip {
					continue
				}
				d, ok := docs[key]
				if !ok {
					id, known := opts.FileID(path)
					if !known {
						continue
					}
					d = &LegacyDoc{Path: path}
					if asInstance {
						d.Module = m
						id = instanceID(opts, id, r, m)
					} else {
						owners[path] = m
						if opts.Taken != nil {
							opts.Taken[path] = struct{}{}
						}
					}
					d.Doc = map[string]any{"id": id, "file": path}
					docs[key] = d
					order = append(order, key)
				}
				d.add(b, conv, renders)
			}
		}
	}
	out := make([]*LegacyDoc, 0, len(order))
	for _, key := range order {
		out = append(out, docs[key])
	}
	return out
}

// legacyDocPlacement chooses the document key for a block. Resource, data and
// ephemeral blocks of a module instance stay on a per-instance document.
// Everything else of a module directory is reported once on the written file,
// as before the contract input, so roots do not multiply the same static finding.
func legacyDocPlacement(
	opts LegacyOptions, owners map[string]*model.Module, path string, r *model.Root, m *model.Module, b *model.Block,
) (key string, asInstance, skip bool) {
	instanceKind := b.Kind == address.KindResource || b.Kind == address.KindData || b.Kind == address.KindEphemeral
	if m.Address != "" && instanceKind {
		return path + "\x00" + r.ID + "\x00" + m.Address, true, false
	}
	if _, seen := opts.Taken[path]; seen && owners[path] == nil {
		return "", false, true
	}
	if owner, ok := owners[path]; ok && owner != m && m.Address == "" {
		return "", false, true
	}
	return path, false, false
}

func instanceID(opts LegacyOptions, fileID string, r *model.Root, m *model.Module) string {
	if opts.InstanceID != nil {
		return opts.InstanceID(fileID, m)
	}
	return fileID + "\x00" + r.ID + "|" + m.Address
}

func (d *LegacyDoc) add(b *model.Block, conv value.Converter, renders map[*model.Module]*legacyRender) {
	switch b.Kind {
	case address.KindResource, address.KindData, address.KindEphemeral:
		byName := child(child(d.Doc, b.Kind), b.Type)
		for _, inst := range b.Instances {
			name := b.Name + inst.Key
			byName[name] = legacyAttrs(b, inst, conv, renderOf(b.Module, inst, conv, renders))
			if inst.Key != "" {
				if d.Instances == nil {
					d.Instances = map[LegacyKey]LegacyInstance{}
				}
				d.Instances[LegacyKey{Kind: b.Kind, Type: b.Type, Name: name}] = LegacyInstance{Label: b.Name, Suffix: inst.Key}
			}
		}
	case address.KindModule:
		// A call to a local module is evaluated through the module's own
		// documents; reporting the call too would flag one problem twice.
		if resolvedLocalCall(b) {
			return
		}
		addLegacyBlock(d.Doc, b, legacyAttrs(b, firstInstance(b), conv, renderOf(b.Module, firstInstance(b), conv, renders)))
	default:
		var inst *model.Instance
		if len(b.Instances) > 0 {
			inst = b.Instances[0]
		}
		addLegacyBlock(d.Doc, b, legacyAttrs(b, inst, conv, renderOf(b.Module, inst, conv, renders)))
	}
}

// renderOf is the renderer of the blocks of module m; one per module, with
// the iteration of the instance added when it has one.
func renderOf(m *model.Module, inst *model.Instance, conv value.Converter, renders map[*model.Module]*legacyRender) *legacyRender {
	lr, ok := renders[m]
	if !ok {
		lr = newLegacyRender(m, conv)
		renders[m] = lr
	}
	return lr.forInstance(inst)
}

func firstInstance(b *model.Block) *model.Instance {
	if len(b.Instances) == 0 {
		return nil
	}
	return b.Instances[0]
}

// resolvedLocalCall reports whether b calls a module by a local path and the
// model evaluated the call.
func resolvedLocalCall(b *model.Block) bool {
	if len(b.Module.Called(b.Name)) == 0 {
		return false
	}
	inst := firstInstance(b)
	if inst == nil {
		return false
	}
	src, ok := inst.Attrs["source"]
	if !ok || !src.IsKnown() || src.IsNull() || src.Type() != cty.String {
		return false
	}
	path := src.AsString()
	return strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../")
}

func addLegacyBlock(doc map[string]any, b *model.Block, attrs map[string]any) {
	switch b.Kind {
	case address.KindModule, address.KindVariable, address.KindOutput:
		child(doc, b.Kind)[b.Name] = attrs
	case address.KindProvider:
		providers := child(doc, address.KindProvider)
		switch prev := providers[b.Type].(type) {
		case nil:
			providers[b.Type] = attrs
		case []any:
			providers[b.Type] = append(prev, attrs)
		default:
			providers[b.Type] = []any{prev, attrs}
		}
	case model.KindLocals:
		locals := child(doc, model.KindLocals)
		for k, v := range attrs {
			locals[k] = v
		}
	}
}

func child(m map[string]any, key string) map[string]any {
	c, ok := m[key].(map[string]any)
	if !ok {
		c = map[string]any{}
		m[key] = c
	}
	return c
}

// legacyRender renders the attributes of a block of module m the way the
// legacy converter did: from the written expressions, with what evaluation
// could resolve resolved and every reference to a managed or ephemeral block
// of the module kept as its source text. The model resolves such references
// to the values of the blocks they name, which the legacy view must not see;
// their namespace is therefore taken out of the context the expressions
// evaluate in, and a value one of them reaches renders from the partial
// renderer, which keeps the reference text wherever evaluation put it.
type legacyRender struct {
	conv value.Converter
	// refs are the root names of the blocks whose values stay unseen: the
	// module's resource types, the ephemeral namespace and the locals that
	// read them.
	refs map[string]bool
	// dataKinds holds the data source types whose computed attributes the
	// render context re-renders (patchLegacyData).
	dataKinds map[string]bool
	ctx       *hcl.EvalContext
	rd        *partial.Renderer
}

// newLegacyRender is the renderer for the blocks of m; nil when the module
// was not evaluated and nothing can render from expressions.
func newLegacyRender(m *model.Module, conv value.Converter) *legacyRender {
	if m == nil || m.Scope == nil {
		return nil
	}
	scope := m.Scope
	base := scope.RenderContext()
	if base == nil {
		return nil
	}
	refs := map[string]bool{"ephemeral": true, "local": true}
	for _, b := range m.Blocks {
		if b.Kind == address.KindResource || b.Kind == address.KindEphemeral {
			refs[b.Type] = true
		}
	}
	vars := make(map[string]cty.Value, len(base.Variables))
	for name, v := range base.Variables {
		vars[name] = v
	}
	for name := range refs {
		delete(vars, name)
	}
	ctx := &hcl.EvalContext{Variables: vars, Functions: base.Functions}
	// The model resolved the module's locals with the resource values
	// in scope, which the legacy view keeps unseen. Re-resolve them
	// without those values: a local that still resolves keeps its value,
	// one that reads a block of the module stays out of the context, so a
	// consumer of it renders its reference text, as the previous
	// engine's documents carried.
	delete(vars, localNamespace)
	if len(scope.Locals) > 0 {
		vars[localNamespace] = legacyLocals(scope, ctx)
	}
	lr := &legacyRender{
		conv:      conv,
		refs:      refs,
		dataKinds: map[string]bool{},
		ctx:       ctx,
		rd:        &partial.Renderer{Ctx: ctx, Source: partial.FileSources(scope.Sources())},
	}
	patchLegacyData(m, vars, lr)
	return lr
}

// legacyLocals re-resolves the module's local expressions without the
// module's resource values, in dependency order: a local whose expression
// resolves keeps its value, one that does not is left out. nil when the
// module declares no locals.
func legacyLocals(scope *tfeval.ModuleScope, base *hcl.EvalContext) cty.Value {
	vals := make(map[string]cty.Value, len(scope.Locals))
	child := base.NewChild()
	// The expressions read their peers through the local namespace, so the
	// values resolved so far are installed under it and refreshed as the
	// passes add more, letting chains of locals resolve in dependency order.
	child.Variables = map[string]cty.Value{localNamespace: cty.ObjectVal(vals)}
	remaining := make(map[string]hclsyntax.Expression, len(scope.Locals))
	for name, expr := range scope.Locals {
		remaining[name] = expr
	}
	for progress, passes := true, len(scope.Locals)+1; progress && passes > 0; passes-- {
		progress = false
		for name, expr := range remaining {
			v, diags := expr.Value(child)
			if diags.HasErrors() {
				continue
			}
			v, _ = v.UnmarkDeep()
			if !v.IsWhollyKnown() {
				continue
			}
			vals[name] = v
			child.Variables[localNamespace] = cty.ObjectVal(vals)
			delete(remaining, name)
			progress = true
		}
	}
	return cty.ObjectVal(vals)
}

// forInstance is the renderer for one block instance, whose count.index or
// each.key the expressions may read.
func (lr *legacyRender) forInstance(inst *model.Instance) *legacyRender {
	if lr == nil || len(inst.Iteration) == 0 {
		return lr
	}
	child := lr.ctx.NewChild()
	child.Variables = inst.Iteration
	return &legacyRender{
		conv:      lr.conv,
		refs:      lr.refs,
		dataKinds: lr.dataKinds,
		ctx:       child,
		rd:        &partial.Renderer{Ctx: child, Source: lr.source()},
	}
}

// source is the configuration the renderer reads reference text from.
func (lr *legacyRender) source() partial.Source {
	return lr.rd.Source
}

// readsRefs reports whether expr reaches a block whose values the legacy view
// keeps unseen. Every other expression already evaluated to the value the
// view carries, so its conversion is kept as is.
func (lr *legacyRender) readsRefs(expr hcl.Expression) bool {
	if lr == nil || expr == nil {
		return false
	}
	for _, traversal := range expr.Variables() {
		if lr.refs[traversal.RootName()] {
			return true
		}
	}
	return false
}

// value renders one attribute: an expression reading a hidden block renders
// from the partial renderer, which keeps what resolves and writes every
// reference the hidden namespace reaches as its source text, with a
// genuinely unrenderable part as the placeholder.
func (lr *legacyRender) value(v cty.Value, expr hcl.Expression) any {
	// The renderer evaluates the expression with the hidden namespaces out
	// of its context, which reproduces the previous engine's semantics: a
	// try whose failing argument errors answers from its fallback, one
	// whose argument is unknown stays unknown and renders whole as
	// written, and a placing function builds its value around the
	// reference texts.
	rendered, ok := lr.rd.Render(expr)
	if !ok {
		return lr.conv.Go(v)
	}
	return lr.conv.Go(renderedValue(rendered, lr.conv.Placeholder))
}

// renderedValue replaces each unresolved leaf the renderer could not give
// source text with the placeholder of the view, at every depth.
func renderedValue(v cty.Value, placeholder string) cty.Value {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return v
	}
	if v.Type() == cty.String {
		s := v.AsString()
		if strings.Contains(s, partial.UnknownPlaceholder) {
			return cty.StringVal(strings.ReplaceAll(s, partial.UnknownPlaceholder, placeholder))
		}
		return v
	}
	ty := v.Type()
	switch {
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		elems := v.AsValueSlice()
		out := make([]cty.Value, len(elems))
		for i, e := range elems {
			out[i] = renderedValue(e, placeholder)
		}
		return cty.TupleVal(out)
	case ty.IsMapType() || ty.IsObjectType():
		elems := v.AsValueMap()
		out := make(map[string]cty.Value, len(elems))
		for k, e := range elems {
			out[k] = renderedValue(e, placeholder)
		}
		return cty.ObjectVal(out)
	}
	return v
}

// legacyAttrs is instance inst of b in the legacy shape; a plan's computed
// values fill the attributes the configuration does not write. Attributes
// reading a block of the module render from their expression with the block's
// namespace out of the context, so a reference keeps its source text.
func legacyAttrs(b *model.Block, inst *model.Instance, conv value.Converter, lr *legacyRender) map[string]any {
	out := map[string]any{}
	if inst == nil {
		return out
	}
	var body *hclsyntax.Body
	if b.Syntax != nil {
		body = b.Syntax.Body
	}
	for name, v := range inst.Computed {
		if value.Present(v) {
			out[name] = conv.Go(v)
		}
	}
	for name, v := range inst.Attrs {
		if !value.Present(v) {
			continue
		}
		if lr.renderValue(out, name, v, body) {
			continue
		}
		if text, ok := partialText(inst, name, conv); ok {
			out[name] = text
			continue
		}
		if text, ok := unknownText(b, body, name, v); ok {
			out[name] = text
			continue
		}
		out[name] = conv.Go(v)
	}
	collapseBlocks(out, body)
	prepareLegacyFilterPatterns(out)
	return out
}

// renderValue writes the document value of one attribute of the written body
// under name and reports whether it did: a reference-like attribute reading a
// hidden block, or whose value the model could not resolve, renders from its
// expression, so a reference keeps its source text. An expression deciding on
// what it reads (a condition, a loop) keeps the value evaluation produced,
// and attributes of no expression the renderer knows — a plan's computed
// ones, a merged override, unknown dynamic content — keep the conversion of
// the value the model carries.
func (lr *legacyRender) renderValue(out map[string]any, name string, v cty.Value, body *hclsyntax.Body) bool {
	if lr == nil || body == nil {
		return false
	}
	v, _ = v.UnmarkDeep()
	if attr, ok := body.Attributes[name]; ok && lr.rendersFromExpr(attr.Expr, v) {
		out[name] = lr.value(v, attr.Expr)
		return true
	}
	if sources, ok := nestedSources(body)[name]; ok && len(sources) > 0 && rendersNested(lr, sources, v) {
		out[name] = lr.nested(v, sources)
		return true
	}
	return false
}

// rendersFromExpr reports whether expr renders from the partial renderer: it
// only places references into its value, and one of them reaches a hidden
// block, or the value evaluation produced is not wholly known and the
// expression would otherwise lose its reference text.
func (lr *legacyRender) rendersFromExpr(expr hcl.Expression, v cty.Value) bool {
	syn, ok := expr.(hclsyntax.Expression)
	if !ok {
		return false
	}
	if call, isCall := syn.(*hclsyntax.FunctionCallExpr); isCall && !lr.rd.Places(call) {
		// A function deciding on its arguments renders whole as written as
		// soon as one reference argument does not resolve: evaluating it
		// would answer from a fallback (try) or otherwise without the
		// reference the view keeps unseen, whatever the model resolved.
		return !lr.argsResolve(call) || ((lr.readsRefs(syn) || !v.IsWhollyKnown()) && lr.referenceLike(syn))
	}
	return (lr.readsRefs(syn) || lr.readsComputedData(syn) || !v.IsWhollyKnown()) && lr.referenceLike(syn)
}

// readsComputedData reports whether expr reads a computed attribute of a data
// source whose value the render context re-renders: the model computed it with
// the unknown marker in place of what does not resolve, while the view keeps
// the interpolation text.
func (lr *legacyRender) readsComputedData(expr hcl.Expression) bool {
	if lr == nil || expr == nil || len(lr.dataKinds) == 0 {
		return false
	}
	for _, traversal := range expr.Variables() {
		if traversal.RootName() != dataNamespace || len(traversal) < 2 {
			continue
		}
		if attr, ok := traversal[1].(hcl.TraverseAttr); ok && lr.dataKinds[attr.Name] {
			return true
		}
	}
	return false
}

// argsResolve reports whether every argument of the call resolves in the
// rendering context.
func (lr *legacyRender) argsResolve(e *hclsyntax.FunctionCallExpr) bool {
	for _, arg := range e.Args {
		v, diags := arg.Value(lr.ctx)
		if diags.HasErrors() || !v.IsWhollyKnown() {
			return false
		}
	}
	return true
}

// referenceLike reports whether expr places references into its value: a
// traversal, an index or relative traversal over one — a selector reading
// count.index or each.key still names a block of the module and renders as
// its written text — a template or collection of them, or a call to a
// function that only places its arguments. An expression deciding on what
// it reads (a condition, a loop) is not.
func (lr *legacyRender) referenceLike(expr hclsyntax.Expression) bool {
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr, *hclsyntax.ScopeTraversalExpr, *hclsyntax.AnonSymbolExpr:
		return true
	case *hclsyntax.IndexExpr:
		return lr.referenceLike(e.Collection)
	case *hclsyntax.RelativeTraversalExpr:
		return lr.referenceLike(e.Source)
	case *hclsyntax.ConditionalExpr, *hclsyntax.ForExpr:
		// A condition or loop reading a block of the module renders whole
		// as its written text: evaluation cannot choose a branch or expand
		// the loop without the values the view keeps unseen.
		return true
	case *hclsyntax.FunctionCallExpr:
		// A call one of whose arguments reads a block renders from its
		// written text, whole when the function decides on its arguments
		// and per placed part when it only places them.
		return lr.rd.PlacesOnly(e) || lr.referenceLikeAll(e.Args)
	}
	return lr.referenceLikeChildren(expr)
}

// referenceLikeChildren reports whether the container expressions place
// references: every child of a template, a collection or an object
// constructor is reference-like, and an object key only has to resolve (the
// parser wraps a bare identifier in an ObjectConsKeyExpr; the key shapes the
// object, only the value places references).
func (lr *legacyRender) referenceLikeChildren(expr hclsyntax.Expression) bool {
	switch e := expr.(type) {
	case *hclsyntax.TemplateExpr:
		return lr.referenceLikeAll(e.Parts)
	case *hclsyntax.TemplateWrapExpr:
		return lr.referenceLike(e.Wrapped)
	case *hclsyntax.ParenthesesExpr:
		return lr.referenceLike(e.Expression)
	case *hclsyntax.TupleConsExpr:
		return lr.referenceLikeAll(e.Exprs)
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			if _, diags := item.KeyExpr.Value(lr.ctx); diags.HasErrors() {
				return false
			}
			if !lr.referenceLike(item.ValueExpr) {
				return false
			}
		}
		return true
	}
	return false
}

func (lr *legacyRender) referenceLikeAll(exprs []hclsyntax.Expression) bool {
	for _, e := range exprs {
		if !lr.referenceLike(e) {
			return false
		}
	}
	return true
}

// rendersNested reports whether an element of the nested block value v
// renders from its written body.
func rendersNested(lr *legacyRender, sources []nestedSource, v cty.Value) bool {
	if !v.IsWhollyKnown() {
		return true
	}
	if !v.CanIterateElements() {
		return false
	}
	i := 0
	for it := v.ElementIterator(); it.Next(); i++ {
		_, ev := it.Element()
		idx := i
		if idx >= len(sources) {
			idx = len(sources) - 1
		}
		if sources[idx].dynamic {
			continue
		}
		if rendersNestedElement(lr, sources[idx].body, ev) {
			return true
		}
	}
	return false
}

// rendersNestedElement reports whether the object v, produced by one block
// body, holds an attribute or a deeper nested block that renders from its
// expression, at every depth.
func rendersNestedElement(lr *legacyRender, body *hclsyntax.Body, v cty.Value) bool {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || !v.Type().IsObjectType() {
		return false
	}
	for name, attr := range body.Attributes {
		if ev, ok := attrValue(v, name); ok && lr.rendersFromExpr(attr.Expr, ev) {
			return true
		}
	}
	for name, inner := range nestedSources(body) {
		if len(inner) == 0 {
			continue
		}
		if ev, ok := attrValue(v, name); ok && rendersNested(lr, inner, ev) {
			return true
		}
	}
	return false
}

// attrValue is the value of one attribute of an object value.
func attrValue(v cty.Value, name string) (cty.Value, bool) {
	if !v.Type().IsObjectType() && !v.Type().IsMapType() {
		return cty.NilVal, false
	}
	if !v.Type().HasAttribute(name) {
		return cty.NilVal, false
	}
	return v.GetAttr(name), true
}

// nested renders the elements of one nested block type of an instance. A
// static block renders from its written body; the content of a dynamic block
// keeps the value evaluation produced, since its iterator is no longer bound.
func (lr *legacyRender) nested(v cty.Value, sources []nestedSource) any {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || !v.CanIterateElements() {
		return lr.conv.Go(v)
	}
	out := make([]any, 0, v.LengthInt())
	i := 0
	for it := v.ElementIterator(); it.Next(); i++ {
		_, e := it.Element()
		e, _ = e.UnmarkDeep()
		if i < len(sources) && !sources[i].dynamic && e.IsKnown() && e.Type().IsObjectType() {
			out = append(out, lr.attrs(e, sources[i].body))
			continue
		}
		if m, ok := lr.conv.Go(e).(map[string]any); ok {
			collapseBlocks(m, sources[min(i, len(sources)-1)].body)
			out = append(out, m)
			continue
		}
		out = append(out, lr.conv.Go(e))
	}
	if len(out) == 1 {
		if m, ok := out[0].(map[string]any); ok {
			return m
		}
	}
	return out
}

// attrs renders the attributes and nested blocks of one block body from the
// values they evaluated to, with the attributes reading a hidden block
// rendered from their expressions.
func (lr *legacyRender) attrs(v cty.Value, body *hclsyntax.Body) map[string]any {
	out := make(map[string]any, v.LengthInt())
	sources := nestedSources(body)
	for it := v.ElementIterator(); it.Next(); {
		k, e := it.Element()
		name := k.AsString()
		e, _ = e.UnmarkDeep()
		if !value.Present(e) {
			continue
		}
		if attr, ok := body.Attributes[name]; ok && lr.rendersFromExpr(attr.Expr, e) {
			out[name] = lr.value(e, attr.Expr)
			continue
		}
		if sources, ok := sources[name]; ok && len(sources) > 0 {
			out[name] = lr.nested(e, sources)
			continue
		}
		out[name] = lr.conv.Go(e)
	}
	return out
}

// prepareLegacyFilterPatterns rewrites pattern attributes the way the runner
// sanitizes KindTerraform documents, so counted instances keep _dd_filter_expr.
func prepareLegacyFilterPatterns(doc map[string]any) {
	for key, v := range doc {
		switch node := v.(type) {
		case map[string]any:
			prepareLegacyFilterPatterns(node)
		case []any:
			for _, item := range node {
				if child, ok := item.(map[string]any); ok {
					prepareLegacyFilterPatterns(child)
				}
			}
		case string:
			if key == "pattern" {
				doc[key] = jsonfilter.Resolve(node)
			}
		}
	}
}

// partialText renders a string with an unknown part the way the legacy
// converter did: a template with the placeholder for each unknown part, and
// a JSON-encoded value with the placeholder for each unknown leaf.
func partialText(inst *model.Instance, name string, conv value.Converter) (string, bool) {
	if v, ok := inst.JSON[name]; ok {
		b, err := json.Marshal(conv.Go(v))
		if err != nil {
			return "", false
		}
		return string(b), true
	}
	parts, ok := inst.Templates[name]
	if !ok {
		return "", false
	}
	var sb strings.Builder
	for _, p := range parts {
		if p.IsKnown() && !p.IsNull() && p.Type() == cty.String {
			sb.WriteString(p.AsString())
			continue
		}
		sb.WriteString(conv.Placeholder)
	}
	return sb.String(), true
}

// unknownText is the source of a wholly unknown attribute written in body,
// as the legacy converter rendered an expression it could not resolve.
func unknownText(b *model.Block, body *hclsyntax.Body, name string, v cty.Value) (string, bool) {
	v, _ = v.UnmarkDeep()
	if v.IsKnown() || body == nil || b.Module == nil || b.Module.Scope == nil {
		return "", false
	}
	attr, ok := body.Attributes[name]
	if !ok {
		return "", false
	}
	rng := attr.Expr.Range()
	src := b.Module.Scope.Sources()[rng.Filename]
	if rng.Start.Byte < 0 || rng.End.Byte > len(src) || rng.Start.Byte >= rng.End.Byte {
		return "", false
	}
	return "${" + string(src[rng.Start.Byte:rng.End.Byte]) + "}", true
}

// collapseBlocks turns the nested blocks of obj written once in body into an
// object, at every depth.
func collapseBlocks(obj map[string]any, body *hclsyntax.Body) {
	if body == nil {
		return
	}
	for name, sources := range nestedSources(body) {
		list, ok := obj[name].([]any)
		if !ok {
			continue
		}
		for i, e := range list {
			if m, ok := e.(map[string]any); ok {
				collapseBlocks(m, sources[min(i, len(sources)-1)].body)
			}
		}
		if len(list) == 1 {
			if m, ok := list[0].(map[string]any); ok {
				obj[name] = m
			}
		}
	}
}

// nestedSource is the body one written nested block contributed to its block
// type. A dynamic block contributes the body of its content, whose
// expressions read the iterator the expansion bound.
type nestedSource struct {
	body    *hclsyntax.Body
	dynamic bool
}

// nestedSources returns, by block type, the source of every nested block of
// body; a dynamic block contributes its content to the type it generates.
func nestedSources(body *hclsyntax.Body) map[string][]nestedSource {
	out := map[string][]nestedSource{}
	for _, nb := range body.Blocks {
		if dynamicblock.Is(nb) {
			if content := dynamicblock.Content(nb); content != nil {
				typ := dynamicblock.GeneratedType(nb)
				out[typ] = append(out[typ], nestedSource{body: content, dynamic: true})
			}
			continue
		}
		out[nb.Type] = append(out[nb.Type], nestedSource{body: nb.Body})
	}
	return out
}
// dataNamespace is the root name the module's data sources are read through.
const dataNamespace = "data"

// patchLegacyData re-renders, in the legacy view's own context, the attributes
// the data sources Terraform computes from their configuration alone
// (aws_iam_policy_document, google_iam_policy) carry. The model evaluates
// those data sources too, but replaces an unresolved part of the computed
// document with the unknown marker, so a policy document built over a data
// source reference loses the reference text around it; the previous engine
// kept the interpolation text. Only a data source with one keyed instance and
// an object already in the render context is patched; the others keep the
// values the model carries.
func patchLegacyData(m *model.Module, vars map[string]cty.Value, lr *legacyRender) {
	dv, ok := vars[dataNamespace]
	if !ok || !dv.IsKnown() || !dv.Type().IsObjectType() {
		return
	}
	byType := dv.AsValueMap()
	changed := false
	for _, b := range m.Blocks {
		if b.Kind != address.KindData || b.Syntax == nil {
			continue
		}
		source, ok := localdata.Lookup(b.Type)
		if !ok || len(b.Instances) != 1 || b.Instances[0].Key != "" {
			continue
		}
		typeVal, ok := byType[b.Type]
		if !ok || !typeVal.IsKnown() || !typeVal.Type().IsObjectType() {
			continue
		}
		entries := typeVal.AsValueMap()
		entry, ok := entries[b.Name]
		if !ok || !entry.IsKnown() || !entry.Type().IsObjectType() {
			continue
		}
		computed := source(context.Background(), b.Syntax.Body, func(expr hcl.Expression) (cty.Value, bool) {
			return lr.rd.Render(expr)
		})
		if len(computed) == 0 {
			continue
		}
		lr.dataKinds[b.Type] = true
		attrs := entry.AsValueMap()
		for name, v := range computed {
			attrs[name] = cty.StringVal(v)
		}
		entries[b.Name] = cty.ObjectVal(attrs)
		byType[b.Type] = cty.ObjectVal(entries)
		changed = true
	}
	if changed {
		vars[dataNamespace] = cty.ObjectVal(byType)
	}
}
