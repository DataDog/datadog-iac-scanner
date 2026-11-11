/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// metaArgs are the arguments of a resource-like block that are not attributes.
var metaArgs = map[string]bool{
	"count": true, "for_each": true, "provider": true, lifecycleBlock: true, "depends_on": true,
}

// moduleMetaArgs are the module call arguments that are not attributes.
var moduleMetaArgs = map[string]bool{
	"count": true, "for_each": true, "providers": true, "depends_on": true,
}

type builder struct {
	root *Root
	base string
}

func newBuilder(root *Root, base string) *builder {
	return &builder{root: root, base: base}
}

func (b *builder) build(resources []tfeval.ResolvedResource) {
	byModule := map[string][]*tfeval.ResolvedResource{}
	for i := range resources {
		r := &resources[i]
		byModule[r.ModuleAddress] = append(byModule[r.ModuleAddress], r)
	}
	for _, m := range b.root.Modules {
		if m.parent == nil {
			continue
		}
		rest := strings.TrimPrefix(m.Address, joinAddr(m.parent.Address, "module."))
		label, _, _ := strings.Cut(rest, "[")
		if m.parent.calls == nil {
			m.parent.calls = map[string][]*Module{}
		}
		m.parent.calls[label] = append(m.parent.calls[label], m)
	}
	for _, m := range b.root.Modules {
		b.buildModule(m, byModule[m.Address])
	}
	markDuplicates(b.root)
	resolveProviders(b.root)
	traceRoot(b.root)
}

func (b *builder) buildModule(m *Module, resources []*tfeval.ResolvedResource) {
	if m.Scope == nil {
		b.root.Incomplete, b.root.Unscoped = true, true
		b.root.Notes = append(b.root.Notes, "module instance without scope: "+m.Address)
		return
	}
	byBody := map[*hclsyntax.Body][]*tfeval.ResolvedResource{}
	for _, r := range resources {
		byBody[r.Body] = append(byBody[r.Body], r)
	}
	for _, body := range m.Scope.Bodies {
		for _, sb := range body.Blocks {
			if blk := b.blockOf(m, sb, byBody[sb.Body]); blk != nil {
				m.Blocks = append(m.Blocks, blk)
			}
		}
	}
}

// blockOf models one top-level block, nil for a block that is not modeled
// here: a resource without instances, a static kind outside the module's
// first instance, or a kind rules do not read.
func (b *builder) blockOf(m *Module, sb *hclsyntax.Block, rs []*tfeval.ResolvedResource) *Block {
	labels := len(sb.Labels)
	switch sb.Type {
	case address.KindResource, address.KindData:
		return b.resourceBlock(m, sb, rs)
	case address.KindEphemeral:
		if labels == 2 {
			return b.evaluatedBlock(m, sb, address.KindEphemeral, sb.Labels[0], sb.Labels[1], metaArgs)
		}
	case address.KindProvider:
		// Providers are modeled for every module instance: two calls of the
		// same module may declare distinct configurations (regions,
		// default_tags). Variables and outputs stay Static-only below.
		if labels == 1 {
			return b.evaluatedBlock(m, sb, address.KindProvider, sb.Labels[0], literalString(sb.Body, "alias"), nil)
		}
	case address.KindVariable:
		if m.Static && labels == 1 {
			return b.variableBlock(m, sb)
		}
	case address.KindOutput:
		if m.Static && labels == 1 {
			return b.outputBlock(m, sb)
		}
	case KindLocals:
		return b.localsBlock(m, sb)
	case address.KindModule:
		return b.moduleCallBlock(m, sb)
	}
	return nil
}

func (b *builder) newBlock(m *Module, sb *hclsyntax.Block, kind, typ, name string) *Block {
	return &Block{
		Module: m, Kind: kind, Type: typ, Name: name,
		File: relPath(b.base, sb.TypeRange.Filename), Range: sb.DefRange(), Syntax: sb,
		Nonliteral: nonliteralPaths(m, sb.Body),
	}
}

func (b *builder) resourceBlock(m *Module, sb *hclsyntax.Block, rs []*tfeval.ResolvedResource) *Block {
	if len(sb.Labels) != 2 || len(rs) == 0 {
		return nil
	}
	blk := b.newBlock(m, sb, sb.Type, sb.Labels[0], sb.Labels[1])
	blk.Provider = providerRef(sb.Body, sb.Labels[0])
	blk.DependsOn = traversalTexts(sb.Body, "depends_on")
	_, expands := sb.Body.Attributes["count"]
	if _, ok := sb.Body.Attributes["for_each"]; ok {
		expands = true
	}
	for _, r := range rs {
		key := instanceKey(r.Name, sb.Labels[1])
		inst := &Instance{Block: blk, Key: key}
		inst.Address = joinAddr(m.Address, address.Addr(address.Block{Kind: blk.Kind, Type: blk.Type, Name: blk.Name})+key)
		inst.Iteration = r.Iteration
		if inst.Iteration == nil {
			inst.Iteration = iterationOf(key, r.Attributes["for_each"])
		}
		inst.Ranges = map[string]hcl.Range{"": blk.Range}
		inst.Attrs = normalizeBody(r.Attributes, sb.Body, r.DynamicCounts, "", inst.Ranges, metaArgs)
		if lc, ok := r.Attributes[lifecycleBlock]; ok {
			blk.Lifecycle = lc
		}
		derive(inst, m, sb.Body)
		blk.Instances = append(blk.Instances, inst)
	}
	if expands && len(blk.Instances) == 1 && blk.Instances[0].Key == "" {
		blk.KeyUnknown = true
	}
	blk.Overridable = expands && readsRootInput(m, expansionExpr(sb.Body), 0)
	return blk
}

// instanceKey turns the instance name tfeval gives ("b[0]", `b["x"]`, with
// Go quoting) into the HCL suffix of the address.
func instanceKey(name, label string) string {
	rest := strings.TrimPrefix(name, label)
	if rest == "" || rest == name {
		return ""
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]")
	if s, err := strconv.Unquote(inner); err == nil {
		return address.InstanceSuffix(cty.StringVal(s))
	}
	if n, err := strconv.Atoi(inner); err == nil {
		return address.InstanceSuffix(cty.NumberIntVal(int64(n)))
	}
	return rest
}

// iterationOf rebuilds count or each for an instance tfeval did not keep the
// iteration of. forEach is the instance's own element of for_each.
func iterationOf(key string, forEach cty.Value) map[string]cty.Value {
	if key == "" {
		return nil
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(key, "["), "]")
	if n, err := strconv.Atoi(inner); err == nil {
		return map[string]cty.Value{"count": cty.ObjectVal(map[string]cty.Value{"index": cty.NumberIntVal(int64(n))})}
	}
	k, err := strconv.Unquote(inner)
	if err != nil {
		return nil
	}
	each := cty.DynamicVal
	if forEach != cty.NilVal && forEach.IsWhollyKnown() && !forEach.IsNull() {
		ty := forEach.Type()
		switch {
		case ty.IsMapType() || ty.IsObjectType():
			if forEach.Type().IsObjectType() && forEach.Type().HasAttribute(k) {
				each = forEach.GetAttr(k)
			} else if ty.IsMapType() && forEach.HasIndex(cty.StringVal(k)).True() {
				each = forEach.Index(cty.StringVal(k))
			}
		case ty.IsSetType():
			each = cty.StringVal(k)
		}
	}
	return map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal(k), "value": each})}
}

func expansionExpr(body *hclsyntax.Body) hclsyntax.Expression {
	if a, ok := body.Attributes["count"]; ok {
		return a.Expr
	}
	if a, ok := body.Attributes["for_each"]; ok {
		return a.Expr
	}
	return nil
}

// normalizeBody shapes the attributes tfeval evaluated from body: nested
// blocks become tuples, whatever their count; a dynamic block kept as written
// becomes one unknown element of its block type; meta-arguments are dropped.
// It records the range of every attribute and nested block under prefix.
func normalizeBody(
	vals map[string]cty.Value, body *hclsyntax.Body, counts tfeval.DynamicCounts,
	prefix string, ranges map[string]hcl.Range, skip map[string]bool,
) map[string]cty.Value {
	out := make(map[string]cty.Value, len(vals))
	kept := keptDynamic(body, counts)
	for name, v := range vals {
		if skip[name] {
			continue
		}
		if attr, ok := body.Attributes[name]; ok {
			out[name] = v
			path := joinPath(prefix, name)
			ranges[path] = attr.SrcRange
			recordExprRanges(attr.Expr, path, ranges)
			if sources := blockSources(body, name, counts); len(sources) > 0 {
				recordBlockRanges(sources, path, ranges, literalCollectionLen(attr.Expr))
			}
			continue
		}
		if name == "dynamic" && len(kept) > 0 {
			continue
		}
		sources := blockSources(body, name, counts)
		if len(sources) == 0 {
			out[name] = v
			continue
		}
		out[name] = normalizeBlocks(v, sources, counts, joinPath(prefix, name), ranges)
	}
	for typ, blocks := range kept {
		if !skip[typ] {
			out[typ] = appendUnknownBlocks(out[typ], blocks, joinPath(prefix, typ), ranges)
		}
	}
	return out
}

// keptDynamic returns, by generated block type, the dynamic blocks of body
// that were kept as written.
func keptDynamic(body *hclsyntax.Body, counts tfeval.DynamicCounts) map[string][]*hclsyntax.Block {
	kept := map[string][]*hclsyntax.Block{}
	for _, nb := range body.Blocks {
		if dynamicblock.Is(nb) && counts[nb] == tfeval.DynamicKeptAsWritten {
			kept[dynamicblock.GeneratedType(nb)] = append(kept[dynamicblock.GeneratedType(nb)], nb)
		}
	}
	return kept
}

// appendUnknownBlocks appends one unknown element per dynamic block to the
// nested block list cur.
func appendUnknownBlocks(cur cty.Value, blocks []*hclsyntax.Block, path string, ranges map[string]hcl.Range) cty.Value {
	elems := []cty.Value{}
	if cur != cty.NilVal && cur.IsKnown() && !cur.IsNull() {
		elems = append(elems, cur.AsValueSlice()...)
	}
	for _, nb := range blocks {
		ranges[joinPath(path, strconv.Itoa(len(elems)))] = nb.Range()
		elems = append(elems, cty.DynamicVal)
	}
	return cty.TupleVal(elems)
}

// blockSource is the body that produced one nested block element.
type blockSource struct {
	body *hclsyntax.Body
	rng  hcl.Range
}

// blockSources lists, in order, the bodies that produced the elements of the
// nested block type name: a static block once, a dynamic block's content once
// per block it generated. A dynamic block whose count varies stands for any
// number of elements and ends the list.
func blockSources(body *hclsyntax.Body, name string, counts tfeval.DynamicCounts) []blockSource {
	var out []blockSource
	for _, nb := range body.Blocks {
		if !dynamicblock.Is(nb) {
			if nb.Type == name {
				out = append(out, blockSource{body: nb.Body, rng: nb.Range()})
			}
			continue
		}
		if dynamicblock.GeneratedType(nb) != name {
			continue
		}
		content := dynamicblock.Content(nb)
		if content == nil {
			continue
		}
		rng := contentRange(nb)
		n := counts[nb]
		if n == tfeval.DynamicCountVaries {
			return append(out, blockSource{body: content, rng: rng}, blockSource{})
		}
		for range n {
			out = append(out, blockSource{body: content, rng: rng})
		}
	}
	return out
}

func contentRange(dyn *hclsyntax.Block) hcl.Range {
	for _, b := range dyn.Body.Blocks {
		if b.Type == "content" {
			return b.Range()
		}
	}
	return dyn.Range()
}

func normalizeBlocks(
	v cty.Value, sources []blockSource, counts tfeval.DynamicCounts, path string, ranges map[string]hcl.Range,
) cty.Value {
	var elems []cty.Value
	switch {
	case !v.IsKnown() || v.IsNull():
		return v
	case v.Type().IsTupleType() || v.Type().IsListType():
		elems = v.AsValueSlice()
	default:
		elems = []cty.Value{v}
	}
	out := make([]cty.Value, len(elems))
	for i, e := range elems {
		src := sources[min(i, len(sources)-1)]
		if src.body == nil && len(sources) > 1 {
			src = sources[len(sources)-2]
		}
		elemPath := joinPath(path, strconv.Itoa(i))
		ranges[elemPath] = src.rng
		if !e.IsKnown() || e.IsNull() || !e.Type().IsObjectType() || src.body == nil {
			out[i] = e
			continue
		}
		out[i] = cty.ObjectVal(normalizeBody(e.AsValueMap(), src.body, counts, elemPath, ranges, nil))
	}
	return cty.TupleVal(out)
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// recordExprRanges walks literal tuples/objects under path. Bare objects also
// get a synthetic ".0" so tf.nested index-0 finding paths resolve. A
// jsonencode argument or a literal JSON string records its document.
func recordExprRanges(expr hcl.Expression, path string, ranges map[string]hcl.Range) {
	if recordDocRanges(expr, path, ranges) {
		return
	}
	switch e := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		for i, elem := range e.Exprs {
			elemPath := joinPath(path, strconv.Itoa(i))
			ranges[elemPath] = elem.Range()
			recordExprRanges(elem, elemPath, ranges)
		}
	case *hclsyntax.ObjectConsExpr:
		zero := joinPath(path, "0")
		ranges[zero] = e.Range()
		for _, item := range e.Items {
			name, ok := objectConsKeyName(item.KeyExpr)
			if !ok {
				continue
			}
			child := joinPath(path, name)
			ranges[child] = item.ValueExpr.Range()
			ranges[joinPath(zero, name)] = item.ValueExpr.Range()
			recordExprRanges(item.ValueExpr, child, ranges)
			recordExprRanges(item.ValueExpr, joinPath(zero, name), ranges)
		}
	case *hclsyntax.ParenthesesExpr:
		recordExprRanges(e.Expression, path, ranges)
	}
}

func objectConsKeyName(expr hcl.Expression) (string, bool) {
	if k, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		expr = k.Wrapped
	}
	switch e := expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		if len(e.Traversal) == 1 {
			if root, ok := e.Traversal[0].(hcl.TraverseRoot); ok {
				return root.Name, true
			}
		}
	case *hclsyntax.TemplateExpr:
		if e.IsStringLiteral() {
			v, diags := e.Value(nil)
			if !diags.HasErrors() {
				return v.AsString(), true
			}
		}
	case *hclsyntax.LiteralValueExpr:
		if e.Val.Type() == cty.String {
			return e.Val.AsString(), true
		}
	}
	return "", false
}

// literalCollectionLen is how many indexes expr owns before same-name blocks.
func literalCollectionLen(expr hcl.Expression) int {
	switch e := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		return len(e.Exprs)
	case *hclsyntax.ObjectConsExpr:
		return 1
	case *hclsyntax.ParenthesesExpr:
		return literalCollectionLen(e.Expression)
	}
	return 0
}

func recordBlockRanges(sources []blockSource, path string, ranges map[string]hcl.Range, start int) {
	for i, src := range sources {
		if src.body == nil {
			continue
		}
		elemPath := joinPath(path, strconv.Itoa(start+i))
		ranges[elemPath] = src.rng
		recordBodyRanges(src.body, elemPath, ranges)
	}
}

func recordBodyRanges(body *hclsyntax.Body, prefix string, ranges map[string]hcl.Range) {
	for name, attr := range body.Attributes {
		path := joinPath(prefix, name)
		ranges[path] = attr.SrcRange
		recordExprRanges(attr.Expr, path, ranges)
	}
	byType := map[string]int{}
	for _, nb := range body.Blocks {
		typ := nestedType(nb)
		i := byType[typ]
		byType[typ]++
		path := joinPath(joinPath(prefix, typ), strconv.Itoa(i))
		ranges[path] = nb.Range()
		if dynamicblock.Is(nb) {
			continue
		}
		recordBodyRanges(nb.Body, path, ranges)
	}
}

// evaluatedBlock evaluates a block tfeval does not expand (ephemeral
// resources, providers) in the module's scope, as one instance.
func (b *builder) evaluatedBlock(m *Module, sb *hclsyntax.Block, kind, typ, name string, skip map[string]bool) *Block {
	blk := b.newBlock(m, sb, kind, typ, name)
	if kind == address.KindEphemeral {
		blk.Provider = providerRef(sb.Body, typ)
		blk.KeyUnknown = expansionExpr(sb.Body) != nil
	}
	inst := &Instance{Block: blk, Ranges: map[string]hcl.Range{"": blk.Range}}
	inst.Address = joinAddr(m.Address, address.Addr(address.Block{Kind: kind, Type: typ, Name: name}))
	ctx := m.Scope.EvalContext()
	if blk.KeyUnknown {
		ctx = unknownIteration(ctx)
	}
	inst.Attrs = evalBody(sb.Body, ctx, "", inst.Ranges, skip)
	derive(inst, m, sb.Body)
	blk.Instances = []*Instance{inst}
	return blk
}

func unknownIteration(ctx *hcl.EvalContext) *hcl.EvalContext {
	child := ctx.NewChild()
	child.Variables = map[string]cty.Value{
		"count": cty.ObjectVal(map[string]cty.Value{"index": cty.UnknownVal(cty.Number)}),
		"each":  cty.ObjectVal(map[string]cty.Value{"key": cty.UnknownVal(cty.String), "value": cty.DynamicVal}),
	}
	return child
}

// evalBody evaluates a body in the shape normalizeBody gives: nested blocks
// as tuples, every dynamic block as one unknown element.
func evalBody(
	body *hclsyntax.Body, ctx *hcl.EvalContext, prefix string, ranges map[string]hcl.Range, skip map[string]bool,
) map[string]cty.Value {
	out := make(map[string]cty.Value, len(body.Attributes)+len(body.Blocks))
	attrNames := map[string]bool{}
	for name, attr := range body.Attributes {
		if skip[name] {
			continue
		}
		attrNames[name] = true
		path := joinPath(prefix, name)
		out[name] = evalExpr(attr.Expr, ctx)
		ranges[path] = attr.SrcRange
		recordExprRanges(attr.Expr, path, ranges)
	}
	lists := map[string][]cty.Value{}
	for _, nb := range body.Blocks {
		typ := nestedType(nb)
		if skip[typ] {
			continue
		}
		i := len(lists[typ])
		if attrNames[typ] {
			if attr := body.Attributes[typ]; attr != nil {
				i = literalCollectionLen(attr.Expr) + len(lists[typ])
			}
		}
		path := joinPath(joinPath(prefix, typ), strconv.Itoa(i))
		ranges[path] = nb.Range()
		if dynamicblock.Is(nb) {
			lists[typ] = append(lists[typ], cty.DynamicVal)
			continue
		}
		lists[typ] = append(lists[typ], cty.ObjectVal(evalBody(nb.Body, ctx, path, ranges, nil)))
	}
	for typ, elems := range lists {
		out[typ] = cty.TupleVal(elems)
	}
	return out
}

func evalExpr(expr hcl.Expression, ctx *hcl.EvalContext) cty.Value {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return cty.DynamicVal
	}
	return v
}

func (b *builder) variableBlock(m *Module, sb *hclsyntax.Block) *Block {
	blk := b.newBlock(m, sb, address.KindVariable, "", sb.Labels[0])
	inst := &Instance{Block: blk, Ranges: map[string]hcl.Range{"": blk.Range}}
	inst.Address = joinAddr(m.Address, "var."+blk.Name)
	ctx := &hcl.EvalContext{Functions: m.Scope.EvalContext().Functions}
	inst.Attrs = evalBody(sb.Body, ctx, "", inst.Ranges, map[string]bool{"type": true})
	if attr, ok := sb.Body.Attributes["type"]; ok {
		text := sourceText(m, attr.Expr.Range())
		if v, diags := attr.Expr.Value(nil); !diags.HasErrors() && v.Type() == cty.String && v.IsWhollyKnown() && !v.IsNull() {
			text = v.AsString()
		}
		inst.Attrs["type"] = cty.StringVal(text)
		inst.Ranges["type"] = attr.SrcRange
	}
	blk.Instances = []*Instance{inst}
	return blk
}

func sourceText(m *Module, rng hcl.Range) string {
	src := m.Scope.Sources()[rng.Filename]
	if rng.Start.Byte < 0 || rng.End.Byte > len(src) || rng.Start.Byte > rng.End.Byte {
		return ""
	}
	return string(src[rng.Start.Byte:rng.End.Byte])
}

func (b *builder) outputBlock(m *Module, sb *hclsyntax.Block) *Block {
	blk := b.newBlock(m, sb, address.KindOutput, "", sb.Labels[0])
	inst := &Instance{Block: blk, Ranges: map[string]hcl.Range{"": blk.Range}}
	inst.Address = joinAddr(m.Address, "output."+blk.Name)
	inst.Attrs = evalBody(sb.Body, m.Scope.EvalContext(), "", inst.Ranges, map[string]bool{"depends_on": true})
	if v, ok := m.Outputs[blk.Name]; ok {
		inst.Attrs["value"] = v
	}
	derive(inst, m, sb.Body)
	blk.Instances = []*Instance{inst}
	return blk
}

func (b *builder) localsBlock(m *Module, sb *hclsyntax.Block) *Block {
	blk := b.newBlock(m, sb, KindLocals, "", "")
	inst := &Instance{Block: blk, Ranges: map[string]hcl.Range{"": blk.Range}}
	inst.Address = joinAddr(m.Address, "locals")
	inst.Attrs = make(map[string]cty.Value, len(sb.Body.Attributes))
	local := m.Scope.Local
	for name, attr := range sb.Body.Attributes {
		inst.Ranges[name] = attr.SrcRange
		if local.IsKnown() && !local.IsNull() && local.Type().IsObjectType() && local.Type().HasAttribute(name) {
			inst.Attrs[name] = local.GetAttr(name)
			continue
		}
		inst.Attrs[name] = evalExpr(attr.Expr, m.Scope.EvalContext())
	}
	derive(inst, m, sb.Body)
	blk.Instances = []*Instance{inst}
	return blk
}

// moduleCallBlock models a module call with one instance per evaluated module
// instance, its attributes the arguments that instance received. A call
// that did not evaluate and whose count or for_each is not known empty
// makes the root incomplete; it is modeled as one instance.
func (b *builder) moduleCallBlock(m *Module, sb *hclsyntax.Block) *Block {
	if len(sb.Labels) != 1 {
		return nil
	}
	blk := b.newBlock(m, sb, address.KindModule, "", sb.Labels[0])
	blk.DependsOn = traversalTexts(sb.Body, "depends_on")
	prefix := joinAddr(m.Address, "module."+blk.Name)
	children := m.calls[blk.Name]
	static := map[string]bool{"source": true, "version": true}
	ranges := map[string]hcl.Range{"": blk.Range}
	staticAttrs := evalBody(&hclsyntax.Body{Attributes: pick(sb.Body.Attributes, static)}, m.Scope.EvalContext(), "", ranges, nil)
	for name, attr := range sb.Body.Attributes {
		if !moduleMetaArgs[name] {
			ranges[name] = attr.SrcRange
		}
	}
	for _, child := range children {
		key := strings.TrimPrefix(child.Address, prefix)
		inst := &Instance{Block: blk, Key: key, Address: child.Address, Ranges: ranges}
		inst.Attrs = make(map[string]cty.Value, len(child.Inputs)+len(staticAttrs))
		for k, v := range child.Inputs {
			inst.Attrs[k] = v
		}
		for k, v := range staticAttrs {
			inst.Attrs[k] = v
		}
		inst.Iteration = iterationOf(key, cty.NilVal)
		blk.Instances = append(blk.Instances, inst)
	}
	expansion := expansionExpr(sb.Body)
	if len(children) == 0 {
		if expansion != nil && knownEmpty(evalExpr(expansion, m.Scope.EvalContext())) {
			return nil
		}
		m.Root.Incomplete = true
		m.Root.Notes = append(m.Root.Notes, "module call did not resolve: "+prefix)
		inst := &Instance{Block: blk, Address: prefix, Ranges: map[string]hcl.Range{"": blk.Range}}
		ctx := m.Scope.EvalContext()
		if expansion != nil {
			ctx = unknownIteration(ctx)
			blk.KeyUnknown = true
		}
		inst.Attrs = evalBody(sb.Body, ctx, "", inst.Ranges, moduleMetaArgs)
		blk.Instances = []*Instance{inst}
		m.Root.Unresolved = append(m.Root.Unresolved, inst)
	}
	if expansion != nil && len(children) == 1 && children[0].Address == prefix {
		blk.KeyUnknown = true
	}
	blk.Overridable = expansion != nil && readsRootInput(m, expansion, 0)
	sort.SliceStable(blk.Instances, func(i, j int) bool { return blk.Instances[i].Address < blk.Instances[j].Address })
	return blk
}

func pick(attrs hclsyntax.Attributes, names map[string]bool) hclsyntax.Attributes {
	out := hclsyntax.Attributes{}
	for name, a := range attrs {
		if names[name] {
			out[name] = a
		}
	}
	return out
}

func knownEmpty(v cty.Value) bool {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return false
	}
	if v.Type() == cty.Number {
		n, _ := v.AsBigFloat().Int64()
		return n <= 0
	}
	if v.CanIterateElements() {
		return v.LengthInt() == 0
	}
	return false
}

// providerRef is the provider configuration a block names, as written: its
// provider argument, else the provider its type belongs to.
func providerRef(body *hclsyntax.Body, typ string) string {
	if attr, ok := body.Attributes["provider"]; ok {
		if t, ok := attr.Expr.(*hclsyntax.ScopeTraversalExpr); ok {
			return traversalText(t.Traversal)
		}
	}
	name, _, _ := strings.Cut(typ, "_")
	return name
}

func traversalTexts(body *hclsyntax.Body, name string) []string {
	attr, ok := body.Attributes[name]
	if !ok {
		return nil
	}
	var out []string
	for _, t := range attr.Expr.Variables() {
		out = append(out, traversalText(t))
	}
	return out
}

func traversalText(t hcl.Traversal) string {
	var b strings.Builder
	for i, step := range t {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			b.WriteString(s.Name)
		case hcl.TraverseAttr:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(s.Name)
		case hcl.TraverseIndex:
			b.WriteString(address.InstanceSuffix(s.Key))
		}
	}
	return b.String()
}

func blockAddr(b *Block) string {
	return address.Addr(address.Block{Kind: b.Kind, Type: b.Type, Name: b.Name})
}
