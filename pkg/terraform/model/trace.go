/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"reflect"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/refs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// markDuplicates flags the blocks whose address another block of the same
// module instance also has.
func markDuplicates(root *Root) {
	for _, m := range root.Modules {
		seen := map[string][]*Block{}
		for _, b := range m.Blocks {
			if b.Kind == KindLocals {
				continue
			}
			key := b.Kind + "\x00" + blockAddr(b)
			seen[key] = append(seen[key], b)
		}
		for _, blocks := range seen {
			if len(blocks) > 1 {
				for _, b := range blocks {
					b.Duplicate = true
				}
			}
		}
	}
}

// resolveProviders sets ProviderBlock: the provider configuration a block's
// module declares under that name, else the one the call passes through
// providers = {}, else, for a default configuration, the caller's. Provider
// blocks are keyed per module instance so two calls of the same module keep
// distinct configurations (and distinct default_tags).
func resolveProviders(root *Root) {
	byModule := map[*Module]map[string]*Block{}
	for _, m := range root.Modules {
		byModule[m] = map[string]*Block{}
		for _, b := range m.Blocks {
			if b.Kind != address.KindProvider {
				continue
			}
			byModule[m][ProviderKey(b.Type, b.Name)] = b
		}
	}
	for _, m := range root.Modules {
		for _, b := range m.Blocks {
			if b.Provider != "" {
				b.ProviderBlock = resolveProvider(byModule, m, b.Provider, 0)
			}
		}
	}
}

func resolveProvider(byModule map[*Module]map[string]*Block, m *Module, key string, depth int) *Block {
	if m == nil || depth > maxTraceDepth {
		return nil
	}
	if b, ok := byModule[m][key]; ok {
		return b
	}
	parent := parentOf(m)
	if parent == nil || len(m.Chain) == 0 {
		return nil
	}
	if call := m.Chain[len(m.Chain)-1].Body; call != nil {
		if attr, ok := call.Attributes["providers"]; ok {
			if obj, ok := attr.Expr.(*hclsyntax.ObjectConsExpr); ok {
				for _, item := range obj.Items {
					if exprText(item.KeyExpr) == key {
						return resolveProvider(byModule, parent, exprText(item.ValueExpr), depth+1)
					}
				}
			}
		}
	}
	if strings.Contains(key, ".") {
		return nil
	}
	return resolveProvider(byModule, parent, key, depth+1)
}

func exprText(expr hclsyntax.Expression) string {
	if k, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		expr = k.Wrapped
	}
	if t, ok := expr.(*hclsyntax.ScopeTraversalExpr); ok {
		return traversalText(t.Traversal)
	}
	return ""
}

type tracer struct {
	root    *Root
	blocks  map[string]map[string][]*Block
	modules map[string]*Module
	// memo caches traces that do not depend on a block instance: each
	// for_each expression is walked once per block, not once per instance.
	memo map[traceKey]traceResult
	// unresolved, when set, holds the module address and label of each
	// unresolved call: reading what one returns is not an untraced value, see
	// onlyUnresolved and exposeUnresolved.
	unresolved map[string]bool
	// outside is set while tracing the arguments of unresolved calls: a root
	// variable then reads no block.
	outside bool
	// resolved is the sibling tracer that tells which untraced values come
	// from unresolved calls alone.
	resolved *tracer
}

type traceKey struct {
	module  string
	expr    uintptr
	certain bool
	depth   int
}

type traceResult struct {
	out      []target
	untraced bool
}

type target struct {
	inst    *Instance
	attr    string
	read    string
	certain bool
}

func traceRoot(root *Root) {
	t := &tracer{root: root, blocks: map[string]map[string][]*Block{}, modules: map[string]*Module{}}
	for _, m := range root.Modules {
		t.modules[m.Address] = m
		t.blocks[m.Address] = map[string][]*Block{}
		for _, b := range m.Blocks {
			switch b.Kind {
			case address.KindResource, address.KindData, address.KindEphemeral:
				t.blocks[m.Address][blockAddr(b)] = append(t.blocks[m.Address][blockAddr(b)], b)
			}
		}
	}
	for _, m := range root.Modules {
		for _, b := range m.Blocks {
			var skip map[string]bool
			switch b.Kind {
			case address.KindResource, address.KindData, address.KindEphemeral:
				skip = metaArgs
			case address.KindModule:
				skip = moduleMetaArgs
			case address.KindOutput:
				skip = map[string]bool{"depends_on": true, "description": true, "sensitive": true}
			default:
				continue
			}
			for _, inst := range b.Instances {
				t.traceInstance(m, inst, skip)
			}
		}
	}
	t.exposeUnresolved()
}

func (t *tracer) traceInstance(m *Module, inst *Instance, skip map[string]bool) {
	b := inst.Block
	type seenKey struct {
		path string
		to   *Instance
		attr string
		read string
	}
	seen := map[seenKey]int{}
	walkExprs(b.Syntax.Body, nil, skip, nil, func(expr hcl.Expression, path []string, shadowed []string) {
		targets, untraced := t.trace(m, inst, expr, true, shadowed, 0)
		key := strings.Join(path, ".")
		for _, tg := range targets {
			certain := tg.certain && !uncertainBlock(b) && !uncertainBlock(tg.inst.Block)
			k := seenKey{key, tg.inst, tg.attr, tg.read}
			if i, ok := seen[k]; ok {
				inst.Refs[i].Certain = inst.Refs[i].Certain || certain
				continue
			}
			seen[k] = len(inst.Refs)
			inst.Refs = append(inst.Refs, Ref{Path: slices.Clone(path), To: tg.inst, Attr: tg.attr, Read: tg.read, Certain: certain})
		}
		if untraced {
			if t.onlyUnresolved(m, inst, expr, shadowed) {
				if inst.UnresolvedAt == nil {
					inst.UnresolvedAt = map[string]bool{}
				}
				inst.UnresolvedAt[key] = true
				return
			}
			if inst.Untraced == nil {
				inst.Untraced = map[string]bool{}
			}
			inst.Untraced[key] = true
		}
	})
}

// onlyUnresolved reports whether the only untraced values expr reads are what
// unresolved module calls return.
func (t *tracer) onlyUnresolved(m *Module, inst *Instance, expr hcl.Expression, shadowed []string) bool {
	if len(t.root.Unresolved) == 0 {
		return false
	}
	if t.resolved == nil {
		t.resolved = &tracer{root: t.root, blocks: t.blocks, modules: t.modules, unresolved: unresolvedCalls(t.root)}
	}
	_, untraced := t.resolved.trace(m, inst, expr, true, shadowed, 0)
	return !untraced
}

func uncertainBlock(b *Block) bool {
	return b.KeyUnknown || b.Overridable || b.Duplicate
}

// readsEachValue reports whether a reference to each reads the element
// rather than its key.
func readsEachValue(after []string) bool {
	return len(after) == 0 || after[0] != "key"
}

// walkExprs calls fn for every expression of body with its attribute path,
// names only: attributes, static nested blocks, and the for_each and content
// of dynamic blocks, whose iterator name shadows a reference root.
func walkExprs(
	body *hclsyntax.Body, prefix []string, skip map[string]bool, shadowed []string,
	fn func(hcl.Expression, []string, []string),
) {
	for name, attr := range body.Attributes {
		if !skip[name] {
			fn(attr.Expr, append(slices.Clone(prefix), name), shadowed)
		}
	}
	for _, nb := range body.Blocks {
		if skip[nb.Type] {
			continue
		}
		if !dynamicblock.Is(nb) {
			walkExprs(nb.Body, append(slices.Clone(prefix), nb.Type), nil, shadowed, fn)
			continue
		}
		path := append(slices.Clone(prefix), dynamicblock.GeneratedType(nb))
		if fe, ok := nb.Body.Attributes["for_each"]; ok {
			fn(fe.Expr, path, shadowed)
		}
		if content := dynamicblock.Content(nb); content != nil {
			walkExprs(content, path, nil, append(slices.Clone(shadowed), dynamicblock.IteratorName(nb)), fn)
		}
	}
}

// trace returns the instances expr references in module m, following locals,
// module arguments and module outputs, and whether it reads a value that it
// could not trace to a block. inst is the block instance that holds expr, used
// to resolve each.value against that instance's for_each.
func (t *tracer) trace(
	m *Module, inst *Instance, expr hcl.Expression, certain bool, shadowed []string, depth int,
) (out []target, untraced bool) {
	if depth > maxTraceDepth || m == nil || m.Scope == nil {
		return nil, true
	}
	// Instance-free traces are shared by every for_each key of a block.
	if inst == nil && len(shadowed) == 0 {
		key := traceKey{m.Address, exprPtr(expr), certain, depth}
		if t.memo == nil {
			t.memo = map[traceKey]traceResult{}
		}
		if got, ok := t.memo[key]; ok {
			return slices.Clone(got.out), got.untraced
		}
		out, untraced = t.traceUncached(m, nil, expr, certain, nil, depth)
		t.memo[key] = traceResult{out: out, untraced: untraced}
		return slices.Clone(out), untraced
	}
	return t.traceUncached(m, inst, expr, certain, shadowed, depth)
}

func (t *tracer) traceUncached(
	m *Module, inst *Instance, expr hcl.Expression, certain bool, shadowed []string, depth int,
) (out []target, untraced bool) {
	mayOnly := mayOnlyRanges(expr)
	for i, all := 0, refs.Of(expr); i < len(all); i++ {
		r := &all[i]
		if slices.Contains(shadowed, r.Traversal.RootName()) {
			untraced = true
			continue
		}
		c := certain && !within(r.Traversal.SourceRange(), mayOnly)
		var got []target
		var u bool
		switch r.Kind {
		case refs.KindResource, refs.KindData, refs.KindEphemeral:
			got, u = t.blockRef(m, inst, r, c)
		case refs.KindLocal:
			got, u = t.localRef(m, r, c, depth)
		case refs.KindVar:
			got, u = t.varRef(m, r, c, depth)
		case refs.KindModule:
			got, u = t.moduleRef(m, r, c, depth)
		case refs.KindEach:
			got, u = t.eachRef(m, inst, r, c, depth)
		}
		out = append(out, got...)
		untraced = untraced || u
	}
	return out, untraced
}

func exprPtr(expr hcl.Expression) uintptr {
	if expr == nil {
		return 0
	}
	v := reflect.ValueOf(expr)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return v.Pointer()
	default:
		return 0
	}
}

// localRef follows a local, and when the reference indexes a literal object
// with a static key, only that entry.
func (t *tracer) localRef(m *Module, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	e, ok := m.Scope.Locals[r.Name]
	if !ok {
		return nil, true
	}
	key, rest := localKey(r)
	if key != "" {
		if item, ok := objectEntry(e, key); ok {
			got, u := t.trace(m, nil, item, certain, nil, depth+1)
			extendTargetRead(got, rest)
			return got, u
		}
		// The local is not a literal object: follow it and keep the index
		// (local.tags.A reading tags = aws_s3_bucket.b.tags → tags.A).
		got, u := t.trace(m, nil, e, certain, nil, depth+1)
		extendTargetRead(got, append([]string{key}, rest...))
		return got, u
	}
	return t.trace(m, nil, e, certain, nil, depth+1)
}

// extendTargetRead appends steps to each target's read path (and sets attr
// when the target had none). The top-level attr is kept when already set.
func extendTargetRead(got []target, steps []string) {
	if len(steps) == 0 {
		return
	}
	suffix := strings.Join(steps, ".")
	for i := range got {
		switch {
		case got[i].read != "":
			got[i].read = got[i].read + "." + suffix
		case got[i].attr != "":
			got[i].read = got[i].attr + "." + suffix
		default:
			got[i].attr, got[i].read = steps[0], suffix
		}
	}
}

// localKey is the static map key a local reference reads, and the attribute
// names past that key: local.m["a"].id and local.m.a.id both give ("a", ["id"]).
func localKey(r *refs.Ref) (key string, rest []string) {
	after := r.After()
	if r.Key != nil {
		k, _ := r.Key.Unmark()
		if k.IsWhollyKnown() && !k.IsNull() && k.Type() == cty.String {
			return k.AsString(), after
		}
		return "", after
	}
	if len(after) == 0 {
		return "", nil
	}
	return after[0], after[1:]
}

// objectEntry returns the value expression of a literal object constructor
// entry whose key is name.
func objectEntry(expr hcl.Expression, name string) (hcl.Expression, bool) {
	obj, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return nil, false
	}
	for _, item := range obj.Items {
		if objectKeyName(item.KeyExpr) == name {
			return item.ValueExpr, true
		}
	}
	return nil, false
}

func objectKeyName(expr hclsyntax.Expression) string {
	if k, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		expr = k.Wrapped
	}
	if t, ok := expr.(*hclsyntax.ScopeTraversalExpr); ok && len(t.Traversal) == 1 {
		return t.Traversal.RootName()
	}
	if t, ok := expr.(*hclsyntax.TemplateExpr); ok && t.IsStringLiteral() {
		v, _ := t.Value(nil)
		if v.Type() == cty.String {
			return v.AsString()
		}
	}
	if lit, ok := expr.(*hclsyntax.LiteralValueExpr); ok {
		v, _ := lit.Val.Unmark()
		if v.Type() == cty.String {
			return v.AsString()
		}
	}
	return ""
}

// eachRef resolves each.value against the instance's for_each: when for_each
// is a resource (or data) map, the instance key selects that same-key instance.
func (t *tracer) eachRef(m *Module, inst *Instance, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	after := r.After()
	if !readsEachValue(after) {
		return nil, false
	}
	if inst == nil || inst.Block == nil || inst.Block.Syntax == nil {
		return nil, true
	}
	fe, ok := inst.Block.Syntax.Body.Attributes["for_each"]
	if !ok {
		return nil, true
	}
	got, u := t.trace(m, nil, fe.Expr, certain, nil, depth+1)
	if len(got) == 0 {
		return nil, u
	}
	attr := ""
	if len(after) > 1 {
		attr = after[1]
	}
	var out []target
	for _, tg := range got {
		if inst.Key != "" && tg.inst.Key != inst.Key {
			continue
		}
		c := certain && inst.Key != "" && tg.inst.Key == inst.Key
		tg.attr, tg.read = attr, attr
		tg.certain = c
		out = append(out, tg)
	}
	if len(out) == 0 {
		return nil, true
	}
	return out, false
}

func (t *tracer) blockRef(m *Module, from *Instance, r *refs.Ref, certain bool) ([]target, bool) {
	kind := map[refs.Kind]string{
		refs.KindResource: address.KindResource, refs.KindData: address.KindData, refs.KindEphemeral: address.KindEphemeral,
	}[r.Kind]
	blocks := t.blocks[m.Address][address.Addr(address.Block{Kind: kind, Type: r.Type, Name: r.Name})]
	if r.Name == "" {
		return nil, true
	}
	if len(blocks) == 0 {
		// A managed or data address the complete root does not declare
		// targets nothing; an incomplete root may still hold that block.
		return nil, t.root.Incomplete
	}
	attr, key := blockRefAttrAndKey(m, from, r, blocks)
	out := blockRefTargets(blocks, attr, key, r.DynamicKey, certain)
	read := r.ReadPath()
	for i := range out {
		out[i].read = read
	}
	return out, len(out) == 0
}

func blockRefAttrAndKey(m *Module, from *Instance, r *refs.Ref, blocks []*Block) (attr string, key *cty.Value) {
	if after := r.After(); len(after) > 0 {
		attr = after[0]
	}
	key = r.Key
	// Without an iteration of its own, the referencing instance gets a guessed
	// count.index of 0; that guess only selects an instance when the target
	// has a single one, else the selector stays dynamic and names the block.
	guessed := from == nil || from.Iteration == nil
	if key == nil && r.DynamicKey && r.KeyExpr != nil && (!guessed || instanceCount(blocks) <= 1) {
		if k, ok := evalIndexKey(m, from, r.KeyExpr); ok {
			key = &k
		}
	}
	return attr, key
}

func blockRefTargets(blocks []*Block, attr string, key *cty.Value, dynamicKey, certain bool) []target {
	var out []target
	for _, b := range blocks {
		for _, inst := range b.Instances {
			c := certain
			switch {
			case key != nil && !b.KeyUnknown:
				if inst.Key != address.InstanceSuffix(*key) {
					continue
				}
			case key != nil || dynamicKey:
				c = false
			}
			out = append(out, target{inst: inst, attr: attr, certain: c})
		}
	}
	return out
}

func instanceCount(blocks []*Block) int {
	n := 0
	for _, b := range blocks {
		n += len(b.Instances)
	}
	return n
}

// evalIndexKey evaluates a dynamic instance-key expression in the module
// scope, with the referencing instance's count/each binding. A non-expanded
// companion has no iteration: count.index is 0 so a known local.list[count.index]
// still selects a concrete instance.
func evalIndexKey(m *Module, from *Instance, expr hcl.Expression) (cty.Value, bool) {
	if m == nil || m.Scope == nil || expr == nil {
		return cty.NilVal, false
	}
	ctx := m.Scope.EvalContext().NewChild()
	if from != nil && from.Iteration != nil {
		ctx.Variables = from.Iteration
	} else {
		ctx.Variables = map[string]cty.Value{
			"count": cty.ObjectVal(map[string]cty.Value{"index": cty.NumberIntVal(0)}),
		}
	}
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return cty.NilVal, false
	}
	v, _ = v.Unmark()
	if !v.IsWhollyKnown() || v.IsNull() {
		return cty.NilVal, false
	}
	return v, true
}

func (t *tracer) varRef(m *Module, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	if m.Address == "" {
		if t.outside {
			// A root variable is an input from outside the root: no block
			// of the root flows through it.
			return nil, false
		}
		v := m.Scope.Var
		if v.IsKnown() && !v.IsNull() && v.Type().IsObjectType() && v.Type().HasAttribute(r.Name) {
			return nil, !v.GetAttr(r.Name).IsWhollyKnown()
		}
		return nil, true
	}
	parent := parentOf(m)
	if parent == nil || len(m.Chain) == 0 || m.Chain[len(m.Chain)-1].Body == nil {
		return nil, true
	}
	arg, ok := m.Chain[len(m.Chain)-1].Body.Attributes[r.Name]
	if !ok {
		return nil, false
	}
	return t.trace(parent, nil, arg.Expr, certain, nil, depth+1)
}

func (t *tracer) moduleRef(m *Module, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	if t.unresolved[unresolvedKey(m.Address, r.Name)] {
		// What an unresolved call returns carries only what its own
		// arguments gave it, and those are traced as exposed already.
		return nil, false
	}
	after := r.After()
	if r.Name == "" || len(after) == 0 {
		return nil, true
	}
	prefix := joinAddr(m.Address, "module."+r.Name)
	var out []target
	untraced := false
	found := false
	for _, child := range m.calls[r.Name] {
		rest := strings.TrimPrefix(child.Address, prefix)
		c := certain
		if r.Key != nil {
			if rest != address.InstanceSuffix(*r.Key) {
				continue
			}
		} else if r.DynamicKey {
			c = false
		}
		found = true
		expr := outputExpr(child, after[0])
		if expr == nil {
			untraced = true
			continue
		}
		got, u := t.trace(child, nil, expr, c, nil, depth+1)
		out = append(out, got...)
		untraced = untraced || u
	}
	if !found {
		// A module address the complete root does not declare targets nothing.
		return out, t.root.Incomplete
	}
	return out, untraced
}

func outputExpr(m *Module, name string) hcl.Expression {
	if m.Scope == nil {
		return nil
	}
	for _, body := range m.Scope.Bodies {
		for _, b := range body.Blocks {
			if b.Type == address.KindOutput && len(b.Labels) == 1 && b.Labels[0] == name {
				if a, ok := b.Body.Attributes["value"]; ok {
					return a.Expr
				}
			}
		}
	}
	return nil
}

// mayOnlyFunctions return one of several arguments, or none.
var mayOnlyFunctions = map[string]bool{
	"try": true, "can": true, "coalesce": true, "coalescelist": true, "lookup": true,
	"one": true, "element": true, "compact": true, "setsubtract": true, "setintersection": true,
}

// mayOnlyRanges returns the ranges of expr whose references may not reach the
// value: conditional branches, the arguments of functions that pick among
// them, filtered for expressions.
func mayOnlyRanges(expr hcl.Expression) []hcl.Range {
	native, ok := expr.(hclsyntax.Expression)
	if !ok {
		return nil
	}
	var out []hcl.Range
	_ = hclsyntax.VisitAll(native, func(node hclsyntax.Node) hcl.Diagnostics {
		switch n := node.(type) {
		case *hclsyntax.ConditionalExpr:
			out = append(out, n.TrueResult.Range(), n.FalseResult.Range())
		case *hclsyntax.FunctionCallExpr:
			if mayOnlyFunctions[n.Name] {
				for _, a := range n.Args {
					out = append(out, a.Range())
				}
			}
		case *hclsyntax.ForExpr:
			if n.CondExpr != nil {
				out = append(out, n.Range())
			}
		}
		return nil
	})
	return out
}

func within(r hcl.Range, ranges []hcl.Range) bool {
	for _, o := range ranges {
		if o.Filename == r.Filename && o.Start.Byte <= r.Start.Byte && r.End.Byte <= o.End.Byte {
			return true
		}
	}
	return false
}
