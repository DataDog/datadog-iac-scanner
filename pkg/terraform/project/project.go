/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package project turns Terraform models into rule input for the Terraform rule contract:
// one document per root, module instance and file, and the engine indexes
// the Terraform library reads from input._dd.
package project

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/hashicorp/hcl/v2"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/zclconf/go-cty/cty"
)

// Options configure a projection.
type Options struct {
	// Placeholder stands for unknown values (see value.NewPlaceholder).
	Placeholder string
	// LiteralKeys selects the companion literals to index (see
	// LiteralKeysFromModules).
	LiteralKeys LiteralKeys
	// Cross holds the literal companions of the other roots (3.8).
	Cross *CrossIndex
}

// Projection is the rule input of one evaluation and what the engine needs
// to locate findings in it.
type Projection struct {
	// Input is {"document": [...], "_dd": {...}}.
	Input ast.Value
	// Blocks locates every block instance of the input, by id.
	Blocks map[string]*Located
	// Unknown is set for the types of a root with a placeholder in a block.
	Unknown map[TypeKey]bool
	// Open is set when a block holds the placeholder or has a relation that
	// ends with it.
	Open bool
	// External lists the blocks of other roots that a related list names.
	External map[string]bool
	// Cross lists the cross-root matches the relations use.
	Cross []CrossMatch
	// Incompleteness says, per root with an unresolved module call, which
	// relation answers it made incomplete.
	Incompleteness []RootIncompleteness
	// BlocksComplete is false when an unresolved module call may invent
	// blocks of types not yet listed in _dd.blocks; absence checks must not
	// treat those inventories as closed.
	BlocksComplete bool

	parts *parts
	rel   *relIndex
}

// TypeKey names a block type in a root.
type TypeKey struct {
	Root, Kind, Type string
}

// Located is a block instance of the input.
type Located struct {
	Root, File, Address string
	Kind, Type          string
	// ID is the block id in _dd.
	ID string
	// Block is the block as written.
	Block *model.Block
	// Term is the projected instance, as rules see it.
	Term *ast.Term
	// Placeholder is set when the block holds the placeholder.
	Placeholder bool
	// RelPlaceholder is set when a relation list of the block ends with the
	// placeholder (an answer that may be incomplete) or names a block that
	// holds it.
	RelPlaceholder bool
	inst           *model.Instance
	provider       string
	ranges         map[string]hcl.Range
}

// Instance returns the block instance projected, nil for evidence of another
// root.
func (l *Located) Instance() *model.Instance { return l.inst }

// Span returns the source range of the whole block, from its header to its
// closing brace; the header alone when the block has no native syntax.
func (l *Located) Span() hcl.Range {
	if l.Block != nil && l.Block.Syntax != nil {
		return l.Block.Syntax.Range()
	}
	return l.ranges[""]
}

// Range returns the source range of path in the block: the path itself, else
// its deepest ancestor with a range, the block header for []. A nested block
// list named without an index is its first block. Path steps are attribute
// names and list indexes.
func (l *Located) Range(path []any) hcl.Range {
	steps := make([]string, 0, len(path))
	for _, s := range path {
		switch s := s.(type) {
		case string:
			steps = append(steps, s)
		case int:
			steps = append(steps, strconv.Itoa(s))
		case int64:
			steps = append(steps, strconv.FormatInt(s, 10))
		case json.Number:
			i, err := s.Int64()
			if err != nil {
				return l.ranges[""]
			}
			steps = append(steps, strconv.FormatInt(i, 10))
		default:
			return l.ranges[""]
		}
	}
	for n := len(steps); n > 0; n-- {
		key := strings.Join(steps[:n], ".")
		if r, ok := l.ranges[key]; ok {
			return r
		}
		if r, ok := l.ranges[key+".0"]; ok {
			return r
		}
	}
	return l.ranges[""]
}

// Project builds the input of an evaluation over roots.
func Project(roots []*model.Root, opts Options) *Projection {
	p := newProjector(opts)
	for _, r := range roots {
		p.assignIDs(r)
	}
	for _, r := range roots {
		p.root(r)
	}
	proj := &Projection{Input: p.input(), Blocks: p.located, Unknown: p.unknown, BlocksComplete: !p.incompleteInventory}
	proj.parts = p.parts
	proj.rel = p.rel
	proj.External = p.external
	proj.Cross = p.cross
	proj.Incompleteness = p.rel.incompleteness
	for _, loc := range p.located {
		if loc.Placeholder || loc.RelPlaceholder {
			proj.Open = true
			break
		}
	}
	return proj
}

var typedKinds = []string{address.KindResource, address.KindData, address.KindEphemeral, address.KindProvider}

var listKinds = []string{address.KindModule, address.KindVariable, address.KindOutput, model.KindLocals}

type projector struct {
	opts    Options
	t       terms
	ids     map[*model.Instance]string
	located map[string]*Located
	unknown map[TypeKey]bool

	emptyObject *ast.Term
	emptySet    *ast.Term
	docs        []*ast.Term
	typed       map[string]map[string][]*ast.Term
	lists       map[string][]*ast.Term
	byID        [][2]*ast.Term
	// nested is block id -> the nested block lists taken off the block object.
	nested [][2]*ast.Term
	rel    *relIndex
	roots  map[string]bool
	order  []string
	keys   map[string]*ast.Term

	placeholderList      *ast.Term
	parts                *parts
	external             map[string]bool
	cross                []CrossMatch
	incompleteInventory  bool
}

func newProjector(opts Options) *projector {
	p := &projector{
		opts:        opts,
		t:           terms{placeholder: ast.StringTerm(opts.Placeholder)},
		ids:         map[*model.Instance]string{},
		located:     map[string]*Located{},
		unknown:     map[TypeKey]bool{},
		emptyObject: ast.ObjectTerm(),
		emptySet:    ast.SetTerm(),
		typed:       map[string]map[string][]*ast.Term{},
		lists:       map[string][]*ast.Term{},
		rel:         newRelIndex(opts.LiteralKeys),
		roots:       map[string]bool{},
		keys:        map[string]*ast.Term{},
		external:    map[string]bool{},
	}
	p.placeholderList = ast.ArrayTerm(p.t.placeholder)
	for _, k := range typedKinds {
		p.typed[k] = map[string][]*ast.Term{}
	}
	return p
}

// key returns the shared term of an object key.
func (p *projector) key(name string) *ast.Term {
	t, ok := p.keys[name]
	if !ok {
		t = ast.StringTerm(name)
		p.keys[name] = t
	}
	return t
}

// assignIDs names every instance of r: root-qualified address, plus the
// declaring position when the address is not unique.
func (p *projector) assignIDs(r *model.Root) {
	for _, m := range r.Modules {
		for _, b := range m.Blocks {
			for _, inst := range b.Instances {
				id := r.ID + "/" + inst.Address
				if b.Duplicate || b.Kind == model.KindLocals {
					id += "#" + b.File + ":" + strconv.Itoa(b.Range.Start.Line)
				}
				p.ids[inst] = id
			}
		}
	}
}

func (p *projector) root(r *model.Root) {
	p.roots[r.ID] = true
	if r.Incomplete {
		// An unresolved module may create blocks of any type; typed inventories
		// are not closed until every call resolves.
		p.incompleteInventory = true
	}
	if r.IncompleteEverywhere() {
		p.rel.incomplete[r.ID] = true
	} else if r.Incomplete {
		p.rel.scoped[r.ID] = r
	}
	for _, m := range r.Modules {
		var files []string
		byFile := map[string]*document{}
		for _, b := range m.Blocks {
			d, ok := byFile[b.File]
			if !ok {
				d = newDocument()
				byFile[b.File] = d
				files = append(files, b.File)
			}
			p.block(r, b, d)
		}
		for _, f := range files {
			p.docs = append(p.docs, byFile[f].term(r.ID+"|"+m.Address+"|"+f, f))
		}
	}
}

// document collects the blocks of one root, module instance and file.
type document struct {
	typed map[string]map[string][][2]*ast.Term
	keyed map[string][][2]*ast.Term
	lists map[string][]*ast.Term
}

func newDocument() *document {
	return &document{
		typed: map[string]map[string][][2]*ast.Term{},
		keyed: map[string][][2]*ast.Term{},
		lists: map[string][]*ast.Term{},
	}
}

func (d *document) add(b *model.Block, key string, t *ast.Term) {
	if b.Duplicate {
		key += "#" + strconv.Itoa(b.Range.Start.Line)
	}
	switch b.Kind {
	case address.KindResource, address.KindData, address.KindEphemeral:
		if d.typed[b.Kind] == nil {
			d.typed[b.Kind] = map[string][][2]*ast.Term{}
		}
		d.typed[b.Kind][b.Type] = append(d.typed[b.Kind][b.Type], [2]*ast.Term{ast.StringTerm(key), t})
	case address.KindModule, address.KindVariable, address.KindOutput:
		d.keyed[b.Kind] = append(d.keyed[b.Kind], [2]*ast.Term{ast.StringTerm(key), t})
	case address.KindProvider:
		d.lists[b.Type] = append(d.lists[b.Type], t)
	case model.KindLocals:
		d.lists[""] = append(d.lists[""], t)
	}
}

func (d *document) term(id, file string) *ast.Term {
	pairs := [][2]*ast.Term{ast.Item(ast.StringTerm("id"), ast.StringTerm(id)), ast.Item(ast.StringTerm("file"), ast.StringTerm(file))}
	for _, kind := range []string{address.KindResource, address.KindData, address.KindEphemeral} {
		if byType := d.typed[kind]; len(byType) > 0 {
			typePairs := make([][2]*ast.Term, 0, len(byType))
			for typ, blocks := range byType {
				typePairs = append(typePairs, ast.Item(ast.StringTerm(typ), ast.ObjectTerm(blocks...)))
			}
			pairs = append(pairs, ast.Item(ast.StringTerm(kind), ast.ObjectTerm(typePairs...)))
		}
	}
	for _, kind := range []string{address.KindModule, address.KindVariable, address.KindOutput} {
		if blocks := d.keyed[kind]; len(blocks) > 0 {
			pairs = append(pairs, ast.Item(ast.StringTerm(kind), ast.ObjectTerm(blocks...)))
		}
	}
	var providers [][2]*ast.Term
	for typ, blocks := range d.lists {
		if typ == "" {
			pairs = append(pairs, ast.Item(ast.StringTerm(model.KindLocals), ast.ArrayTerm(blocks...)))
		} else {
			providers = append(providers, ast.Item(ast.StringTerm(typ), ast.ArrayTerm(blocks...)))
		}
	}
	if len(providers) > 0 {
		pairs = append(pairs, ast.Item(ast.StringTerm(address.KindProvider), ast.ObjectTerm(providers...)))
	}
	return ast.ObjectTerm(pairs...)
}

// cached is the term of an attribute value, shared by the next instance of
// the block when its value is the same.
type cached struct {
	v       cty.Value
	t       *ast.Term
	unknown bool
}

// block projects the instances of b. Values every instance shares are one
// term: block-level metadata, and attributes equal to the previous
// instance's.
func (p *projector) block(r *model.Root, b *model.Block, d *document) {
	shared := p.sharedMeta(r, b)
	nonliteral := make([]*ast.Term, 0, len(b.Nonliteral))
	for _, path := range b.Nonliteral {
		nonliteral = append(nonliteral, ast.StringTerm(path))
	}
	nonliteralTerm := ast.ArrayTerm(nonliteral...)
	sharedDerived := ast.ObjectTerm(
		ast.Item(p.key("template"), p.emptyObject),
		ast.Item(p.key("json"), p.emptyObject),
		ast.Item(p.key("nonliteral"), nonliteralTerm),
	)
	prev := map[string]cached{}
	providerID := ""
	if b.ProviderBlock != nil && len(b.ProviderBlock.Instances) > 0 {
		providerID = p.ids[b.ProviderBlock.Instances[0]]
	}
	for _, inst := range b.Instances {
		id := p.ids[inst]
		key := instanceKey(b, inst)
		var unknown bool
		var t *ast.Term
		t, prev, unknown = p.instanceTerm(inst, id, key, shared, sharedDerived, nonliteralTerm, prev)
		d.add(b, key, t)
		p.index(r, b, inst, id, t)
		p.located[id] = &Located{
			ID: id, Root: r.ID, File: b.File, Address: inst.Address, Kind: b.Kind, Type: b.Type, Block: b, Term: t,
			Placeholder: unknown, ranges: inst.Ranges, inst: inst, provider: providerID,
		}
		p.order = append(p.order, id)
		if unknown {
			p.unknown[TypeKey{Root: r.ID, Kind: b.Kind, Type: b.Type}] = true
		}
	}
}

// filterInterpretation is the derived reading of a metric filter's pattern:
// status "ok" with the expression tree, or "unsupported"/"unknown" with the
// placeholder so rules that cannot prove the pattern stay uncertain. The
// pattern attribute itself stays the evaluated string.
func (p *projector) filterInterpretation(inst *model.Instance) (*ast.Term, bool) {
	if inst.Block == nil || inst.Block.Type != "aws_cloudwatch_log_metric_filter" {
		return nil, false
	}
	v, ok := inst.Attrs["pattern"]
	if !ok {
		return nil, false
	}
	v, _ = v.UnmarkDeep()
	if v.IsNull() {
		return nil, false
	}
	uncertain := func(status string) (*ast.Term, bool) {
		return ast.ObjectTerm(
			ast.Item(p.key("status"), ast.StringTerm(status)),
			ast.Item(p.key("expr"), p.t.placeholder),
		), true
	}
	if !v.IsKnown() || v.Type() != cty.String || value.HasUnknownMarker(v.AsString()) {
		return uncertain("unknown")
	}
	inter := jsonfilter.Interpret(v.AsString())
	if inter.Status != jsonfilter.StatusOK {
		return uncertain("unsupported")
	}
	expr, err := ast.InterfaceToValue(inter.Expr)
	if err != nil {
		return uncertain("unsupported")
	}
	return ast.ObjectTerm(
		ast.Item(p.key("status"), ast.StringTerm("ok")),
		ast.Item(p.key("expr"), &ast.Term{Value: expr}),
	), false
}

// instanceTerm is the block as a rule sees it. A nested block list is recorded
// under _dd.nested instead of on the object, so a rule that only names the
// block does not hash every generated element.
func (p *projector) instanceTerm(
	inst *model.Instance, id, key string, shared [][2]*ast.Term, sharedDerived, nonliteralTerm *ast.Term,
	prev map[string]cached,
) (*ast.Term, map[string]cached, bool) {
	pairs := make([][2]*ast.Term, 0, len(inst.Attrs)+1)
	var nested [][2]*ast.Term
	unknown := false
	next := make(map[string]cached, len(inst.Attrs))
	for _, name := range sortedKeys(inst.Attrs) {
		v := inst.Attrs[name]
		var c cached
		ok := false
		if prev != nil {
			c, ok = prev[name]
		}
		if !ok || !c.v.RawEquals(v) {
			p.t.unknown = false
			c = cached{v: v, t: p.t.term(v), unknown: p.t.unknown}
		}
		next[name] = c
		if c.t == nil {
			continue
		}
		unknown = unknown || c.unknown
		item := ast.Item(p.key(name), c.t)
		if nestedBlocks(v) {
			nested = append(nested, item)
			continue
		}
		pairs = append(pairs, item)
	}
	if len(nested) > 0 {
		p.nested = append(p.nested, ast.Item(ast.StringTerm(id), ast.ObjectTerm(nested...)))
	}
	derived := sharedDerived
	if len(inst.Templates) > 0 || len(inst.JSON) > 0 || len(inst.JSONExpr) > 0 {
		derived = p.derived(inst, nonliteralTerm)
		unknown = true
	}
	computed := p.emptyObject
	if len(inst.Computed) > 0 {
		p.t.unknown = false
		computed = p.computed(inst)
		unknown = unknown || p.t.unknown
	}
	meta := append([][2]*ast.Term{
		ast.Item(p.key("id"), ast.StringTerm(id)),
		ast.Item(p.key("address"), ast.StringTerm(inst.Address)),
		ast.Item(p.key("key"), ast.StringTerm(key)),
		ast.Item(p.key("derived"), derived),
		ast.Item(p.key("computed"), computed),
		ast.Item(p.key("written"), p.written(inst)),
	}, shared...)
	if filter, uncertain := p.filterInterpretation(inst); filter != nil {
		meta = append(meta, ast.Item(p.key("filter"), filter))
		unknown = unknown || uncertain
	}
	pairs = append(pairs, ast.Item(p.key("_dd_meta"), ast.ObjectTerm(meta...)))
	return ast.ObjectTerm(pairs...), next, unknown
}

// nestedBlocks reports a list of objects written as nested blocks. Scalar
// lists, such as cidr_blocks, stay on the block.
func nestedBlocks(v cty.Value) bool {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return false
	}
	ty := v.Type()
	if (!ty.IsTupleType() && !ty.IsListType() && !ty.IsSetType()) || v.LengthInt() == 0 {
		return false
	}
	it := v.ElementIterator()
	if !it.Next() {
		return false
	}
	_, e := it.Element()
	// The type decides, not the value: an unknown string such as x.id is
	// still an attribute element.
	return e.Type().IsObjectType()
}

// sharedMeta returns the _dd_meta entries every instance of b shares.
func (p *projector) sharedMeta(r *model.Root, b *model.Block) [][2]*ast.Term {
	label := b.Name
	if b.Kind == address.KindProvider {
		label = b.Type
	}
	lifecycle := p.emptyObject
	if b.Lifecycle != cty.NilVal {
		if t := p.t.term(b.Lifecycle); t != nil {
			lifecycle = t
		}
	}
	dependsOn := make([]*ast.Term, 0, len(b.DependsOn))
	for _, d := range b.DependsOn {
		dependsOn = append(dependsOn, ast.StringTerm(d))
	}
	meta := [][2]*ast.Term{
		ast.Item(p.key("kind"), ast.StringTerm(b.Kind)),
		ast.Item(p.key("type"), ast.StringTerm(b.Type)),
		ast.Item(p.key("label"), ast.StringTerm(label)),
		ast.Item(p.key("module"), ast.StringTerm(b.Module.Address)),
		ast.Item(p.key("root"), ast.StringTerm(r.ID)),
		ast.Item(p.key("file"), ast.StringTerm(b.File)),
		ast.Item(p.key("line"), ast.IntNumberTerm(b.Range.Start.Line)),
		ast.Item(p.key("lifecycle"), lifecycle),
		ast.Item(p.key("depends_on"), ast.ArrayTerm(dependsOn...)),
	}
	if b.ProviderBlock != nil && len(b.ProviderBlock.Instances) > 0 {
		if id, ok := p.ids[b.ProviderBlock.Instances[0]]; ok {
			meta = append(meta, ast.Item(p.key("provider"), ast.StringTerm(id)))
		}
	}
	return meta
}

// instanceKey is the key of an instance in its document and _dd_meta: the
// label and instance key for expanded kinds, the provider key, the name of a
// variable or output, "" for locals.
func instanceKey(b *model.Block, inst *model.Instance) string {
	switch b.Kind {
	case address.KindProvider:
		return model.ProviderKey(b.Type, b.Name)
	case model.KindLocals:
		return ""
	}
	return b.Name + inst.Key
}

// computed is the term of the planned values the configuration of inst does
// not write; an unknown one is the placeholder.
func (p *projector) computed(inst *model.Instance) *ast.Term {
	pairs := make([][2]*ast.Term, 0, len(inst.Computed))
	for _, name := range sortedKeys(inst.Computed) {
		if t := p.t.term(inst.Computed[name]); t != nil {
			pairs = append(pairs, ast.Item(p.key(name), t))
		}
	}
	return ast.ObjectTerm(pairs...)
}

// written is the set of dot-joined attribute paths the configuration of
// inst writes, including paths whose value is unknown. Null attributes are
// absent, as in the projected block.
func (p *projector) written(inst *model.Instance) *ast.Term {
	if len(inst.Attrs) == 0 {
		return p.emptySet
	}
	var paths []string
	for _, name := range sortedKeys(inst.Attrs) {
		paths = appendWrittenPaths(paths, "", name, inst.Attrs[name])
	}
	if len(paths) == 0 {
		return p.emptySet
	}
	terms := make([]*ast.Term, len(paths))
	for i, path := range paths {
		terms[i] = ast.StringTerm(path)
	}
	return ast.SetTerm(terms...)
}

func appendWrittenPaths(out []string, prefix, name string, v cty.Value) []string {
	v, _ = v.UnmarkDeep()
	if v.IsNull() {
		return out
	}
	path := name
	if prefix != "" {
		path = prefix + "." + name
	}
	out = append(out, path)
	if !v.IsKnown() {
		return out
	}
	ty := v.Type()
	switch {
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		i := 0
		for it := v.ElementIterator(); it.Next(); i++ {
			_, e := it.Element()
			out = appendWrittenPaths(out, path, strconv.Itoa(i), e)
		}
	case ty.IsMapType() || ty.IsObjectType():
		m := v.AsValueMap()
		for _, k := range sortedKeys(m) {
			out = appendWrittenPaths(out, path, k, m[k])
		}
	}
	return out
}

func (p *projector) derived(inst *model.Instance, nonliteral *ast.Term) *ast.Term {
	templates := make([][2]*ast.Term, 0, len(inst.Templates))
	for _, path := range sortedKeys(inst.Templates) {
		parts := make([]*ast.Term, 0, len(inst.Templates[path]))
		for _, part := range inst.Templates[path] {
			t := p.t.term(part)
			if t == nil {
				t = p.t.placeholder
			}
			parts = append(parts, t)
		}
		templates = append(templates, ast.Item(p.key(path), ast.ArrayTerm(parts...)))
	}
	docs := make([][2]*ast.Term, 0, len(inst.JSON))
	for _, path := range sortedKeys(inst.JSON) {
		t := p.t.term(inst.JSON[path])
		if t == nil {
			t = ast.NullTerm()
		}
		docs = append(docs, ast.Item(p.key(path), t))
	}
	exprDocs := make([][2]*ast.Term, 0, len(inst.JSONExpr))
	for _, path := range sortedKeys(inst.JSONExpr) {
		leaves := inst.JSONExpr[path]
		pairs := make([][2]*ast.Term, 0, len(leaves))
		for _, leaf := range sortedKeys(leaves) {
			pairs = append(pairs, ast.Item(p.key(leaf), ast.StringTerm(leaves[leaf])))
		}
		exprDocs = append(exprDocs, ast.Item(p.key(path), ast.ObjectTerm(pairs...)))
	}
	return ast.ObjectTerm(
		ast.Item(p.key("template"), ast.ObjectTerm(templates...)),
		ast.Item(p.key("json"), ast.ObjectTerm(docs...)),
		ast.Item(p.key("json_expr"), ast.ObjectTerm(exprDocs...)),
		ast.Item(p.key("nonliteral"), nonliteral),
	)
}

// index adds an instance to the engine indexes.
func (p *projector) index(r *model.Root, b *model.Block, inst *model.Instance, id string, t *ast.Term) {
	if slices.Contains(typedKinds, b.Kind) {
		p.typed[b.Kind][b.Type] = append(p.typed[b.Kind][b.Type], t)
	} else {
		p.lists[b.Kind] = append(p.lists[b.Kind], t)
	}
	p.byID = append(p.byID, ast.Item(p.key(id), t))

	for _, ref := range inst.Refs {
		if to, ok := p.ids[ref.To]; ok {
			p.rel.reference(id, b, to, ref)
		}
	}
	for path := range inst.Untraced {
		p.rel.markUntargeted(r.ID, b.Kind, b.Type, path)
		p.rel.entry(id).targets.list(path).ph = true
	}
	for path := range inst.UnresolvedAt {
		p.rel.notePath(b.Kind, b.Type, path)
		p.rel.entry(id).targets.list(path).ph = true
	}
	p.rel.literals(r.ID, b, inst, id)
}

// stringsAt appends the known strings at the attribute names path in v,
// through list elements at any depth.
func stringsAt(v cty.Value, path, out []string) []string {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return out
	}
	ty := v.Type()
	switch {
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			out = stringsAt(e, path, out)
		}
	case len(path) == 0:
		if ty == cty.String {
			out = append(out, v.AsString())
		}
	case ty.IsObjectType() && ty.HasAttribute(path[0]):
		out = stringsAt(v.GetAttr(path[0]), path[1:], out)
	case ty.IsMapType():
		if k := cty.StringVal(path[0]); v.HasIndex(k).True() {
			out = stringsAt(v.Index(k), path[1:], out)
		}
	}
	return out
}

func (p *projector) input() ast.Value {
	blocks := make([][2]*ast.Term, 0, len(typedKinds)+len(listKinds))
	for _, kind := range typedKinds {
		byType := make([][2]*ast.Term, 0, len(p.typed[kind]))
		for typ, list := range p.typed[kind] {
			byType = append(byType, ast.Item(p.key(typ), ast.ArrayTerm(list...)))
		}
		blocks = append(blocks, ast.Item(p.key(kind), ast.ObjectTerm(byType...)))
	}
	for _, kind := range listKinds {
		blocks = append(blocks, ast.Item(p.key(kind), ast.ArrayTerm(p.lists[kind]...)))
	}
	p.resolve()
	related, targets, referrers := p.relationTerms()
	p.parts = &parts{
		typed: p.typed, lists: p.lists, byID: p.byID, docs: p.docs, nested: p.nested,
		related: related, targets: targets, referrers: referrers,
	}
	ddPairs := [][2]*ast.Term{
		ast.Item(p.key("placeholder"), p.t.placeholder),
		ast.Item(p.key("blocks_complete"), ast.BooleanTerm(!p.incompleteInventory)),
		ast.Item(p.key("blocks"), ast.ObjectTerm(blocks...)),
		ast.Item(p.key("by_id"), ast.ObjectTerm(p.byID...)),
		ast.Item(p.key("related"), related),
		ast.Item(p.key("targets"), targets),
		ast.Item(p.key("referrers"), referrers),
	}
	if len(p.nested) > 0 {
		ddPairs = append(ddPairs, ast.Item(p.key("nested"), ast.ObjectTerm(p.nested...)))
	}
	dd := ast.NewObject(ddPairs...)
	return ast.NewObject(
		ast.Item(p.key("document"), ast.ArrayTerm(p.docs...)),
		ast.Item(p.key("_dd"), ast.NewTerm(dd)),
	)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
