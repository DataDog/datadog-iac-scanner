/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/zclconf/go-cty/cty"
)

// The relation indexes of input._dd are final answers, computed here:
//
//	related:   {id: {type: {pathKey: [id, ...]}}}
//	targets:   {id: {pathKey: [id, ...]}}
//	referrers: {id: {pathKey: [id, ...]}}
//
// Each list is the concrete block ids, then the placeholder once when the
// answer may be incomplete: an uncertain reference, an untraced value at the
// path, a companion whose count or for_each is unknown, a literal that may
// name a block of another provider scope, or an incomplete root. The library
// only looks the lists up.

// globalLiteralTypes are the types whose names are global to every provider
// configuration of a partition: a literal names the same block under any.
var globalLiteralTypes = map[string]bool{"aws_s3_bucket": true}

// ViaKey is the key of the targets index that holds the blocks a source
// attribute reads through one attribute path of the target: metric_name#name
// lists the blocks whose name the attribute reads, and
// metric_name#metric_transformation.name the ones whose transformation name
// it reads. The plain path lists them
// whatever attribute is read.
func ViaKey(path, attr string) string { return path + "#" + attr }

// idList is the answer to one relation lookup.
type idList struct {
	ids  []string
	seen map[string]struct{}
	ph   bool
}

func (l *idList) addLast(id string) {
	if n := len(l.ids); n > 0 && l.ids[n-1] == id {
		return
	}
	l.ids = append(l.ids, id)
}

func (l *idList) add(id string) {
	if l.seen == nil {
		l.seen = make(map[string]struct{}, 4)
		for _, existing := range l.ids {
			l.seen[existing] = struct{}{}
		}
	}
	if _, ok := l.seen[id]; ok {
		return
	}
	l.seen[id] = struct{}{}
	l.ids = append(l.ids, id)
}

// pathLists maps a dot-joined attribute path to its answer.
type pathLists map[string]*idList

func (m *pathLists) list(path string) *idList {
	if *m == nil {
		*m = pathLists{}
	}
	l, ok := (*m)[path]
	if !ok {
		l = &idList{}
		(*m)[path] = l
	}
	return l
}

// relEntry holds the relations of one block instance: the references to it
// (referrers, related) and from it (targets).
type relEntry struct {
	referrers pathLists
	related   map[string]pathLists
	targets   pathLists
}

func (e *relEntry) relatedList(typ, path string) *idList {
	if e.related == nil {
		e.related = map[string]pathLists{}
	}
	m := e.related[typ]
	l := m.list(path)
	e.related[typ] = m
	return l
}

// companion is a block that names a target by a written literal.
type companion struct {
	id      string
	certain bool
}

// literalRel is one entry of the literal_keys table, seen from the target
// type: the companion type and path that may name it by the target
// attributes.
type literalRel struct {
	companion, path string
	attrs           []string
}

// relIndex gathers what the relation answers are computed from while the
// blocks are projected.
type relIndex struct {
	keys LiteralKeys
	// byTarget lists, per target type, the companions that may name it.
	byTarget map[string][]literalRel
	// targetAttrs lists, per target type, the attributes companions name.
	targetAttrs map[string][]string

	entries map[string]*relEntry
	// untargeted: root -> kind -> type -> path.
	untargeted map[string]map[string]map[string]map[string]bool
	incomplete map[string]bool
	// scoped holds the roots whose only incompleteness is unresolved module
	// calls: their blocks are incomplete when a call may reach them.
	scoped map[string]*model.Root
	// exposed holds the ids of the instances an unresolved call may reach.
	exposed        map[string]bool
	incompleteness []RootIncompleteness
	// paths and pairs list every relation path seen and every (companion
	// type, path) pair, the keys an incomplete root answers with the
	// placeholder.
	paths map[string]bool
	pairs map[[2]string]bool
	// viaPaths holds the attribute-qualified paths, path#attr, of the targets
	// index.
	viaPaths map[string]bool
	allVia   map[string]bool
	// companions: root -> type -> path -> value -> companions.
	companions map[string]map[string]map[string]map[string][]companion
	// values: root -> type -> attribute -> value -> ids, the known strings of
	// the target attributes; unknown: root -> type -> attribute.
	values  map[string]map[string]map[string]map[string][]string
	unknown map[string]map[string]map[string]bool
}

func newRelIndex(keys LiteralKeys) *relIndex {
	x := &relIndex{
		keys:        keys,
		byTarget:    map[string][]literalRel{},
		targetAttrs: map[string][]string{},
		entries:     map[string]*relEntry{},
		untargeted:  map[string]map[string]map[string]map[string]bool{},
		incomplete:  map[string]bool{},
		scoped:      map[string]*model.Root{},
		exposed:     map[string]bool{},
		paths:       map[string]bool{},
		pairs:       map[[2]string]bool{},
		viaPaths:    map[string]bool{},
		companions:  map[string]map[string]map[string]map[string][]companion{},
		values:      map[string]map[string]map[string]map[string][]string{},
		unknown:     map[string]map[string]map[string]bool{},
	}
	for _, typ := range sortedKeys(keys) {
		for _, path := range sortedKeys(keys[typ]) {
			x.paths[path] = true
			x.pairs[[2]string{typ, path}] = true
			for _, target := range sortedKeys(keys[typ][path]) {
				attrs := keys[typ][path][target]
				x.byTarget[target] = append(x.byTarget[target], literalRel{companion: typ, path: path, attrs: attrs})
				for _, a := range attrs {
					if !slices.Contains(x.targetAttrs[target], a) {
						x.targetAttrs[target] = append(x.targetAttrs[target], a)
					}
				}
			}
		}
	}
	return x
}

func (x *relIndex) entry(id string) *relEntry {
	e, ok := x.entries[id]
	if !ok {
		e = &relEntry{}
		x.entries[id] = e
	}
	return e
}

func (x *relIndex) markUntargeted(root, kind, typ, path string) {
	byKind, ok := x.untargeted[root]
	if !ok {
		byKind = map[string]map[string]map[string]bool{}
		x.untargeted[root] = byKind
	}
	byType, ok := byKind[kind]
	if !ok {
		byType = map[string]map[string]bool{}
		byKind[kind] = byType
	}
	paths, ok := byType[typ]
	if !ok {
		paths = map[string]bool{}
		byType[typ] = paths
	}
	paths[path] = true
	x.notePath(kind, typ, path)
}

// notePath records a relation path seen in the evaluation.
func (x *relIndex) notePath(kind, typ, path string) {
	x.paths[path] = true
	if kind == address.KindResource {
		x.pairs[[2]string{typ, path}] = true
	}
}

// reference records the reference of instance from to instance to.
func (x *relIndex) reference(from string, fromBlock *model.Block, to string, ref model.Ref) {
	path := strings.Join(ref.Path, ".")
	x.paths[path] = true
	source := x.entry(from)
	target := x.entry(to)
	targets := source.targets.list(path)
	referrers := target.referrers.list(path)
	var via *idList
	if read := cmp.Or(ref.Read, ref.Attr); read != "" {
		via = source.targets.list(ViaKey(path, read))
		x.viaPaths[ViaKey(path, read)] = true
	}
	var related *idList
	if fromBlock.Kind == address.KindResource {
		x.pairs[[2]string{fromBlock.Type, path}] = true
		related = target.relatedList(fromBlock.Type, path)
	}
	if !ref.Certain {
		targets.ph, referrers.ph = true, true
		if via != nil {
			via.ph = true
		}
		if related != nil {
			related.ph = true
		}
		return
	}
	targets.add(to)
	if via != nil {
		via.add(to)
	}
	referrers.addLast(from)
	if related != nil {
		related.addLast(from)
	}
}

// literals records the literals a companion writes and the target values a
// block exposes, for the types and paths of literal_keys.
func (x *relIndex) literals(root string, b *model.Block, inst *model.Instance, id string) {
	if b.Kind != address.KindResource {
		return
	}
	x.writtenLiterals(root, b, inst, id)
	for _, attr := range x.targetAttrs[b.Type] {
		if slices.Contains(b.Nonliteral, attr) {
			continue
		}
		steps := strings.Split(attr, ".")
		v, ok := targetValue(inst, steps[0])
		if !ok {
			continue
		}
		for _, s := range stringsAt(v, steps[1:], nil) {
			byAttr := nested(x.values, root, b.Type)
			byValue := byAttr[attr]
			if byValue == nil {
				byValue = map[string][]string{}
				byAttr[attr] = byValue
			}
			if !slices.Contains(byValue[s], id) {
				byValue[s] = append(byValue[s], id)
			}
		}
		if unknownAt(v, steps[1:]) {
			nestedBool(x.unknown, root, b.Type)[attr] = true
		}
	}
}

// writtenLiterals records the strings a companion writes at the paths of
// literal_keys.
func (x *relIndex) writtenLiterals(root string, b *model.Block, inst *model.Instance, id string) {
	paths, ok := x.keys[b.Type]
	if !ok {
		return
	}
	certain := !b.KeyUnknown && !b.Overridable && !b.Duplicate
	for _, path := range sortedKeys(paths) {
		for _, s := range writtenStrings(b, inst, path) {
			byPath := nested(x.companions, root, b.Type)
			byValue := byPath[path]
			if byValue == nil {
				byValue = map[string][]companion{}
				byPath[path] = byValue
			}
			if !slices.ContainsFunc(byValue[s], func(c companion) bool { return c.id == id }) {
				byValue[s] = append(byValue[s], companion{id: id, certain: certain})
			}
		}
	}
}

func nested[V any](m map[string]map[string]map[string]V, root, typ string) map[string]V {
	byType, ok := m[root]
	if !ok {
		byType = map[string]map[string]V{}
		m[root] = byType
	}
	byPath, ok := byType[typ]
	if !ok {
		byPath = map[string]V{}
		byType[typ] = byPath
	}
	return byPath
}

func nestedBool(m map[string]map[string]map[string]bool, root, typ string) map[string]bool {
	return nested(m, root, typ)
}

// targetValue is the value a literal can name at attribute name of inst: the
// written one, else the planned one the configuration does not write.
func targetValue(inst *model.Instance, name string) (cty.Value, bool) {
	if v, ok := inst.Attrs[name]; ok {
		return v, true
	}
	v, ok := inst.Computed[name]
	return v, ok
}

// writtenStrings returns the known strings inst writes at the dot-joined path,
// none when the path derives from path.* or terraform.*. A certain reference
// names its block directly, so its value is not a literal.
func writtenStrings(b *model.Block, inst *model.Instance, path string) []string {
	if slices.Contains(b.Nonliteral, path) {
		return nil
	}
	steps := strings.Split(path, ".")
	v, ok := inst.Attrs[steps[0]]
	if !ok {
		return nil
	}
	return dropCertainRefs(inst, path, stringsAt(v, steps[1:], nil))
}

// dropCertainRefs removes values a certain reference at path already names.
func dropCertainRefs(inst *model.Instance, path string, values []string) []string {
	if len(values) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, ref := range inst.Refs {
		if !ref.Certain || strings.Join(ref.Path, ".") != path {
			continue
		}
		for _, s := range refStrings(ref) {
			counts[s]++
		}
	}
	if len(counts) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, s := range values {
		if counts[s] > 0 {
			counts[s]--
			continue
		}
		out = append(out, s)
	}
	return out
}

// refStrings is the known strings a reference reads from its target attribute.
func refStrings(ref model.Ref) []string {
	if ref.To == nil || ref.Attr == "" {
		return nil
	}
	if v, ok := ref.To.Attrs[ref.Attr]; ok {
		return stringsAt(v, nil, nil)
	}
	if v, ok := ref.To.Computed[ref.Attr]; ok {
		return stringsAt(v, nil, nil)
	}
	return nil
}

// unknownAt reports whether the value at the attribute names path in v is
// unknown, through list elements at any depth.
func unknownAt(v cty.Value, path []string) bool {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() {
		return len(path) == 0
	}
	if v.IsNull() {
		return false
	}
	ty := v.Type()
	switch {
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			if unknownAt(e, path) {
				return true
			}
		}
	case len(path) == 0:
	case ty.IsObjectType() && ty.HasAttribute(path[0]):
		return unknownAt(v.GetAttr(path[0]), path[1:])
	case ty.IsMapType():
		if k := cty.StringVal(path[0]); v.HasIndex(k).True() {
			return unknownAt(v.Index(k), path[1:])
		}
	}
	return false
}

// sameScope reports whether a literal that names a block of type named
// reaches the block other: the type is global, both use the same resolved
// provider configuration, or both use one implicit default.
func sameScope(named, other *Located) bool {
	if globalLiteralTypes[named.Type] {
		return true
	}
	if named.provider != other.provider {
		return false
	}
	if named.provider != "" {
		return true
	}
	return sameImplicitDefault(named, other)
}

// sameImplicitDefault reports whether both blocks name no provider alias.
// An unresolved alias is a different scope from the implicit default.
func sameImplicitDefault(a, b *Located) bool {
	ap, aok := writtenProvider(a)
	bp, bok := writtenProvider(b)
	return aok && bok && ap == bp && !strings.Contains(ap, ".")
}

func writtenProvider(loc *Located) (string, bool) {
	if loc == nil || loc.Block == nil {
		return "", false
	}
	return loc.Block.Provider, true
}

// resolve adds the literal matches once every block is indexed.
func (p *projector) resolve() {
	for _, id := range p.order {
		loc := p.located[id]
		if loc.Kind != address.KindResource {
			continue
		}
		p.literalCompanions(loc, id)
		p.literalTargets(loc, id)
	}
}

// literalCompanions adds to the relations of target the companions that name
// it by a written literal.
func (p *projector) literalCompanions(target *Located, id string) {
	x := p.rel
	for _, rel := range x.byTarget[target.Type] {
		byValue := x.companions[target.Root][rel.companion][rel.path]
		if len(byValue) == 0 && p.opts.Cross.Empty() {
			continue
		}
		unknown := false
		for _, attr := range rel.attrs {
			if u := p.literalCompanionAttr(target, rel, id, byValue, attr); u {
				unknown = true
			}
		}
		if unknown {
			e := x.entry(id)
			e.relatedList(rel.companion, rel.path).ph = true
			e.referrers.list(rel.path).ph = true
		}
	}
}

func (p *projector) literalCompanionAttr(
	target *Located, rel literalRel, id string, byValue map[string][]companion, attr string,
) bool {
	steps := strings.Split(attr, ".")
	v, ok := targetValue(target.inst, steps[0])
	if !ok || slices.Contains(target.Block.Nonliteral, attr) {
		return false
	}
	unknown := unknownAt(v, steps[1:])
	x := p.rel
	for _, s := range stringsAt(v, steps[1:], nil) {
		if !p.opts.Cross.Empty() {
			p.crossCompanions(target, rel, s, x.entry(id).relatedList(rel.companion, rel.path))
		}
		for _, c := range byValue[s] {
			other := p.located[c.id]
			if other != nil && !sameScope(target, other) {
				continue
			}
			e := x.entry(id)
			related := e.relatedList(rel.companion, rel.path)
			referrers := e.referrers.list(rel.path)
			if !c.certain || other == nil {
				related.ph, referrers.ph = true, true
				continue
			}
			related.add(c.id)
			referrers.add(c.id)
		}
	}
	return unknown
}

// literalTargets adds to the targets of source the blocks of its root that its
// written literals name.
func (p *projector) literalTargets(source *Located, id string) {
	x := p.rel
	paths, ok := x.keys[source.Type]
	if !ok {
		return
	}
	for _, path := range sortedKeys(paths) {
		literals := writtenStrings(source.Block, source.inst, path)
		if len(literals) == 0 {
			continue
		}
		list := x.entry(id).targets.list(path)
		for _, targetType := range sortedKeys(paths[path]) {
			for _, attr := range paths[path][targetType] {
				if x.unknown[source.Root][targetType][attr] {
					list.ph = true
				}
				byValue := x.values[source.Root][targetType][attr]
				for _, s := range literals {
					matched := false
					for _, tid := range byValue[s] {
						target := p.located[tid]
						if target == nil {
							list.ph = true
							continue
						}
						if !sameScope(target, source) {
							continue
						}
						list.add(tid)
						matched = true
					}
					if !matched {
						// The literal may name a block in another account.
						list.ph = true
					}
				}
			}
		}
	}
}

// RootIncompleteness describes a root whose relations an unresolved module
// call makes incomplete only for the blocks the call may reach.
type RootIncompleteness struct {
	Root string
	// Unresolved is the number of module calls that did not resolve.
	Unresolved int
	// Exposed is the number of block instances, the calls excluded, whose
	// relations are incomplete because an argument of a call reaches them.
	Exposed int
	// Blocks is the number of block instances of the root.
	Blocks int
}

// exposeScoped marks the instances of the roots with unresolved module calls
// that a call may reach: the ones its arguments reference and the ones that
// hold a string its arguments carry.
func (p *projector) exposeScoped() {
	x := p.rel
	for _, root := range sortedKeys(x.scoped) {
		r := x.scoped[root]
		ids := map[string]bool{}
		for inst := range r.Exposed {
			if id, ok := p.ids[inst]; ok {
				ids[id] = true
			}
		}
		for _, byAttr := range x.values[root] {
			for _, byValue := range byAttr {
				for s, named := range byValue {
					if !r.ExposedStrings[s] {
						continue
					}
					for _, id := range named {
						ids[id] = true
					}
				}
			}
		}
		info := RootIncompleteness{Root: root, Unresolved: len(r.Unresolved)}
		for _, inst := range r.Unresolved {
			delete(ids, p.ids[inst])
		}
		info.Exposed = len(ids)
		for _, inst := range r.Unresolved {
			ids[p.ids[inst]] = true
		}
		for id := range ids {
			x.exposed[id] = true
		}
		for _, id := range p.order {
			if p.located[id].Root == root {
				info.Blocks++
			}
		}
		x.incompleteness = append(x.incompleteness, info)
	}
}

type defaultsKey struct {
	root       string
	incomplete bool
}

// relationTerms builds the three indexes.
func (p *projector) relationTerms() (related, targets, referrers *ast.Term) {
	x := p.rel
	p.exposeScoped()
	defaults := map[defaultsKey]*rootDefaults{}
	defaultsOf := func(root string, incomplete bool) *rootDefaults {
		k := defaultsKey{root, incomplete}
		d, ok := defaults[k]
		if !ok {
			d = p.defaults(root, incomplete)
			defaults[k] = d
		}
		return d
	}
	relatedItems := make([][2]*ast.Term, 0, len(p.order))
	targetItems := make([][2]*ast.Term, 0, len(p.order))
	referrerItems := make([][2]*ast.Term, 0, len(p.order))
	for _, id := range p.order {
		loc := p.located[id]
		d := defaultsOf(loc.Root, x.incomplete[loc.Root])
		// A block an unresolved call may reach answers related and referrers
		// like a block of an incomplete root. What a block refers to does not
		// depend on a call that cannot read it.
		dx := d
		if x.exposed[id] {
			dx = defaultsOf(loc.Root, true)
		}
		e := x.entries[id]
		if e == nil {
			e = &relEntry{}
		}
		loc.RelPlaceholder = dx.incomplete
		if t := p.relatedTerm(loc, e, dx); t != nil {
			relatedItems = append(relatedItems, ast.Item(p.key(id), t))
		}
		if t := p.pathTerm(loc, e.targets, d.targetPaths(), d.targetTerm(p)); t != nil {
			targetItems = append(targetItems, ast.Item(p.key(id), t))
		}
		if t := p.pathTerm(loc, e.referrers, dx.referrers, dx.referrersTerm(p)); t != nil {
			referrerItems = append(referrerItems, ast.Item(p.key(id), t))
		}
	}
	return ast.ObjectTerm(relatedItems...), ast.ObjectTerm(targetItems...), ast.ObjectTerm(referrerItems...)
}

// rootDefaults are the answers a root gives, for blocks with no list of
// their own, with the placeholder: for related and referrers the paths where a
// block of the root holds an untraced value, and, for an incomplete root,
// every path seen in the evaluation.
type rootDefaults struct {
	incomplete bool
	// related: type -> path.
	related   map[string]map[string]bool
	referrers map[string]bool
	allPaths  map[string]bool
	// allTargetPaths adds the attribute-qualified paths to allPaths.
	allTargetPaths map[string]bool

	relatedT   *ast.Term
	referrersT *ast.Term
	targetsT   *ast.Term
}

// targetPaths are the paths a block of the root answers with the placeholder
// whatever it holds: its own untraced paths are marked on its entry.
func (d *rootDefaults) targetPaths() map[string]bool {
	if d.incomplete {
		return d.allTargetPaths
	}
	return nil
}

func (d *rootDefaults) referrersTerm(p *projector) *ast.Term {
	if d.referrersT == nil {
		d.referrersT = p.placeholderPaths(d.referrers)
	}
	return d.referrersT
}

func (d *rootDefaults) targetTerm(p *projector) *ast.Term {
	if d.targetsT == nil {
		d.targetsT = p.placeholderPaths(d.targetPaths())
	}
	return d.targetsT
}

func (p *projector) defaults(root string, incomplete bool) *rootDefaults {
	x := p.rel
	d := &rootDefaults{
		incomplete: incomplete,
		related:    map[string]map[string]bool{},
		referrers:  map[string]bool{},
	}
	for kind, byType := range x.untargeted[root] {
		for typ, paths := range byType {
			for path := range paths {
				d.referrers[path] = true
				if kind == address.KindResource {
					addTo(d.related, typ, path)
				}
			}
		}
	}
	if d.incomplete {
		d.allPaths = x.paths
		if x.allVia == nil {
			x.allVia = maps.Clone(x.paths)
			maps.Copy(x.allVia, x.viaPaths)
		}
		d.allTargetPaths = x.allVia
		for path := range x.paths {
			d.referrers[path] = true
		}
		for pair := range x.pairs {
			addTo(d.related, pair[0], pair[1])
		}
	}
	return d
}

func addTo[K comparable](m map[K]map[string]bool, key K, path string) {
	if m[key] == nil {
		m[key] = map[string]bool{}
	}
	m[key][path] = true
}

// placeholderPaths is {path: [placeholder]}.
func (p *projector) placeholderPaths(paths map[string]bool) *ast.Term {
	items := make([][2]*ast.Term, 0, len(paths))
	for _, path := range sortedKeys(paths) {
		items = append(items, ast.Item(p.key(path), p.placeholderList))
	}
	return ast.ObjectTerm(items...)
}

// pathTerm is {path: [ids...]} of a block: its own lists, plus the
// placeholder at every default path. Nil when the block has no list. shared
// is the term of a block with no list of its own.
func (p *projector) pathTerm(loc *Located, own pathLists, defaults map[string]bool, shared *ast.Term) *ast.Term {
	if len(own) == 0 {
		if len(defaults) == 0 {
			return nil
		}
		loc.RelPlaceholder = true
		return shared
	}
	items := make([][2]*ast.Term, 0, len(own)+len(defaults))
	for _, path := range sortedKeys(own) {
		l := own[path]
		l.ph = l.ph || defaults[path]
		items = append(items, ast.Item(p.key(path), p.listTerm(l, loc)))
	}
	for _, path := range sortedKeys(defaults) {
		if _, ok := own[path]; !ok {
			loc.RelPlaceholder = true
			items = append(items, ast.Item(p.key(path), p.placeholderList))
		}
	}
	return ast.ObjectTerm(items...)
}

func (p *projector) relatedTerm(loc *Located, e *relEntry, d *rootDefaults) *ast.Term {
	if len(e.related) == 0 {
		if len(d.related) == 0 {
			return nil
		}
		loc.RelPlaceholder = true
		if d.relatedT == nil {
			items := make([][2]*ast.Term, 0, len(d.related))
			for _, typ := range sortedKeys(d.related) {
				items = append(items, ast.Item(p.key(typ), p.placeholderPaths(d.related[typ])))
			}
			d.relatedT = ast.ObjectTerm(items...)
		}
		return d.relatedT
	}
	types := map[string]bool{}
	for typ := range e.related {
		types[typ] = true
	}
	for typ := range d.related {
		types[typ] = true
	}
	items := make([][2]*ast.Term, 0, len(types))
	for _, typ := range sortedKeys(types) {
		lists := e.related[typ]
		for path := range d.related[typ] {
			lists.list(path).ph = true
		}
		paths := make([][2]*ast.Term, 0, len(lists))
		for _, path := range sortedKeys(lists) {
			paths = append(paths, ast.Item(p.key(path), p.listTerm(lists[path], loc)))
		}
		items = append(items, ast.Item(p.key(typ), ast.ObjectTerm(paths...)))
	}
	return ast.ObjectTerm(items...)
}

func (p *projector) listTerm(l *idList, loc *Located) *ast.Term {
	if l.ph {
		loc.RelPlaceholder = true
	}
	for _, id := range l.ids {
		if other := p.located[id]; other != nil && other.Placeholder {
			loc.RelPlaceholder = true
		}
	}
	if len(l.ids) == 0 && l.ph {
		return p.placeholderList
	}
	terms := make([]*ast.Term, 0, len(l.ids)+1)
	for _, id := range l.ids {
		terms = append(terms, p.key(id))
	}
	if l.ph {
		terms = append(terms, p.t.placeholder)
	}
	return ast.ArrayTerm(terms...)
}
