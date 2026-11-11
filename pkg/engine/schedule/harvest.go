/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package schedule

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Options configures a Harvester.
type Options struct {
	// LibraryPrefixes are the packages allowed to read input. A rule reading
	// input anywhere else always runs. Defaults to data.generic.
	LibraryPrefixes []ast.Ref
}

// Harvester analyses rules compiled together with their libraries. Library
// summaries are shared between the rules it harvests. It is not safe for
// concurrent use.
type Harvester struct {
	c    *ast.Compiler
	libs []ast.Ref
	memo map[string]*summary
}

// NewHarvester returns a harvester over a compiled set of modules.
func NewHarvester(c *ast.Compiler, opts Options) *Harvester {
	libs := opts.LibraryPrefixes
	if len(libs) == 0 {
		libs = []ast.Ref{ast.MustParseRef("data.generic")}
	}
	return &Harvester{c: c, libs: libs, memo: map[string]*summary{}}
}

type summary struct {
	val  absVal
	eff  *effects
	busy bool
}

type effects struct {
	types     map[TypeKey]struct{}
	dynamic   map[string]struct{}
	relations bool
	// nested is set by a block read that is not a generator of the body
	// being harvested; nestedWhy says where.
	nested     bool
	nestedWhy  string
	generators int
	// genHit records that the iteration being evaluated is a generator.
	genHit bool
}

func newEffects() *effects {
	return &effects{types: map[TypeKey]struct{}{}, dynamic: map[string]struct{}{}}
}

func (e *effects) mergeCallee(o *effects, callee string) {
	for k := range o.types {
		e.types[k] = struct{}{}
	}
	for r := range o.dynamic {
		e.dynamic[r] = struct{}{}
	}
	e.relations = e.relations || o.relations
	if (len(o.types) > 0 || o.nested) && !e.nested {
		e.nested = true
		e.nestedWhy = "reads blocks through " + callee
	}
}

// Relation indexes of input._dd and the position of the key naming a block,
// a root or a literal value. Enumerating keys up to that position, or
// reading it at a constant key, would let a rule reach blocks it did not get
// from a harvested type.
var relationAnchor = map[string]int{
	"related":   2,
	"referrers": 2,
	"targets":   2,
	"by_id":     2,
}

type accessMode int

const (
	modeDefined accessMode = iota
	modeConsume
	modeIter
)

type frame struct {
	h     *Harvester
	env   map[ast.Var]absVal
	eff   *effects
	top   bool
	lib   bool
	where string
	row   int
}

func (h *Harvester) newFrame(r *ast.Rule, eff *effects, top bool) *frame {
	f := &frame{h: h, env: map[ast.Var]absVal{}, eff: eff, top: top}
	if r.Module != nil {
		for _, prefix := range h.libs {
			if r.Module.Package.Path.HasPrefix(prefix) {
				f.lib = true
			}
		}
	}
	f.where = r.Ref().String()
	if r.Module != nil {
		f.where = r.Module.Package.Path.Extend(r.Head.Ref().GroundPrefix()).String()
	}
	if r.Location != nil {
		f.row = r.Location.Row
	}
	return f
}

func (f *frame) child() *frame {
	env := make(map[ast.Var]absVal, len(f.env))
	for k, v := range f.env {
		env[k] = v
	}
	return &frame{h: f.h, env: env, eff: f.eff, lib: f.lib, where: f.where, row: f.row}
}

func (f *frame) dynf(format string, args ...any) {
	f.eff.dynamic[fmt.Sprintf("%s:%d: %s", f.where, f.row, fmt.Sprintf(format, args...))] = struct{}{}
}

// Harvest analyses the rule at path, for example data.datadog.DatadogPolicy.
func (h *Harvester) Harvest(path ast.Ref) Rule {
	out := Rule{ID: path.String()}
	rules := h.c.GetRulesExact(path)
	if len(rules) == 0 {
		out.AlwaysRun = true
		out.Reasons = []string{"no rule is defined at " + path.String()}
		out.ClassReason = out.Reasons[0]
		return out
	}
	types := map[TypeKey]struct{}{}
	dynamic := map[string]struct{}{}
	out.Class = Anchored
	for _, r := range rules {
		eff := newEffects()
		f := h.newFrame(r, eff, true)
		f.evalBody(r.Body)
		f.top = false
		f.consume(f.docValue(r))
		for k := range eff.types {
			types[k] = struct{}{}
		}
		for d := range eff.dynamic {
			dynamic[d] = struct{}{}
		}
		if len(eff.types) == 0 && len(eff.dynamic) == 0 {
			dynamic[fmt.Sprintf("%s:%d: a body reads no block", f.where, f.row)] = struct{}{}
		}
		out.Relations = out.Relations || eff.relations
		if why := bodyClassReason(eff); why != "" && out.Class == Anchored {
			out.Class = Relational
			out.ClassReason = fmt.Sprintf("%s:%d: %s", f.where, f.row, why)
		}
	}
	out.Types = sortTypes(types)
	out.Reasons = sortStrings(dynamic)
	if len(out.Reasons) > 0 {
		out.AlwaysRun = true
		if out.Class == Anchored {
			out.Class = Relational
			out.ClassReason = reasonAlwaysRuns
		}
	}
	return out
}

const reasonAlwaysRuns = "always runs"

func bodyClassReason(eff *effects) string {
	switch {
	case len(eff.dynamic) > 0:
		return reasonAlwaysRuns
	case eff.relations:
		return "reads relations"
	case eff.nested:
		return eff.nestedWhy
	case eff.generators == 0:
		return "has no block generator"
	case eff.generators > 1:
		return fmt.Sprintf("joins %d block generators", eff.generators)
	}
	return ""
}

func (f *frame) evalBody(body ast.Body) {
	for _, e := range body {
		f.evalExpr(e)
	}
}

func (f *frame) evalExpr(e *ast.Expr) {
	if e.Location != nil {
		f.row = e.Location.Row
	}
	if len(e.With) > 0 {
		f.dynf("uses a with modifier")
	}
	if e.Negated {
		f.child().evalExprTerms(e)
		return
	}
	f.evalExprTerms(e)
}

func (f *frame) evalExprTerms(e *ast.Expr) {
	switch t := e.Terms.(type) {
	case *ast.Term:
		f.consume(f.evalTerm(t))
	case []*ast.Term:
		f.evalCall(t[0], t[1:], true)
	case *ast.Every:
		c := f.child()
		keys, elems := c.iterate(c.evalTerm(t.Domain))
		if t.Key != nil {
			c.destructure(t.Key, keys)
		}
		c.destructure(t.Value, elems)
		c.evalBody(t.Body)
	case *ast.SomeDecl:
		for _, s := range t.Symbols {
			if call, ok := s.Value.(ast.Call); ok {
				f.evalCall(call[0], call[1:], true)
			}
		}
	}
}

// evalCall evaluates a call. As an expression (asExpr), a trailing output
// argument is bound and a missing one makes the result a truth test.
// nolint:gocyclo
func (f *frame) evalCall(op *ast.Term, args []*ast.Term, asExpr bool) absVal {
	ref, ok := op.Value.(ast.Ref)
	if !ok {
		f.dynf("calls %v", op)
		return topVal
	}
	name := ref.String()
	switch name {
	case ast.Equality.Name, ast.Assign.Name:
		f.unify(args[0], args[1])
		return constVal(ast.BooleanTerm(true))
	case ast.Member.Name:
		xs := f.evalTerm(args[1])
		if !f.isPattern(args[0]) {
			f.consume(xs)
			f.consume(f.evalTerm(args[0]))
			return topVal
		}
		_, elems := f.iterate(xs)
		f.destructure(args[0], elems)
		return constVal(ast.BooleanTerm(true))
	case ast.MemberWithKey.Name:
		xs := f.evalTerm(args[2])
		if !f.isPattern(args[0]) && !f.isPattern(args[1]) {
			f.consume(xs)
			f.consume(f.evalTerm(args[0]))
			f.consume(f.evalTerm(args[1]))
			return topVal
		}
		keys, elems := f.iterate(xs)
		f.destructure(args[0], keys)
		f.destructure(args[1], elems)
		return constVal(ast.BooleanTerm(true))
	}
	var in []*ast.Term
	var out *ast.Term
	var result absVal
	if ref.HasPrefix(ast.DefaultRootRef) {
		if !f.lib && f.h.isPrivateLibrary(ref) {
			f.dynf("calls private library function %s", name)
		}
		rules := f.h.c.GetRulesExact(ref)
		if len(rules) == 0 {
			f.dynf("calls %s, which has no definition", name)
			result = topVal
		} else {
			n := len(rules[0].Head.Args)
			in = args
			if len(args) == n+1 {
				in, out = args[:n], args[n]
			}
			vals := make([]absVal, len(in))
			for i, a := range in {
				vals[i] = f.evalTerm(a)
			}
			s := f.h.summarize(ref, rules, vals)
			f.eff.mergeCallee(s.eff, name)
			result = s.val
		}
	} else {
		in, out = f.splitBuiltinArgs(name, args)
		result = f.builtin(name, in)
	}
	if !asExpr {
		return result
	}
	if out != nil {
		f.destructure(out, result)
	} else {
		f.consume(result)
	}
	return result
}

// isPrivateLibrary reports whether ref names a library rule or function
// whose name starts with an underscore.
func (h *Harvester) isPrivateLibrary(ref ast.Ref) bool {
	for _, prefix := range h.libs {
		if !ref.HasPrefix(prefix) {
			continue
		}
		for _, t := range ref[len(prefix):] {
			if s, ok := t.Value.(ast.String); ok && strings.HasPrefix(string(s), "_") {
				return true
			}
		}
	}
	return false
}

func (f *frame) splitBuiltinArgs(name string, args []*ast.Term) (in []*ast.Term, out *ast.Term) {
	bi := ast.BuiltinMap[name]
	if bi == nil || bi.Decl == nil {
		return args, nil
	}
	fa := bi.Decl.FuncArgs()
	if fa.Variadic != nil {
		return args, nil
	}
	if n := len(fa.Args); len(args) > n {
		return args[:n], args[n]
	}
	return args, nil
}

// summarize returns the value and effects of a rule or function for the given
// abstract arguments.
func (h *Harvester) summarize(ref ast.Ref, rules []*ast.Rule, args []absVal) *summary {
	var key strings.Builder
	key.WriteString(ref.String())
	for _, a := range args {
		key.WriteString("|")
		key.WriteString(a.key())
	}
	if s, ok := h.memo[key.String()]; ok {
		if s.busy {
			eff := newEffects()
			eff.dynamic[ref.String()+": recursive reference"] = struct{}{}
			return &summary{val: topVal, eff: eff}
		}
		return s
	}
	s := &summary{eff: newEffects(), busy: true}
	h.memo[key.String()] = s
	var vals []absVal
	for _, r := range rules {
		for alt := r; alt != nil; alt = alt.Else {
			f := h.newFrame(r, s.eff, false)
			if alt.Location != nil {
				f.row = alt.Location.Row
			}
			params := alt.Head.Args
			if len(params) == 0 {
				params = r.Head.Args
			}
			for i, p := range params {
				if i < len(args) {
					f.destructure(p, args[i])
				}
			}
			f.evalBody(alt.Body)
			vals = append(vals, f.docValue(alt))
		}
	}
	s.val = union(vals...)
	s.busy = false
	return s
}

// docValue is the document a rule definition contributes, wrapped in the
// non-ground part of its head reference.
func (f *frame) docValue(r *ast.Rule) absVal {
	var leaf absVal
	switch {
	case r.Head.RuleKind() == ast.MultiValue && r.Head.Key != nil:
		k := f.evalTerm(r.Head.Key)
		leaf = collVal(k, k)
	case r.Head.Value != nil:
		leaf = f.evalTerm(r.Head.Value)
	default:
		leaf = constVal(ast.BooleanTerm(true))
	}
	if len(r.Head.Args) > 0 {
		return leaf
	}
	ref := r.Head.Ref()
	tail := ref[len(ref.GroundPrefix()):]
	for i := len(tail) - 1; i >= 0; i-- {
		leaf = collVal(f.evalTerm(tail[i]), leaf)
	}
	return leaf
}

// nolint:gocyclo
func (f *frame) evalTerm(t *ast.Term) absVal {
	switch v := t.Value.(type) {
	case ast.Var:
		if val, ok := f.env[v]; ok {
			return val
		}
		if v.Equal(ast.InputRootDocument.Value) {
			return f.evalRef(ast.Ref{t})
		}
		if v.Equal(ast.DefaultRootDocument.Value) {
			f.dynf("reads the whole data document")
		}
		return topVal
	case ast.Ref:
		return f.evalRef(v)
	case ast.Call:
		return f.evalCall(v[0], v[1:], false)
	case *ast.ArrayComprehension:
		c := f.child()
		c.evalBody(v.Body)
		return collVal(topVal, c.evalTerm(v.Term))
	case *ast.SetComprehension:
		c := f.child()
		c.evalBody(v.Body)
		e := c.evalTerm(v.Term)
		return collVal(e, e)
	case *ast.ObjectComprehension:
		c := f.child()
		c.evalBody(v.Body)
		return collVal(c.evalTerm(v.Key), c.evalTerm(v.Value))
	}
	if t.IsGround() {
		return constVal(t)
	}
	switch v := t.Value.(type) {
	case *ast.Array:
		elems := make([]absVal, v.Len())
		for i := range v.Len() {
			elems[i] = f.evalTerm(v.Elem(i))
		}
		if terms, ok := product(elems, func(ts []*ast.Term) *ast.Term { return ast.ArrayTerm(ts...) }); ok {
			return constVal(terms...)
		}
		return collVal(topVal, union(elems...))
	case ast.Set:
		var elems []absVal
		v.Foreach(func(e *ast.Term) { elems = append(elems, f.evalTerm(e)) })
		u := union(elems...)
		return collVal(u, u)
	case ast.Object:
		var keys, vals []absVal
		v.Foreach(func(k, e *ast.Term) {
			keys = append(keys, f.evalTerm(k))
			vals = append(vals, f.evalTerm(e))
		})
		if v.Len() > 0 && allGround(v.Keys()) {
			if terms, ok := product(vals, func(ts []*ast.Term) *ast.Term {
				obj := ast.NewObject()
				for i, k := range v.Keys() {
					obj.Insert(k, ts[i])
				}
				return ast.NewTerm(obj)
			}); ok {
				return constVal(terms...)
			}
		}
		return collVal(union(keys...), union(vals...))
	}
	return topVal
}

func allGround(terms []*ast.Term) bool {
	for _, t := range terms {
		if !t.IsGround() {
			return false
		}
	}
	return true
}

// product combines constant alternatives, or fails when an operand is not a
// set of constants or the combinations exceed maxExpand.
func product(vals []absVal, build func([]*ast.Term) *ast.Term) ([]*ast.Term, bool) {
	n := 1
	for _, v := range vals {
		if !v.onlyConsts() {
			return nil, false
		}
		n *= len(v.consts)
		if n > maxExpand {
			return nil, false
		}
	}
	var out []*ast.Term
	cur := make([]*ast.Term, len(vals))
	var rec func(i int)
	rec = func(i int) {
		if i == len(vals) {
			out = append(out, build(append([]*ast.Term(nil), cur...)))
			return
		}
		for _, c := range vals[i].consts {
			cur[i] = c
			rec(i + 1)
		}
	}
	rec(0)
	return out, true
}

func (f *frame) evalRef(ref ast.Ref) absVal {
	head := ref[0]
	if v, ok := head.Value.(ast.Var); ok {
		if _, bound := f.env[v]; !bound {
			switch {
			case v.Equal(ast.InputRootDocument.Value):
				if !f.lib {
					f.dynf("reads input directly (%v)", ref)
				}
				return f.applySteps(pathVal(inputPath{}), ref[1:])
			case v.Equal(ast.DefaultRootDocument.Value):
				return f.evalDataRef(ref)
			}
		}
	}
	return f.applySteps(f.evalTerm(head), ref[1:])
}

// evalDataRef resolves a data reference to the rules producing it.
func (f *frame) evalDataRef(ref ast.Ref) absVal {
	node := f.h.c.RuleTree.Child(ref[0].Value)
	for i := 1; node != nil && i < len(ref); i++ {
		if !ref[i].IsGround() {
			if len(node.Children) > 0 {
				f.dynf("reads data at a key that is not a constant (%v)", ref)
			}
			return f.applySteps(topVal, ref[i:])
		}
		node = node.Child(ref[i].Value)
		if node == nil {
			break
		}
		if len(node.Values) > 0 {
			if !f.lib && f.h.isPrivateLibrary(ref[:i+1]) {
				f.dynf("reads private library rule %v", ref[:i+1])
			}
			rules := make([]*ast.Rule, len(node.Values))
			for j, v := range node.Values {
				rules[j] = v.(*ast.Rule)
			}
			if len(rules[0].Head.Args) > 0 {
				f.dynf("references function %v without calling it", ref[:i+1])
				return topVal
			}
			s := f.h.summarize(ref[:i+1], rules, nil)
			f.eff.mergeCallee(s.eff, ref[:i+1].String())
			return f.applySteps(s.val, ref[i+1:])
		}
		if i == len(ref)-1 && len(node.Children) > 0 {
			f.dynf("reads a whole package (%v)", ref)
		}
	}
	return f.applySteps(topVal, nil)
}

// applySteps follows reference steps. A step that is an unbound variable
// iterates.
// nolint:gocritic
func (f *frame) applySteps(cur absVal, steps []*ast.Term) absVal {
	for _, s := range steps {
		if f.isPattern(s) {
			keys, elems := f.iterate(cur)
			f.destructure(s, keys)
			cur = elems
			continue
		}
		cur = f.index(cur, f.evalTerm(s), true)
	}
	return cur
}

// index looks up one key. Through a reference (viaRef) the extended input
// paths are read for definedness.
// nolint:gocritic
func (f *frame) index(cur, k absVal, viaRef bool) absVal {
	f.consume(k)
	var out []absVal
	if cur.top {
		out = append(out, topVal)
	}
	for _, c := range cur.consts {
		if k.onlyConsts() {
			for _, key := range k.consts {
				if e, ok := lookupConst(c, key); ok {
					out = append(out, constVal(e))
				}
			}
			continue
		}
		if !k.isEmpty() {
			_, elems := constKeysAndElems(c)
			out = append(out, constVal(elems...))
		}
	}
	for _, c := range cur.colls {
		if !k.isEmpty() {
			out = append(out, c.elems)
		}
	}
	for _, p := range cur.paths {
		for _, s := range steps(k) {
			np := p.extend(s)
			if viaRef {
				f.access(np, modeDefined)
			}
			out = append(out, pathVal(np))
		}
	}
	return union(out...)
}

// nolint:gocritic
func steps(k absVal) []*ast.Term {
	if k.isEmpty() {
		return nil
	}
	if k.onlyConsts() && len(k.consts) <= maxExpand {
		return k.consts
	}
	return []*ast.Term{nil}
}

// anyDepth over-approximates object.get at a key that is not a constant and
// may be a path of any length. Into input, such a key names one entry: the
// library only passes block ids and roots there, and rules cannot reach those
// lookups because they may not call private library functions.
// nolint:gocritic
func (f *frame) anyDepth(cur absVal) absVal {
	if cur.top {
		return topVal
	}
	out := []absVal{{consts: cur.consts}}
	for _, c := range cur.consts {
		out = append(out, constVal(nestedValues(c, nil)...))
	}
	for _, c := range cur.colls {
		out = append(out, absVal{colls: []*coll{c}}, f.anyDepth(c.elems))
	}
	for _, p := range cur.paths {
		out = append(out, pathVal(p.extend(nil)))
	}
	return union(out...)
}

// nestedValues lists the values at any depth of a constant, without object
// keys.
func nestedValues(t *ast.Term, out []*ast.Term) []*ast.Term {
	_, elems := constKeysAndElems(t)
	for _, e := range elems {
		out = nestedValues(e, append(out, e))
	}
	return out
}

func (f *frame) objectGet(args []*ast.Term) absVal {
	obj := f.evalTerm(args[0])
	out := []absVal{f.evalTerm(args[2])}
	var seqs [][]absVal
	unknownDepth := false
	if arr, ok := args[1].Value.(*ast.Array); ok && !args[1].IsGround() {
		seq := make([]absVal, arr.Len())
		for i := range arr.Len() {
			seq[i] = f.evalTerm(arr.Elem(i))
		}
		seqs = append(seqs, seq)
	} else {
		k := f.evalTerm(args[1])
		f.consume(k)
		for _, c := range k.consts {
			if arr, ok := c.Value.(*ast.Array); ok {
				seq := make([]absVal, arr.Len())
				for i := range arr.Len() {
					seq[i] = constVal(arr.Elem(i))
				}
				seqs = append(seqs, seq)
			} else {
				seqs = append(seqs, []absVal{constVal(c)})
			}
		}
		unknownDepth = k.top || len(k.colls) > 0 || len(k.paths) > 0
	}
	for _, seq := range seqs {
		cur := obj
		for _, s := range seq {
			cur = f.index(cur, s, false)
		}
		out = append(out, cur)
	}
	if unknownDepth {
		out = append(out, f.anyDepth(obj))
	}
	return union(out...)
}

// nolint:gocritic
func (f *frame) iterate(v absVal) (keys, elems absVal) {
	var ks, es []absVal
	if v.top {
		ks, es = append(ks, topVal), append(es, topVal)
	}
	for _, c := range v.consts {
		k, e := constKeysAndElems(c)
		ks, es = append(ks, constVal(k...)), append(es, constVal(e...))
	}
	for _, c := range v.colls {
		ks, es = append(ks, c.keys), append(es, c.elems)
	}
	f.eff.genHit = false
	for _, p := range v.paths {
		f.access(p, modeIter)
		ks, es = append(ks, topVal), append(es, topVal)
	}
	if f.eff.genHit {
		f.eff.genHit = false
		f.eff.generators++
	}
	return union(ks...), union(es...)
}

// nolint:gocritic
func (f *frame) consume(v absVal) {
	for _, p := range v.collectPaths(nil) {
		f.access(p, modeConsume)
	}
}

// isPattern reports whether t binds variables when unified: an unbound
// variable, or an array or object holding one outside references and calls.
func (f *frame) isPattern(t *ast.Term) bool {
	switch v := t.Value.(type) {
	case ast.Var:
		_, bound := f.env[v]
		return !bound && !v.Equal(ast.InputRootDocument.Value) && !v.Equal(ast.DefaultRootDocument.Value)
	case *ast.Array:
		for i := range v.Len() {
			if f.isPattern(v.Elem(i)) {
				return true
			}
		}
	case ast.Object:
		found := false
		v.Foreach(func(_, e *ast.Term) { found = found || f.isPattern(e) })
		return found
	}
	return false
}

func (f *frame) unify(a, b *ast.Term) {
	switch {
	case f.isPattern(a):
		f.destructure(a, f.evalTerm(b))
		f.bindRemaining(b)
	case f.isPattern(b):
		f.destructure(b, f.evalTerm(a))
	default:
		f.consume(f.evalTerm(a))
		f.consume(f.evalTerm(b))
	}
}

func (f *frame) bindRemaining(t *ast.Term) {
	if !f.isPattern(t) {
		return
	}
	f.destructure(t, topVal)
}

// nolint:gocritic
func (f *frame) destructure(pattern *ast.Term, val absVal) {
	if !f.isPattern(pattern) {
		f.consume(val)
		f.consume(f.evalTerm(pattern))
		return
	}
	switch p := pattern.Value.(type) {
	case ast.Var:
		f.env[p] = val
	case *ast.Array:
		f.consume(absVal{paths: val.paths})
		for i := range p.Len() {
			f.destructure(p.Elem(i), elemAt(val, ast.InternedTerm(i), p.Len()))
		}
	case ast.Object:
		f.consume(absVal{paths: val.paths})
		p.Foreach(func(k, e *ast.Term) {
			f.destructure(e, elemAt(val, k, -1))
		})
	}
}

// nolint:gocritic
func elemAt(val absVal, key *ast.Term, arrayLen int) absVal {
	var out []absVal
	if val.top || len(val.paths) > 0 {
		out = append(out, topVal)
	}
	for _, c := range val.consts {
		if arr, ok := c.Value.(*ast.Array); ok && arrayLen >= 0 && arr.Len() != arrayLen {
			continue
		}
		if e, ok := lookupConst(c, key); ok {
			out = append(out, constVal(e))
		}
	}
	for _, c := range val.colls {
		out = append(out, c.elems)
	}
	return union(out...)
}

// access classifies a read of an input path.
// nolint:gocyclo
func (f *frame) access(p inputPath, mode accessMode) {
	name := func(i int) (string, bool) {
		if i >= len(p) || p[i] == nil {
			return "", false
		}
		s, ok := p[i].Value.(ast.String)
		return string(s), ok
	}
	if len(p) == 0 {
		if mode != modeDefined {
			f.dynf("reads the whole input")
		}
		return
	}
	root, ok := name(0)
	if !ok {
		f.dynf("reads %v", p)
		return
	}
	if root != "_dd" {
		f.dynf("reads input.%s", root)
		return
	}
	if len(p) == 1 {
		if mode != modeDefined {
			f.dynf("reads input._dd as a whole")
		}
		return
	}
	index, ok := name(1)
	if !ok {
		f.dynf("reads an input._dd index that is not a constant")
		return
	}
	switch anchor := relationAnchor[index]; {
	case index == "placeholder", index == "blocks_complete":
		// Metadata the library reads without naming blocks. Ignoring them
		// keeps a simple tf.blocks rule anchored; absence helpers that also
		// read blocks_complete stay typed instead of AlwaysRun.
	case index == "nested":
		// Nested block lists of a harvested block (tf.nested). Reading them
		// does not name other top-level types; keep the rule typed. Only
		// enumerating the whole index is unbounded.
		if len(p) == 2 && mode != modeDefined {
			f.dynf("reads the whole nested index")
		} else if mode == modeIter && len(p) == 2 {
			f.dynf("enumerates the nested index")
		}
	case anchor > 0:
		switch {
		case len(p) == 2 && mode != modeDefined:
			f.dynf("reads the whole %s index", index)
		case mode == modeIter && len(p) <= anchor:
			f.dynf("enumerates the %s index (%v)", index, p)
		case len(p) > anchor && p[anchor] != nil:
			f.dynf("reads the %s index at a constant key (%v)", index, p)
		default:
			f.eff.relations = true
		}
	case index == "blocks":
		f.blocksAccess(p, mode, name)
	default:
		f.dynf("reads input._dd.%s", index)
	}
}

func (f *frame) blocksAccess(p inputPath, mode accessMode, name func(int) (string, bool)) {
	if len(p) == 2 {
		if mode != modeDefined {
			f.dynf("reads every block kind")
		}
		return
	}
	if nonString(p[2]) {
		return
	}
	kind, ok := name(2)
	if !ok {
		f.dynf("reads blocks of a kind that is not a constant")
		return
	}
	if listKinds[kind] {
		f.typeRead(TypeKey{Kind: kind}, mode == modeIter && len(p) == 3)
		return
	}
	if !typedKinds[kind] {
		f.dynf("reads blocks of unknown kind %q", kind)
		return
	}
	if len(p) == 3 {
		if mode != modeDefined {
			f.dynf("reads every %s type", kind)
		}
		return
	}
	if nonString(p[3]) {
		return
	}
	typ, ok := name(3)
	if !ok {
		f.dynf("reads %s blocks of a type that is not a constant", kind)
		return
	}
	f.typeRead(TypeKey{Kind: kind, Type: typ}, mode == modeIter && len(p) == 4)
}

// nonString reports a constant key that is not a string: kinds and types are
// strings, so such a key never names blocks.
func nonString(step *ast.Term) bool {
	if step == nil {
		return false
	}
	_, ok := step.Value.(ast.String)
	return !ok
}

func (f *frame) typeRead(k TypeKey, generator bool) {
	f.eff.types[k] = struct{}{}
	if generator && f.top {
		f.eff.genHit = true
		return
	}
	if !f.eff.nested {
		f.eff.nested = true
		f.eff.nestedWhy = fmt.Sprintf("reads %s blocks other than as its generator", k)
	}
}
