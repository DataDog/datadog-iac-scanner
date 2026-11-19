/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package schedule

import (
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// maxExpand bounds the number of constants a step or a folded builtin call
// may expand to before the value becomes unknown.
const maxExpand = 64

// absVal over-approximates the values a term may take: a finite set of
// constants, input paths not yet read, collections whose keys and elements
// are themselves abstract, or anything (top).
type absVal struct {
	consts []*ast.Term
	paths  []inputPath
	colls  []*coll
	top    bool
}

// inputPath is a path under input. A nil step is a key that is not a
// constant.
type inputPath []*ast.Term

type coll struct {
	keys, elems absVal
}

var topVal = absVal{top: true}

func constVal(terms ...*ast.Term) absVal {
	return absVal{consts: dedupTerms(terms)}
}

func pathVal(p inputPath) absVal {
	return absVal{paths: []inputPath{p}}
}

// nolint:gocritic
func collVal(keys, elems absVal) absVal {
	return absVal{colls: []*coll{{keys: keys, elems: elems}}}
}

// nolint:gocritic
func (a absVal) isEmpty() bool {
	return !a.top && len(a.consts) == 0 && len(a.paths) == 0 && len(a.colls) == 0
}

// onlyConsts reports whether a is a non-empty finite set of constants.
// nolint:gocritic
func (a absVal) onlyConsts() bool {
	return !a.top && len(a.paths) == 0 && len(a.colls) == 0 && len(a.consts) > 0
}

func union(vals ...absVal) absVal {
	var out absVal
	var consts []*ast.Term
	seenPath := map[string]bool{}
	for _, v := range vals {
		out.top = out.top || v.top
		consts = append(consts, v.consts...)
		for _, p := range v.paths {
			if k := p.String(); !seenPath[k] {
				seenPath[k] = true
				out.paths = append(out.paths, p)
			}
		}
		out.colls = append(out.colls, v.colls...)
	}
	out.consts = dedupTerms(consts)
	return out
}

func dedupTerms(terms []*ast.Term) []*ast.Term {
	if len(terms) < 2 {
		return terms
	}
	sorted := ast.NewSet(terms...).Sorted()
	out := make([]*ast.Term, sorted.Len())
	for i := range out {
		out[i] = sorted.Elem(i)
	}
	return out
}

func (p inputPath) String() string {
	var b strings.Builder
	b.WriteString("input")
	for _, s := range p {
		if s == nil {
			b.WriteString("[?]")
			continue
		}
		if str, ok := s.Value.(ast.String); ok && ast.IsVarCompatibleString(string(str)) {
			b.WriteString(".")
			b.WriteString(string(str))
			continue
		}
		b.WriteString("[")
		b.WriteString(s.String())
		b.WriteString("]")
	}
	return b.String()
}

func (p inputPath) extend(step *ast.Term) inputPath {
	out := make(inputPath, len(p), len(p)+1)
	copy(out, p)
	return append(out, step)
}

// key is a canonical text of a, used to memoise summaries by argument.
// nolint:gocritic
func (a absVal) key() string {
	var b strings.Builder
	a.writeKey(&b)
	return b.String()
}

// nolint:gocritic
func (a absVal) writeKey(b *strings.Builder) {
	b.WriteString("{")
	if a.top {
		b.WriteString("T;")
	} else {
		for _, c := range a.consts {
			b.WriteString(c.String())
			b.WriteString(";")
		}
	}
	paths := make([]string, len(a.paths))
	for i, p := range a.paths {
		paths[i] = p.String()
	}
	sort.Strings(paths)
	for _, p := range paths {
		b.WriteString("P")
		b.WriteString(p)
		b.WriteString(";")
	}
	colls := make([]string, len(a.colls))
	for i, c := range a.colls {
		var cb strings.Builder
		cb.WriteString("C(")
		c.keys.writeKey(&cb)
		cb.WriteString(":")
		c.elems.writeKey(&cb)
		cb.WriteString(")")
		colls[i] = cb.String()
	}
	sort.Strings(colls)
	for _, c := range colls {
		b.WriteString(c)
	}
	b.WriteString("}")
}

// constKeysAndElems lists the keys and elements of a constant collection.
func constKeysAndElems(t *ast.Term) (keys, elems []*ast.Term) {
	switch v := t.Value.(type) {
	case *ast.Array:
		for i := range v.Len() {
			keys = append(keys, ast.InternedTerm(i))
			elems = append(elems, v.Elem(i))
		}
	case ast.Set:
		v.Foreach(func(e *ast.Term) {
			keys = append(keys, e)
			elems = append(elems, e)
		})
	case ast.Object:
		v.Foreach(func(k, e *ast.Term) {
			keys = append(keys, k)
			elems = append(elems, e)
		})
	}
	return keys, elems
}

// lookupConst returns the element of a constant collection at a constant key.
func lookupConst(t, key *ast.Term) (*ast.Term, bool) {
	switch v := t.Value.(type) {
	case *ast.Array:
		n, ok := key.Value.(ast.Number)
		if !ok {
			return nil, false
		}
		i, ok := n.Int()
		if !ok || i < 0 || i >= v.Len() {
			return nil, false
		}
		return v.Elem(i), true
	case ast.Set:
		if v.Contains(key) {
			return key, true
		}
	case ast.Object:
		if e := v.Get(key); e != nil {
			return e, true
		}
	}
	return nil, false
}

// collectPaths returns every input path held in a, including inside
// collections.
// nolint:gocritic
func (a absVal) collectPaths(out []inputPath) []inputPath {
	out = append(out, a.paths...)
	for _, c := range a.colls {
		out = c.keys.collectPaths(out)
		out = c.elems.collectPaths(out)
	}
	return out
}
