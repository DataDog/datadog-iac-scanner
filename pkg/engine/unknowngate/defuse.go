package unknowngate

import (
	"strconv"

	"github.com/open-policy-agent/opa/v1/ast"
)

// flow is the static def-use analysis of the compiled rules. It is computed once, when the
// gate is built, and read concurrently afterwards.
type flow struct {
	// message[e]: the output of e flows only into the value of its rule: a function's value,
	// or a result field other than _dd_id, path and key.
	message map[*ast.Expr]bool
	// member[e]: e is `v = data...` and v is only used as the collection of membership tests.
	member map[*ast.Expr]ast.Ref
	// memberVar[rule][v]: the document a membership-only variable holds.
	memberVar map[*ast.Rule]map[ast.Var]ast.Ref
}

func (fl *flow) messageOnly(r *ast.Rule, kind ruleKind, e *ast.Expr) bool {
	if r == nil || kind == ruleVdoc {
		return false
	}
	return fl.message[e]
}

func (fl *flow) memberOnly(e *ast.Expr) bool {
	_, ok := fl.member[e]
	return ok
}

func (fl *flow) memberDoc(r *ast.Rule, v ast.Var) ast.Ref {
	if r == nil {
		return nil
	}
	return fl.memberVar[r][v]
}

const anyElem = "*"

type flowAnalyzer struct {
	rules *compiledRules
	// funcs caches, per function and argument position, the result paths an argument reaches.
	funcs    map[string][][]string
	funcsOK  map[string]bool
	visiting map[string]bool
}

func analyzeFlow(cr *compiledRules) *flow {
	a := &flowAnalyzer{rules: cr, funcs: map[string][][]string{}, funcsOK: map[string]bool{}, visiting: map[string]bool{}}
	fl := &flow{
		message:   map[*ast.Expr]bool{},
		member:    map[*ast.Expr]ast.Ref{},
		memberVar: map[*ast.Rule]map[ast.Var]ast.Ref{},
	}
	for r, meta := range cr.meta {
		for _, e := range r.Body {
			a.analyzeExpr(fl, r, meta.kind, e)
		}
	}
	return fl
}

// nolint:gocyclo
func (a *flowAnalyzer) analyzeExpr(fl *flow, r *ast.Rule, kind ruleKind, e *ast.Expr) {
	if v, doc, ok := docAssignment(e); ok && a.membershipOnly(r, v, e.Index) {
		fl.member[e] = doc
		if fl.memberVar[r] == nil {
			fl.memberVar[r] = map[ast.Var]ast.Ref{}
		}
		fl.memberVar[r][v] = doc
	}
	if kind == ruleVdoc || !e.IsCall() || e.Negated || len(e.With) > 0 {
		return
	}
	name := e.Operator().String()
	ops := e.Operands()
	var out *ast.Term
	switch {
	case msgBuiltins[name]:
		if n := builtinArity(name, len(ops)); len(ops) == n+1 {
			out = ops[n]
		}
	case e.Operator().HasPrefix(ast.DefaultRootRef):
		if n := a.rules.funcArity(e.Operator()); n >= 0 && len(ops) == n+1 {
			out = ops[n]
		}
	}
	if out == nil {
		return
	}
	v, ok := out.Value.(ast.Var)
	if !ok {
		return
	}
	paths, ok := a.flowPaths(r, kind, v, e.Index)
	if ok && sinkOK(kind, paths) {
		fl.message[e] = true
	}
}

// sinkOK reports whether every path is a message position for a rule of this kind.
func sinkOK(kind ruleKind, paths [][]string) bool {
	if kind == ruleFunc {
		return true
	}
	for _, p := range paths {
		if len(p) == 0 || p[0] == anyElem || p[0] == "" || isIdentityField(p[0]) {
			return false
		}
	}
	return true
}

// docAssignment matches `v = data.<ground ref>`.
func docAssignment(e *ast.Expr) (ast.Var, ast.Ref, bool) {
	if !e.IsEquality() || e.Negated || len(e.With) > 0 {
		return "", nil, false
	}
	a, b := e.Operand(0), e.Operand(1)
	if _, ok := a.Value.(ast.Ref); ok {
		a, b = b, a
	}
	v, ok := a.Value.(ast.Var)
	ref, ok2 := b.Value.(ast.Ref)
	if !ok || !ok2 || !ref.HasPrefix(ast.DefaultRootRef) || !ref.IsGround() {
		return "", nil, false
	}
	return v, ref, true
}

// membershipOnly reports whether every use of v after expression def is as the collection of
// a membership test.
func (a *flowAnalyzer) membershipOnly(r *ast.Rule, v ast.Var, def int) bool {
	if occurs(r.Head.Key, v) || occurs(r.Head.Value, v) {
		return false
	}
	used := false
	for _, e := range r.Body[def+1:] {
		if !occursExpr(e, v) {
			continue
		}
		used = true
		if !e.IsCall() || e.Operator().String() != ast.Member.Name || len(e.With) > 0 {
			return false
		}
		ops := e.Operands()
		if !ops[1].Equal(ast.VarTerm(string(v))) || occurs(ops[0], v) {
			return false
		}
	}
	return used
}

// flowPaths returns the paths in the value of rule r where v lands, when every use of v
// after expression def only carries it there: through assignments, object literals,
// object.union, string rendering builtins and functions that pass an argument through.
func (a *flowAnalyzer) flowPaths(r *ast.Rule, kind ruleKind, v ast.Var, def int) ([][]string, bool) {
	var out [][]string
	head := r.Head.Value
	if kind == rulePolicy && r.Head.Key != nil {
		head = r.Head.Key
	}
	if head != nil {
		ps, ok := pathsIn(head, v)
		if !ok {
			return nil, false
		}
		out = append(out, ps...)
	}
	for _, e := range r.Body[def+1:] {
		if !occursExpr(e, v) {
			continue
		}
		if e.Negated || len(e.With) > 0 {
			return nil, false
		}
		ps, ok := a.flowThrough(r, kind, e, v)
		if !ok {
			return nil, false
		}
		out = append(out, ps...)
	}
	return out, true
}

// nolint:gocyclo
func (a *flowAnalyzer) flowThrough(r *ast.Rule, kind ruleKind, e *ast.Expr, v ast.Var) ([][]string, bool) {
	ops := e.Operands()
	if e.IsEquality() {
		lhs, rhs := ops[0], ops[1]
		if occurs(lhs, v) && occurs(rhs, v) {
			return nil, false
		}
		if occurs(lhs, v) {
			lhs, rhs = rhs, lhs
		}
		w, ok := lhs.Value.(ast.Var)
		if !ok || boundBefore(r, w, e.Index) {
			return nil, false
		}
		inner, ok := pathsIn(rhs, v)
		if !ok {
			return nil, false
		}
		outer, ok := a.flowPaths(r, kind, w, e.Index)
		if !ok {
			return nil, false
		}
		return join(outer, nil, inner), true
	}
	if !e.IsCall() {
		return nil, false
	}
	op := e.Operator()
	name := op.String()
	switch {
	case msgBuiltins[name]:
		n := builtinArity(name, len(ops))
		w, ok := outputVar(ops, n, v)
		if !ok {
			return nil, false
		}
		return a.flowPaths(r, kind, w, e.Index)
	case name == ast.ObjectUnion.Name:
		w, ok := outputVar(ops, 2, v)
		if !ok {
			return nil, false
		}
		var inner [][]string
		for _, o := range ops[:2] {
			ps, ok := pathsIn(o, v)
			if !ok {
				return nil, false
			}
			inner = append(inner, ps...)
		}
		outer, ok := a.flowPaths(r, kind, w, e.Index)
		if !ok {
			return nil, false
		}
		return join(outer, nil, inner), true
	case name == ast.ObjectUnionN.Name:
		w, ok := outputVar(ops, 1, v)
		if !ok {
			return nil, false
		}
		ps, ok := pathsIn(ops[0], v)
		if !ok {
			return nil, false
		}
		inner := make([][]string, 0, len(ps))
		for _, p := range ps {
			if len(p) == 0 || p[0] != anyElem {
				return nil, false
			}
			inner = append(inner, p[1:])
		}
		outer, ok := a.flowPaths(r, kind, w, e.Index)
		if !ok {
			return nil, false
		}
		return join(outer, nil, inner), true
	case name == ast.ObjectRemove.Name:
		w, ok := outputVar(ops, 2, v)
		if !ok || occurs(ops[1], v) {
			return nil, false
		}
		inner, ok := pathsIn(ops[0], v)
		if !ok {
			return nil, false
		}
		outer, ok := a.flowPaths(r, kind, w, e.Index)
		if !ok {
			return nil, false
		}
		return join(outer, nil, inner), true
	case op.HasPrefix(ast.DefaultRootRef):
		n := a.rules.funcArity(op)
		if n < 0 {
			return nil, false
		}
		w, ok := outputVar(ops, n, v)
		if !ok {
			return nil, false
		}
		outer, ok := a.flowPaths(r, kind, w, e.Index)
		if !ok {
			return nil, false
		}
		var res [][]string
		for i, o := range ops[:n] {
			inner, ok := pathsIn(o, v)
			if !ok {
				return nil, false
			}
			if len(inner) == 0 {
				continue
			}
			shift, ok := a.funcFlow(op, i)
			if !ok {
				return nil, false
			}
			for _, s := range shift {
				res = append(res, join(outer, s, inner)...)
			}
		}
		return res, true
	}
	return nil, false
}

// outputVar returns the output operand of a call with n inputs, if it is a variable and v is
// not it.
func outputVar(ops []*ast.Term, n int, v ast.Var) (ast.Var, bool) {
	if len(ops) != n+1 || occurs(ops[n], v) {
		return "", false
	}
	w, ok := ops[n].Value.(ast.Var)
	return w, ok
}

// funcFlow returns the paths in the value of function fn where argument i lands.
func (a *flowAnalyzer) funcFlow(fn ast.Ref, i int) ([][]string, bool) {
	key := fn.String() + "#" + strconv.Itoa(i)
	if ps, ok := a.funcsOK[key]; ok {
		return a.funcs[key], ps
	}
	if a.visiting[key] {
		return nil, false
	}
	a.visiting[key] = true
	defer delete(a.visiting, key)
	var out [][]string
	ok := true
	for _, r := range a.rules.rules(fn) {
		if i >= len(r.Head.Args) {
			ok = false
			break
		}
		arg := r.Head.Args[i]
		if arg.IsGround() {
			continue
		}
		v, isVar := arg.Value.(ast.Var)
		if !isVar {
			ok = false
			break
		}
		ps, pok := a.flowPaths(r, ruleFunc, v, -1)
		if !pok {
			ok = false
			break
		}
		out = append(out, ps...)
	}
	a.funcs[key], a.funcsOK[key] = out, ok
	return out, ok
}

func join(outer [][]string, mid []string, inner [][]string) [][]string {
	var res [][]string
	for _, o := range outer {
		for _, in := range inner {
			p := make([]string, 0, len(o)+len(mid)+len(in))
			p = append(p, o...)
			p = append(p, mid...)
			p = append(p, in...)
			res = append(res, p)
		}
	}
	return res
}

// pathsIn returns the paths of v inside term: object keys, "*" for array and set elements.
// It fails when v occurs in a key, a ref or a comprehension.
// nolint:gocyclo
func pathsIn(term *ast.Term, v ast.Var) ([][]string, bool) {
	if term == nil {
		return nil, true
	}
	switch x := term.Value.(type) {
	case ast.Var:
		if x == v {
			return [][]string{{}}, true
		}
		return nil, true
	case ast.Object:
		var out [][]string
		ok := true
		_ = x.Iter(func(k, val *ast.Term) error {
			if occurs(k, v) {
				ok = false
				return errStop
			}
			ps, pok := pathsIn(val, v)
			if !pok {
				ok = false
				return errStop
			}
			key := ""
			if s, isStr := k.Value.(ast.String); isStr {
				key = string(s)
			}
			for _, p := range ps {
				out = append(out, append([]string{key}, p...))
			}
			return nil
		})
		return out, ok
	case *ast.Array:
		var out [][]string
		for i := 0; i < x.Len(); i++ {
			ps, ok := pathsIn(x.Elem(i), v)
			if !ok {
				return nil, false
			}
			for _, p := range ps {
				out = append(out, append([]string{anyElem}, p...))
			}
		}
		return out, true
	case ast.Set:
		var out [][]string
		ok := true
		_ = x.Iter(func(e *ast.Term) error {
			ps, pok := pathsIn(e, v)
			if !pok {
				ok = false
				return errStop
			}
			for _, p := range ps {
				out = append(out, append([]string{anyElem}, p...))
			}
			return nil
		})
		return out, ok
	}
	if occurs(term, v) {
		return nil, false
	}
	return nil, true
}

func occurs(term *ast.Term, v ast.Var) bool {
	if term == nil {
		return false
	}
	found := false
	ast.WalkVars(term, func(x ast.Var) bool {
		found = found || x == v
		return found
	})
	return found
}

func occursExpr(e *ast.Expr, v ast.Var) bool {
	found := false
	ast.WalkVars(e, func(x ast.Var) bool {
		found = found || x == v
		return found
	})
	return found
}

// boundBefore reports whether w occurs in the head arguments or before expression i.
func boundBefore(r *ast.Rule, w ast.Var, i int) bool {
	for _, a := range r.Head.Args {
		if occurs(a, w) {
			return true
		}
	}
	for _, e := range r.Body[:i] {
		if occursExpr(e, w) {
			return true
		}
	}
	return false
}
