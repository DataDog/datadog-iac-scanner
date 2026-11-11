package unknowngate

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// freshString equals no constant a rule can contain.
const freshString = "\x00unknowngate-fresh"

// substitutionValues collects the replacement values of the substitution check: the scalar
// constants the gated rules compare with an input-derived value (and of every rule they
// reach), numbers plus and minus one, true, false, 0, "", [], {} and a fresh string.
// companions are objects shaped by the attribute paths the rules read, one per scalar value,
// to stand for an unknown relation element. countExpands are list-cardinality sizes taken
// only from count(...) comparisons in those rules.
func substitutionValues(c *ast.Compiler, cr *compiledRules, placeholder string) (values, companions []ast.Value, countExpands []int) {
	seen := newValueSet()
	add := func(v ast.Value) {
		if s, ok := v.(ast.String); ok && string(s) == placeholder {
			return
		}
		if seen.add(v) {
			values = append(values, v)
		}
	}
	base := []ast.Value{
		ast.Boolean(true), ast.Boolean(false), ast.Number("0"), ast.String(""),
		ast.NewArray(), ast.NewObject(), ast.String(freshString),
	}
	for _, v := range base {
		add(v)
	}
	constants, shapes, reached := reachableConstants(c, cr)
	for _, v := range constants {
		add(v)
		if n, ok := v.(ast.Number); ok {
			if f, ok := new(big.Float).SetString(string(n)); ok {
				one := big.NewFloat(1)
				add(ast.Number(new(big.Float).Add(f, one).Text('g', -1)))
				add(ast.Number(new(big.Float).Sub(f, one).Text('g', -1)))
			}
		}
	}
	if !shapes.empty() {
		for _, v := range values {
			if ast.IsScalar(v) {
				companions = append(companions, shapes.build(v))
			}
		}
	}
	return values, companions, countExpandSizes(reached, cr)
}

// reachableConstants returns the comparison constants of the gated rules and of every rule
// they reach, the attribute paths they read below variables, and the reached rules themselves.
func reachableConstants(c *ast.Compiler, cr *compiledRules) ([]ast.Value, *shape, []*ast.Rule) {
	shapes := newShape()
	seen := map[*ast.Rule]bool{}
	var queue, reached []*ast.Rule
	for r, m := range cr.meta {
		if m.kind == rulePolicy {
			queue = append(queue, r)
		}
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].Loc().Compare(queue[j].Loc()) < 0 })
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		if seen[r] {
			continue
		}
		seen[r] = true
		reached = append(reached, r)
		var vis *ast.GenericVisitor
		vis = ast.NewGenericVisitor(func(x any) bool {
			v, ok := x.(ast.Ref)
			if !ok {
				return false
			}
			if v.HasPrefix(ast.DefaultRootRef) {
				queue = append(queue, c.GetRules(v.GroundPrefix())...)
			} else if _, isVar := v[0].Value.(ast.Var); isVar && !v.HasPrefix(ast.InputRootRef) {
				shapes.addPath(v[1:])
			}
			// Attribute names in ref steps are not values: a ref key that holds an
			// unknown is always a touch for the tracer.
			for _, k := range v[1:] {
				if !ast.IsScalar(k.Value) {
					vis.Walk(k)
				}
			}
			return true
		})
		vis.Walk(r)
	}
	return comparisonConstants(reached, cr), shapes, reached
}

// shape is a tree of the attribute paths the rules read below a variable.
type shape struct {
	keys  map[string]*shape
	elems *shape
}

func newShape() *shape { return &shape{keys: map[string]*shape{}} }

func (s *shape) empty() bool { return len(s.keys) == 0 && s.elems == nil }

func (s *shape) addPath(path ast.Ref) {
	cur := s
	for _, t := range path {
		switch k := t.Value.(type) {
		case ast.String:
			next := cur.keys[string(k)]
			if next == nil {
				next = newShape()
				cur.keys[string(k)] = next
			}
			cur = next
		case ast.Var, ast.Number:
			if cur.elems == nil {
				cur.elems = newShape()
			}
			cur = cur.elems
		default:
			return
		}
	}
}

func (s *shape) build(leaf ast.Value) ast.Value {
	if len(s.keys) > 0 {
		obj := ast.NewObject()
		for k, c := range s.keys {
			obj.Insert(ast.StringTerm(k), ast.NewTerm(c.build(leaf)))
		}
		return obj
	}
	if s.elems != nil {
		return ast.NewArray(ast.NewTerm(s.elems.build(leaf)))
	}
	return leaf
}

type parentKind uint8

const (
	parentNone parentKind = iota
	parentArray
	parentObject
	parentSet
)

// occurrence is the position of one placeholder inside a scope value.
type occurrence struct {
	path   []*ast.Term
	parent parentKind
}

func occurrences(v ast.Value, ph *placeholder) []occurrence {
	var out []occurrence
	var walk func(v ast.Value, path []*ast.Term, parent parentKind)
	walk = func(v ast.Value, path []*ast.Term, parent parentKind) {
		if ph.is(v) {
			out = append(out, occurrence{path: append([]*ast.Term(nil), path...), parent: parent})
			return
		}
		if !ph.has(v) {
			return
		}
		switch x := v.(type) {
		case *ast.Array:
			for i := 0; i < x.Len(); i++ {
				walk(x.Elem(i).Value, append(path, ast.InternedTerm(i)), parentArray)
			}
		case ast.Object:
			_ = x.Iter(func(k, e *ast.Term) error {
				walk(e.Value, append(path, k), parentObject)
				return nil
			})
		case ast.Set:
			_ = x.Iter(func(e *ast.Term) error {
				walk(e.Value, append(path, e), parentSet)
				return nil
			})
		}
	}
	walk(v, nil, parentNone)
	return out
}

// replacement is one concretization of a placeholder: a value, its removal (a
// dynamic block with no instance), or, for a list element, an expansion that
// replaces the placeholder with expandBy concrete elements (unknown
// dynamic-block cardinality). expandBy is how many concrete elements to insert;
// 0 means 1.
type replacement struct {
	value    ast.Value
	remove   bool
	expand   bool
	expandBy int
}

func (r replacement) expandCount() int {
	if r.expandBy > 0 {
		return r.expandBy
	}
	return 1
}

func (r replacement) String() string {
	if r.remove {
		return "removed"
	}
	if r.expand {
		return "expanded"
	}
	return r.value.String()
}

// scopesOf returns the composite scopes of c. A scope is replaced in the input by value, so a
// scalar scope would stand for every equal scalar.
func scopesOf(c Candidate, input ast.Value) []ast.Value {
	if len(c.Scope) == 0 {
		return []ast.Value{input}
	}
	out := make([]ast.Value, 0, len(c.Scope))
	for _, s := range c.Scope {
		switch s.(type) {
		case *ast.Array, ast.Object, ast.Set:
			out = append(out, s)
		}
	}
	return out
}

// substitution runs stage 2 on the candidates that share one input.
type substitution struct {
	g     *Gate
	ctx   context.Context
	input ast.Value
	ph    *placeholder
	evals int
}

// removes reports whether replacing the unknown at o in scope s by r removes the result of j.
func (s *substitution) removes(scope ast.Value, o occurrence, r replacement, j *job) (bool, error) {
	s2 := replaceAt(scope, o.path, r)
	in := rebuild(s.input, s.ph, func(v ast.Value) (ast.Value, bool) { return s2, sameValue(v, scope) })
	var errs []topdown.Error
	res, err := s.g.evalErrs(s.ctx, in, &errs)
	s.evals++
	if err != nil {
		return false, err
	}
	return !hasIdentity(res, j.id, j.mask, s.ph) && !s.g.renderingFailed(errs), nil
}

func substitutionVerdict(o occurrence, r replacement) Verdict {
	return Verdict{
		Uncertain: true,
		Stage:     StageSubstitution,
		Reason:    fmt.Sprintf("the result disappears when the unknown at %v is %v", ast.Ref(o.path), r),
	}
}

// batch checks candidates together. Each replacement is applied to every unknown of every
// scope at once, in one evaluation. A candidate whose result disappears is checked again one
// unknown at a time; that check decides. A result that a single substitution removes but that
// the combined substitutions keep is missed: the batch trades that case for one evaluation per
// replacement instead of one per candidate.
func (s *substitution) batch(jobs []job, out []Verdict) error {
	scopes := make([][]ast.Value, len(jobs))
	all := newValueSet()
	var list []ast.Value
	pending := 0
	for i := range jobs {
		for _, scope := range scopesOf(jobs[i].cand, s.input) {
			if !s.ph.has(scope) {
				continue
			}
			scopes[i] = append(scopes[i], scope)
			if all.add(scope) {
				list = append(list, scope)
			}
		}
		if len(scopes[i]) > 0 {
			pending++
		}
	}
	inList := s.inList(list)
	for _, r := range s.g.batchReplacements() {
		if pending == 0 {
			break
		}
		if r.listOnly && !inList {
			continue
		}
		n, err := s.batchRound(jobs, scopes, list, r, out)
		if err != nil {
			return err
		}
		pending -= n
	}
	return nil
}

func (s *substitution) inList(scopes []ast.Value) bool {
	for _, scope := range scopes {
		for _, o := range occurrences(scope, s.ph) {
			if o.parent == parentArray || o.parent == parentSet {
				return true
			}
		}
	}
	return false
}

// batchRound applies r to every scope, evaluates once and confirms the candidates whose result
// disappears. It clears the scopes of the candidates it decides and returns their number.
func (s *substitution) batchRound(jobs []job, scopes [][]ast.Value, list []ast.Value, r batchReplacement, out []Verdict) (int, error) {
	repl := newValueMap[ast.Value]()
	for _, scope := range list {
		repl.put(scope, replaceEvery(scope, r, s.ph))
	}
	var errs []topdown.Error
	res, err := s.g.evalErrs(s.ctx, replaceScopes(s.input, repl, s.ph), &errs)
	s.evals++
	if err != nil {
		return 0, err
	}
	ids := newIdentityIndex(res, s.ph)
	decided := 0
	for i := range jobs {
		j := &jobs[i]
		if len(scopes[i]) == 0 || ids.has(j.id, j.mask) {
			continue
		}
		v, err := s.confirm(scopes[i], r, j)
		if err != nil {
			return decided, err
		}
		if v.Uncertain {
			out[j.index] = v
			scopes[i] = nil
			decided++
		}
	}
	return decided, nil
}

// confirm checks replacement r on each unknown of scopes, one at a time.
func (s *substitution) confirm(scopes []ast.Value, r batchReplacement, j *job) (Verdict, error) {
	for _, scope := range scopes {
		for _, o := range occurrences(scope, s.ph) {
			if !r.applies(o.parent) {
				continue
			}
			gone, err := s.removes(scope, o, r.replacement, j)
			if err != nil {
				return Verdict{}, err
			}
			if gone {
				return substitutionVerdict(o, r.replacement), nil
			}
		}
	}
	return Verdict{}, nil
}

// batchReplacement is a replacement and the unknowns it applies to.
type batchReplacement struct {
	replacement
	listOnly bool
}

func (r batchReplacement) applies(p parentKind) bool {
	return !r.listOnly || p == parentArray || p == parentSet
}

func (g *Gate) batchReplacements() []batchReplacement {
	out := make([]batchReplacement, 0, len(g.values)+2*len(g.companions)+len(g.countExpands)+1)
	out = append(out, batchReplacement{replacement{remove: true}, true})
	expandVal := ast.Value(ast.NewObject())
	if len(g.companions) > 0 {
		expandVal = g.companions[0]
	}
	for _, n := range g.countExpands {
		out = append(out, batchReplacement{replacement{
			value: expandVal, expand: true, expandBy: n,
		}, true})
	}
	for _, v := range g.values {
		out = append(out, batchReplacement{replacement{value: v}, false})
	}
	for _, v := range g.companions {
		out = append(out, batchReplacement{replacement{value: v}, true})
	}
	return out
}

// countExpandSizes returns the list-cardinality substitutions for count(...)
// comparisons in rules: always 1 (for small equalities such as != 2), plus each
// bound a count is compared with. There is no fixed maximum: a count < 100
// yields expandBy 100. Unrelated numeric constants (ports, etc.) are ignored.
// After compile, count appears as count(coll, out) then lt(out, N).
func countExpandSizes(rules []*ast.Rule, cr *compiledRules) []int {
	seen := map[int]bool{1: true}
	for _, r := range rules {
		countVars := countResultVars(r, cr)
		ast.WalkExprs(r, func(e *ast.Expr) bool {
			if e.Negated || len(e.With) > 0 || !e.IsCall() {
				return false
			}
			name := e.Operator().String()
			if !compareOps[name] && !e.IsEquality() {
				return false
			}
			if e.IsEquality() {
				name = ast.Equality.Name
			}
			ops := e.Operands()
			if len(ops) < 2 {
				return false
			}
			if n, ok := countCompareExpand(countVars, name, ops[0], ops[1]); ok {
				seen[n] = true
			}
			return false
		})
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// countResultVars are variables that hold count(...) in a rule body: either
// bound as count(coll, out) or assigned from a count call term.
func countResultVars(r *ast.Rule, cr *compiledRules) map[ast.Var]bool {
	out := map[ast.Var]bool{}
	for _, e := range r.Body {
		if e.Negated || len(e.With) > 0 || !e.IsCall() || e.IsEquality() {
			continue
		}
		if !e.Operator().Equal(ast.Count.Ref()) {
			continue
		}
		ops := e.Operands()
		if len(ops) == 2 {
			if v, ok := ops[1].Value.(ast.Var); ok {
				out[v] = true
			}
		}
	}
	for v, def := range cr.defs[r] {
		if isCountCall(def) {
			out[v] = true
		}
	}
	return out
}

// countCompareExpand is the expandBy that can flip a count comparison, if any.
func countCompareExpand(countVars map[ast.Var]bool, op string, left, right *ast.Term) (int, bool) {
	n, countLeft, ok := countCompareNumber(countVars, left, right)
	if !ok || n < 0 {
		return 0, false
	}
	switch op {
	case ast.Equal.Name, ast.Equality.Name, ast.NotEqual.Name:
		if n == 0 {
			return 0, false // remove already yields zero
		}
		return n, true
	case ast.LessThan.Name:
		if countLeft {
			return n, n > 0
		}
		return 0, false
	case ast.LessThanEq.Name:
		if countLeft {
			return n + 1, true
		}
		return 0, false
	case ast.GreaterThan.Name:
		if !countLeft {
			return n, n > 0
		}
		return 0, false
	case ast.GreaterThanEq.Name:
		if !countLeft {
			return n + 1, true
		}
		return 0, false
	}
	return 0, false
}

func countCompareNumber(countVars map[ast.Var]bool, left, right *ast.Term) (n int, countLeft bool, ok bool) {
	switch {
	case termIsCount(countVars, left):
		n, ok = termInt(right)
		return n, true, ok
	case termIsCount(countVars, right):
		n, ok = termInt(left)
		return n, false, ok
	}
	return 0, false, false
}

func termIsCount(countVars map[ast.Var]bool, t *ast.Term) bool {
	if isCountCall(t) {
		return true
	}
	v, ok := t.Value.(ast.Var)
	return ok && countVars[v]
}

func isCountCall(t *ast.Term) bool {
	call, ok := t.Value.(ast.Call)
	if !ok || len(call) == 0 {
		return false
	}
	ref, ok := call[0].Value.(ast.Ref)
	return ok && ref.Equal(ast.Count.Ref())
}

func termInt(t *ast.Term) (int, bool) {
	n, ok := t.Value.(ast.Number)
	if !ok {
		return 0, false
	}
	return n.Int()
}

// replaceEvery returns v with r applied to every unknown it applies to.
func replaceEvery(v ast.Value, r batchReplacement, ph *placeholder) ast.Value {
	if ph.is(v) {
		if r.applies(parentNone) {
			return r.value
		}
		return v
	}
	if !ph.has(v) {
		return v
	}
	switch x := v.(type) {
	case *ast.Array:
		elems := make([]*ast.Term, 0, x.Len())
		for i := 0; i < x.Len(); i++ {
			e := x.Elem(i)
			if ph.is(e.Value) {
				if r.remove {
					continue
				}
				if r.expand {
					for i := 0; i < r.expandCount(); i++ {
						elems = append(elems, ast.NewTerm(r.value))
					}
					continue
				}
				elems = append(elems, ast.NewTerm(r.value))
				continue
			}
			elems = append(elems, ast.NewTerm(replaceEvery(e.Value, r, ph)))
		}
		return ast.NewArray(elems...)
	case ast.Object:
		out := ast.NewObject()
		_ = x.Iter(func(k, e *ast.Term) error {
			if ph.is(e.Value) && !r.applies(parentObject) {
				out.Insert(k, e)
				return nil
			}
			out.Insert(k, ast.NewTerm(replaceEvery(e.Value, r, ph)))
			return nil
		})
		return out
	case ast.Set:
		out := ast.NewSet()
		_ = x.Iter(func(e *ast.Term) error {
			if ph.is(e.Value) {
				if !r.remove {
					out.Add(ast.NewTerm(r.value))
				}
				return nil
			}
			out.Add(ast.NewTerm(replaceEvery(e.Value, r, ph)))
			return nil
		})
		return out
	}
	return v
}

// replaceScopes returns input with every subterm found in repl replaced. Every scope holds
// the placeholder, so subterms without it are kept as they are.
func replaceScopes(input ast.Value, repl *valueMap[ast.Value], ph *placeholder) ast.Value {
	return rebuild(input, ph, func(v ast.Value) (ast.Value, bool) { return repl.get(v) })
}

// rebuild returns v with the composite subterms that hold the placeholder and that subst maps
// replaced, sharing every unchanged subterm.
// nolint:gocyclo
func rebuild(v ast.Value, ph *placeholder, subst func(ast.Value) (ast.Value, bool)) ast.Value {
	switch v.(type) {
	case *ast.Array, ast.Object, ast.Set:
	default:
		return v
	}
	if !ph.has(v) {
		return v
	}
	if n, ok := subst(v); ok {
		return n
	}
	switch x := v.(type) {
	case *ast.Array:
		var elems []*ast.Term
		for i := 0; i < x.Len(); i++ {
			e := x.Elem(i)
			n := rebuild(e.Value, ph, subst)
			if elems == nil && n != e.Value {
				elems = make([]*ast.Term, i, x.Len())
				for k := 0; k < i; k++ {
					elems[k] = x.Elem(k)
				}
			}
			if elems != nil {
				elems = append(elems, ast.NewTerm(n))
			}
		}
		if elems == nil {
			return v
		}
		return ast.NewArray(elems...)
	case ast.Object:
		var changed [][2]*ast.Term
		_ = x.Iter(func(k, e *ast.Term) error {
			if n := rebuild(e.Value, ph, subst); n != e.Value {
				changed = append(changed, [2]*ast.Term{k, ast.NewTerm(n)})
			}
			return nil
		})
		if changed == nil {
			return v
		}
		out := ast.NewObject()
		_ = x.Iter(func(k, e *ast.Term) error {
			out.Insert(k, e)
			return nil
		})
		for _, kv := range changed {
			out.Insert(kv[0], kv[1])
		}
		return out
	case ast.Set:
		changed := false
		out := ast.NewSet()
		_ = x.Iter(func(e *ast.Term) error {
			n := rebuild(e.Value, ph, subst)
			if n != e.Value {
				changed = true
				out.Add(ast.NewTerm(n))
				return nil
			}
			out.Add(e)
			return nil
		})
		if !changed {
			return v
		}
		return out
	}
	return v
}

// renderingFailed reports whether a string rendering builtin raised an error: the value
// substituted has a type the attribute cannot have, and a well-typed value is tried as well.
func (g *Gate) renderingFailed(errs []topdown.Error) bool {
	for _, e := range errs {
		if e.Location != nil && g.renderSites[locationKey(e.Location)] {
			return true
		}
	}
	return false
}

func locationKey(l *ast.Location) string {
	return fmt.Sprintf("%s:%d:%d", l.File, l.Row, l.Col)
}

// renderSites returns the locations of the string rendering builtin calls of c.
func renderSites(c *ast.Compiler) map[string]bool {
	out := map[string]bool{}
	for _, m := range c.Modules {
		ast.WalkExprs(m, func(e *ast.Expr) bool {
			if e.IsCall() && msgBuiltins[e.Operator().String()] && e.Location != nil {
				out[locationKey(e.Location)] = true
			}
			return false
		})
	}
	return out
}

// identityIndex holds the identities of a result set, computed once per mask.
type identityIndex struct {
	results []ast.Value
	ph      *placeholder
	byMask  map[string]*valueSet
}

func newIdentityIndex(res ast.Value, ph *placeholder) *identityIndex {
	return &identityIndex{results: elements(res), ph: ph, byMask: map[string]*valueSet{}}
}

func (x *identityIndex) has(id ast.Value, mask []string) bool {
	key := strings.Join(mask, "\x00")
	set, ok := x.byMask[key]
	if !ok {
		set = newValueSet()
		for _, e := range x.results {
			set.add(x.ph.identityMasked(e, mask))
		}
		x.byMask[key] = set
	}
	return set.has(id)
}

func hasIdentity(res, id ast.Value, mask []string, ph *placeholder) bool {
	for _, e := range elements(res) {
		if ph.identityMasked(e, mask).Compare(id) == 0 {
			return true
		}
	}
	return false
}

// replaceAt returns v with the value at path replaced.
func replaceAt(v ast.Value, path []*ast.Term, r replacement) ast.Value {
	if len(path) == 0 {
		return r.value
	}
	k := path[0]
	switch x := v.(type) {
	case *ast.Array:
		i, _ := k.Value.(ast.Number).Int()
		elems := make([]*ast.Term, 0, x.Len())
		for j := 0; j < x.Len(); j++ {
			if j != i {
				elems = append(elems, x.Elem(j))
				continue
			}
			if len(path) == 1 && r.remove {
				continue
			}
			if len(path) == 1 && r.expand {
				for k := 0; k < r.expandCount(); k++ {
					elems = append(elems, ast.NewTerm(r.value))
				}
				continue
			}
			elems = append(elems, ast.NewTerm(replaceAt(x.Elem(j).Value, path[1:], r)))
		}
		return ast.NewArray(elems...)
	case ast.Object:
		out := ast.NewObject()
		_ = x.Iter(func(key, e *ast.Term) error {
			if key.Value.Compare(k.Value) != 0 {
				out.Insert(key, e)
				return nil
			}
			if len(path) == 1 && r.remove {
				return nil
			}
			out.Insert(key, ast.NewTerm(replaceAt(e.Value, path[1:], r)))
			return nil
		})
		return out
	case ast.Set:
		out := ast.NewSet()
		_ = x.Iter(func(e *ast.Term) error {
			if e.Value.Compare(k.Value) != 0 {
				out.Add(e)
				return nil
			}
			if len(path) == 1 && r.remove {
				return nil
			}
			out.Add(ast.NewTerm(replaceAt(e.Value, path[1:], r)))
			return nil
		})
		return out
	}
	return v
}

func sameValue(a, b ast.Value) bool {
	switch x := a.(type) {
	case ast.Object:
		if y, ok := b.(ast.Object); ok && x == y {
			return true
		}
	case *ast.Array:
		if y, ok := b.(*ast.Array); ok && x == y {
			return true
		}
	case ast.Set:
		if y, ok := b.(ast.Set); ok && x == y {
			return true
		}
	}
	return a.Hash() == b.Hash() && a.Compare(b) == 0
}
