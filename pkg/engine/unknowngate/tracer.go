package unknowngate

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
)

type frameKind uint8

const (
	// kindQuery: a negation, comprehension, `every` or the top query. Its outcome is part of
	// the expression that spawned it, so touches propagate to that expression.
	kindQuery frameKind = iota
	// kindPolicy: a derivation of the gated rule.
	kindPolicy
	// kindVdoc: a derivation of another rule without arguments, memoised per element.
	kindVdoc
	// kindFunc: a function body, memoised per call.
	kindFunc
)

type touchKind uint8

const (
	touchNone touchKind = iota
	// touchSet: the set of solutions of the expression may differ (iterating an unknown),
	// but every solution found holds.
	touchSet
	// touchValue: the current solution, or the failure, depends on an unknown.
	touchValue
)

func worse(a, b touchKind) touchKind {
	if b > a {
		return b
	}
	return a
}

// frame is the state of one query (rule body, negation, comprehension) of the evaluation.
type frame struct {
	parent     *frame
	parentExpr int
	kind       frameKind
	rule       *ast.Rule
	call       *callState
	scope      int
	input      ast.Value

	// taint[0] is the head unification, taint[i+1] expression i, on the current derivation.
	taint []bool
	// sticky[i]: expression i was touched before producing a solution, so every solution
	// it produces carries the touch.
	sticky []bool
	// touch and touchSticky mirror taint and sticky for a function body, for every kind of
	// touch: the call learns of them when the derivation succeeds, or fails on an
	// expression that may not fail whatever the unknown is.
	touch       []bool
	touchSticky []bool
	exprs       []*ast.Expr
	last        int
	lastDone    bool

	calls     map[int]*callState
	iterRefs  map[int][]ast.Ref
	withScope map[int]int
	withInput map[int]ast.Value
}

type resultState struct {
	anyClean bool
}

// tracer marks, per derivation of the gated rule, whether it depends on an unknown value.
type tracer struct {
	g       *Gate
	ph      *placeholder
	input   ast.Value
	frames  map[uint64]*frame
	scopes  []*scopeMemo
	results *valueMap[*resultState]
	// probes caches the values of evalCall by call; nil stands for no value.
	probes *valueMap[ast.Value]
	// probeDepth is the nesting of the traced probes, rootTouched says that a touch reached the
	// top query of this tracer.
	probeDepth  int
	rootTouched bool
}

func (f *frame) grow(i int) {
	for len(f.taint) < i+2 {
		f.taint = append(f.taint, false)
		f.sticky = append(f.sticky, false)
		f.touch = append(f.touch, false)
		f.touchSticky = append(f.touchSticky, false)
		f.exprs = append(f.exprs, nil)
	}
}

func (f *frame) reset(i int) {
	f.grow(i)
	for k := i + 1; k < len(f.taint); k++ {
		f.taint[k] = false
		f.touch[k] = false
	}
}

// commitTouch tells the call, or the virtual document, of f that a derivation touched an
// unknown.
func (t *tracer) commitTouch(f *frame, ev *topdown.Event) {
	switch f.kind {
	case kindFunc:
		if f.call != nil {
			f.call.touched = true
		}
	case kindVdoc:
		ref, _, _ := t.elementRef(f, f.rule, ev)
		t.memo(f.scope).docs.markDirty(ref)
	}
}

func (f *frame) anyTouch() bool {
	n := f.last + 2
	if n > len(f.touch) {
		n = len(f.touch)
	}
	for _, x := range f.touch[:n] {
		if x {
			return true
		}
	}
	return false
}

func (f *frame) anyTaint() bool {
	n := f.last + 2
	if n > len(f.taint) {
		n = len(f.taint)
	}
	for _, x := range f.taint[:n] {
		if x {
			return true
		}
	}
	return false
}

func (f *frame) scopeAt(i int) int {
	if s, ok := f.withScope[i]; ok {
		return s
	}
	return f.scope
}

func (f *frame) inputAt(i int) ast.Value {
	if v, ok := f.withInput[i]; ok {
		return v
	}
	return f.input
}

const maxProbeDepth = 2

func newTracer(g *Gate, input ast.Value) *tracer {
	return &tracer{
		g:       g,
		ph:      newPlaceholder(g.placeholder),
		input:   input,
		frames:  map[uint64]*frame{},
		scopes:  []*scopeMemo{newScopeMemo()},
		results: newValueMap[*resultState](),
		probes:  newValueMap[ast.Value](),
	}
}

func (t *tracer) Enabled() bool { return true }

func (t *tracer) Config() topdown.TraceConfig {
	return topdown.TraceConfig{PlugLocalVars: false}
}

// nolint:gocritic // topdown.QueryTracer takes the event by value.
func (t *tracer) TraceEvent(ev topdown.Event) {
	f := t.frame(&ev)
	switch ev.Op {
	case topdown.EnterOp:
		t.enter(f, &ev)
	case topdown.EvalOp:
		if e, ok := ev.Node.(*ast.Expr); ok {
			t.eval(f, e, &ev)
		}
	case topdown.RedoOp:
		if e, ok := ev.Node.(*ast.Expr); ok {
			t.redo(f, e, &ev)
		}
	case topdown.FailOp:
		if e, ok := ev.Node.(*ast.Expr); ok {
			t.fail(f, e, &ev)
		}
	case topdown.ExitOp:
		t.exit(f, &ev)
	case topdown.UnifyOp:
		t.unify(f, &ev)
	}
}

func (t *tracer) frame(ev *topdown.Event) *frame {
	if f := t.frames[ev.QueryID]; f != nil {
		return f
	}
	f := &frame{last: -1, parentExpr: -1, input: t.input}
	if p := t.frames[ev.ParentID]; p != nil && ev.ParentID != ev.QueryID {
		f.parent = p
		f.parentExpr = p.last
		// A closure (negation, comprehension, every) reads the variables of its rule; enter
		// replaces the rule of a rule body.
		f.rule = p.rule
		f.scope = p.scopeAt(p.last)
		f.input = p.inputAt(p.last)
	}
	t.frames[ev.QueryID] = f
	return f
}

func (t *tracer) memo(scope int) *scopeMemo { return t.scopes[scope] }

func (t *tracer) enter(f *frame, ev *topdown.Event) {
	r, ok := ev.Node.(*ast.Rule)
	if !ok {
		return
	}
	f.rule = r
	switch t.g.rules.meta[r].kind {
	case rulePolicy:
		f.kind = kindPolicy
	case ruleVdoc:
		f.kind = kindVdoc
	case ruleFunc:
		f.kind = kindFunc
		if p := f.parent; p != nil {
			f.call = p.calls[p.last]
		}
		if f.call == nil {
			f.kind = kindQuery
		}
	}
}

func (t *tracer) eval(f *frame, e *ast.Expr, ev *topdown.Event) {
	t.complete(f, ev)
	f.reset(e.Index)
	f.last, f.lastDone = e.Index, false
	f.exprs[e.Index] = e
	f.sticky[e.Index] = false
	f.touchSticky[e.Index] = false
	delete(f.calls, e.Index)
	delete(f.iterRefs, e.Index)
	if len(e.With) > 0 {
		t.with(f, e, ev)
	}
	if e.Negated {
		// The complement is evaluated, and checked, in a child query.
		return
	}
	t.check(f, e, ev)
}

func (t *tracer) redo(f *frame, e *ast.Expr, ev *topdown.Event) {
	if f.last == e.Index && !f.lastDone {
		// A solution of the last expression of a comprehension body: no Exit follows.
		f.lastDone = true
		t.post(f, e, ev, true)
	}
	f.reset(e.Index)
	f.last, f.lastDone = e.Index, false
	f.taint[e.Index+1] = f.sticky[e.Index]
	f.touch[e.Index+1] = f.touchSticky[e.Index]
}

func (t *tracer) fail(f *frame, e *ast.Expr, ev *topdown.Event) {
	if f.last == e.Index {
		f.lastDone = true
	}
	if f.anyTouch() && !t.failsWhateverUnknown(f, e, ev) {
		t.commitTouch(f, ev)
	}
	if !e.Negated {
		t.post(f, e, ev, false)
	}
}

// failsWhateverUnknown reports whether the derivation of a function body that failed at e
// fails whatever the unknown values are: a later comparison of two known values fails every
// derivation that reaches it. A derivation that fails before an unknown could matter does not
// make the call uncertain.
func (t *tracer) failsWhateverUnknown(f *frame, e *ast.Expr, ev *topdown.Event) bool {
	if f.rule == nil || f.rule.Body == nil || e.Negated {
		return false
	}
	for _, k := range f.rule.Body[e.Index+1:] {
		if t.knownCompareFails(f, k, ev) {
			return true
		}
	}
	return false
}

// knownCompareFails is true when e is a binary equality that fails on two known values.
func (t *tracer) knownCompareFails(f *frame, e *ast.Expr, ev *topdown.Event) bool {
	if e.Negated || len(e.With) > 0 || !e.IsCall() || len(e.Operands()) != 2 {
		return false
	}
	name := e.Operator().String()
	if name != ast.Equal.Name && name != ast.NotEqual.Name && !e.IsEquality() {
		return false
	}
	a := t.evalTerm(f, f.rule, e.Operand(0), ev, 0)
	b := t.evalTerm(f, f.rule, e.Operand(1), ev, 0)
	if a == nil || b == nil || t.ph.has(a) || t.ph.has(b) {
		return false
	}
	return (ast.Compare(a, b) == 0) == (name == ast.NotEqual.Name)
}

// complete runs the completion checks of the last expression of f once it succeeded.
func (t *tracer) complete(f *frame, ev *topdown.Event) {
	if f.last >= 0 && !f.lastDone {
		f.lastDone = true
		if e := f.exprs[f.last]; e != nil && !e.Negated {
			t.post(f, e, ev, true)
		}
	}
}

func (t *tracer) exit(f *frame, ev *topdown.Event) {
	switch n := ev.Node.(type) {
	case *ast.Rule:
		t.complete(f, ev)
		if f.anyTouch() {
			t.commitTouch(f, ev)
		}
		clean := !f.anyTaint()
		meta := t.g.rules.meta[n]
		switch f.kind {
		case kindPolicy:
			head := n.Head.Key
			if head == nil {
				head = n.Head.Value
			}
			t.addResult(ev.Plug(head).Value, clean)
		case kindVdoc:
			ref, ok, unknownKey := t.elementRef(f, n, ev)
			m := t.memo(f.scope)
			if !ok {
				m.docs.markDirty(ref)
				return
			}
			// A default or else value holds only if no unknown made the other rules fail.
			m.docs.derive(ref, clean && (meta.primary || !m.docs.related(ref)), unknownKey)
		case kindFunc:
			if clean && (meta.primary || !f.call.touched) {
				f.call.cleanPrimary = true
			}
		}
	case ast.Body:
		t.complete(f, ev)
	}
}

func (t *tracer) addResult(v ast.Value, clean bool) {
	id, _ := t.ph.identity(v)
	if rs, ok := t.results.get(id); ok {
		rs.anyClean = rs.anyClean || clean
		return
	}
	t.results.put(id, &resultState{anyClean: clean})
}

// elementRef plugs the ref of the element a virtual document rule produces. When the ref is
// not ground, or a key is an unknown, it returns the ground prefix and false. unknownKey says
// that the last key holds an unknown below its top level.
func (t *tracer) elementRef(f *frame, r *ast.Rule, ev *topdown.Event) (ref ast.Ref, ok, unknownKey bool) {
	head := r.Ref()
	if r.Head.RuleKind() == ast.MultiValue && r.Head.Key != nil {
		head = head.Append(r.Head.Key)
	}
	out := make(ast.Ref, 0, len(head))
	for i, term := range head {
		if i == 0 || term.IsGround() {
			out = append(out, term)
			continue
		}
		// Before the key is bound (a touch earlier in the body), its definition tells which
		// element the derivation produces.
		v := t.evalTerm(f, r, term, ev, 0)
		if v == nil || t.ph.is(v) {
			return out, false, false
		}
		if t.ph.has(v) {
			if i < len(head)-1 {
				return out, false, false
			}
			unknownKey = true
		}
		out = append(out, ast.NewTerm(v))
	}
	return out, true, unknownKey
}

const maxDefinitionDepth = 8

// evalTerm returns the value term will have in rule r: its plugged value, or the value of the
// definitions of its unbound variables when every variable they read is bound. It returns nil
// when that value is not known yet.
// nolint:gocyclo
func (t *tracer) evalTerm(f *frame, r *ast.Rule, term *ast.Term, ev *topdown.Event, depth int) ast.Value {
	if depth > maxDefinitionDepth {
		return nil
	}
	switch x := term.Value.(type) {
	case ast.Var:
		if p := ev.Plug(term); p.IsGround() {
			return p.Value
		}
		if d := t.g.rules.defs[r][x]; d != nil {
			return t.evalTerm(f, r, d, ev, depth+1)
		}
		if c := t.g.rules.callDefs[r][x]; c != nil {
			return t.evalCall(f, r, c, ev, depth+1)
		}
		return nil
	case ast.Ref:
		var cur ast.Value
		switch {
		case x.HasPrefix(ast.DefaultRootRef):
			return nil
		case x[0].Equal(ast.InputRootDocument):
			cur = f.input
		default:
			cur = t.evalTerm(f, r, x[0], ev, depth+1)
		}
		for _, k := range x[1:] {
			kv := t.evalTerm(f, r, k, ev, depth+1)
			if cur == nil || kv == nil || t.ph.is(cur) {
				return nil
			}
			next, err := cur.Find(ast.Ref{ast.NewTerm(kv)})
			if err != nil {
				return nil
			}
			cur = next
		}
		return cur
	case *ast.Array:
		elems := make([]*ast.Term, x.Len())
		for i := range elems {
			v := t.evalTerm(f, r, x.Elem(i), ev, depth+1)
			if v == nil {
				return nil
			}
			elems[i] = ast.NewTerm(v)
		}
		return ast.NewArray(elems...)
	case ast.Object:
		out := ast.NewObject()
		ok := true
		_ = x.Iter(func(k, v *ast.Term) error {
			kv, vv := t.evalTerm(f, r, k, ev, depth+1), t.evalTerm(f, r, v, ev, depth+1)
			if kv == nil || vv == nil {
				ok = false
				return errStop
			}
			out.Insert(ast.NewTerm(kv), ast.NewTerm(vv))
			return nil
		})
		if !ok {
			return nil
		}
		return out
	}
	if term.IsGround() {
		return term.Value
	}
	return nil
}

// evalCall returns the value of a call of a rule function whose arguments are all known, when
// a traced evaluation of the call alone reads no unknown value: the call then has this value
// whatever the unknowns turn out to be. It returns nil otherwise.
func (t *tracer) evalCall(f *frame, r *ast.Rule, c *ast.Expr, ev *topdown.Event, depth int) ast.Value {
	if t.probeDepth >= maxProbeDepth || f.scope != 0 {
		return nil
	}
	ops := c.Operands()
	n := len(ops) - 1
	args := make([]*ast.Term, 0, n+1)
	args = append(args, ast.NewTerm(c.Operator()))
	for _, o := range ops[:n] {
		v := t.evalTerm(f, r, o, ev, depth)
		if v == nil {
			return nil
		}
		args = append(args, ast.NewTerm(v))
	}
	call := ast.NewTerm(ast.Call(args))
	key := ast.NewArray(call.Value.(ast.Call)...)
	if p, ok := t.probes.get(key); ok {
		return p
	}
	var out ast.Value
	if v, ok := t.g.probe(t, f.input, call); ok {
		out = v
	}
	t.probes.put(key, out)
	return out
}

// lookupTouch reports whether a lookup of ref in the memo that finds no element may still
// match an element whose key holds an unknown.
func (t *tracer) lookupTouch(m *scopeMemo, ref ast.Ref) bool {
	n, k := m.docs.missing(ref)
	if n == nil {
		return false
	}
	for _, uk := range n.unknownKeys {
		if t.valuesTouch(k, uk) {
			return true
		}
	}
	return false
}

// mark records a touch at expression i of f (-1 for the head) and propagates it.
func (t *tracer) mark(f *frame, i int, _ *topdown.Event, kind touchKind, sticky bool) {
	if kind == touchNone {
		return
	}
	if (f.kind == kindFunc && f.call != nil) || f.kind == kindVdoc {
		f.grow(i)
		f.touch[i+1] = true
		if sticky && i >= 0 {
			f.touchSticky[i] = true
		}
	}
	if kind == touchValue {
		f.grow(i)
		f.taint[i+1] = true
		if sticky && i >= 0 {
			f.sticky[i] = true
		}
	}
	switch f.kind {
	case kindQuery:
		if f.parent != nil {
			t.mark(f.parent, f.parentExpr, nil, touchValue, true)
		} else {
			t.rootTouched = true
		}
	case kindFunc:
	case kindVdoc, kindPolicy:
	}
}

// markMessage records a touch that only changes a rendered string flowing to the value of
// the rule of f.
func (t *tracer) markMessage(f *frame, i int, ev *topdown.Event) {
	switch f.kind {
	case kindPolicy:
	case kindFunc:
		f.call.msg = true
	default:
		t.mark(f, i, ev, touchValue, true)
	}
}

func (t *tracer) unify(f *frame, ev *topdown.Event) {
	e, ok := ev.Node.(*ast.Expr)
	if !ok || !e.IsEquality() || t.sentinelOperand(f, e.Operands()) {
		return
	}
	// The event holds the terms being unified, the value of a ref rather than the ref: the
	// expression under evaluation tells whether one of its operands is a sentinel.
	if f.last >= 0 && f.last < len(f.exprs) {
		if cur := f.exprs[f.last]; cur != nil && cur.IsEquality() && t.sentinelOperand(f, cur.Operands()) {
			return
		}
	}
	if t.valuesTouch(e.Operand(0).Value, e.Operand(1).Value) {
		t.mark(f, f.last, ev, touchValue, false)
	}
}

// check runs the touch rules of expression e that its operands decide before it runs.
func (t *tracer) check(f *frame, e *ast.Expr, ev *topdown.Event) {
	i := e.Index
	switch terms := e.Terms.(type) {
	case *ast.Term:
		v, tk := t.resolve(f, i, terms, ev)
		if v != nil && t.ph.is(v) {
			tk = touchValue
		}
		t.mark(f, i, ev, tk, true)
	case *ast.Every:
		v, tk := t.resolve(f, i, terms.Domain, ev)
		if v != nil && t.ph.is(v) {
			tk = touchValue
		}
		t.mark(f, i, ev, tk, true)
	case []*ast.Term:
		if e.IsEquality() {
			tk := touchNone
			for _, o := range e.Operands() {
				_, k := t.resolve(f, i, o, ev)
				tk = worse(tk, k)
			}
			t.mark(f, i, ev, tk, true)
			return
		}
		op := e.Operator()
		if op.HasPrefix(ast.DefaultRootRef) {
			if arity := t.g.rules.funcArity(op); arity >= 0 {
				t.startCall(f, e, ev, op, arity)
				return
			}
		}
		t.checkBuiltin(f, e, ev, op.String())
	}
}

var msgBuiltins = map[string]bool{
	ast.Sprintf.Name:     true,
	ast.Concat.Name:      true,
	ast.FormatInt.Name:   true,
	ast.JSONMarshal.Name: true,
}

func builtinArity(name string, n int) int {
	if bi, ok := ast.BuiltinMap[name]; ok && bi.Decl != nil {
		return len(bi.Decl.FuncArgs().Args)
	}
	return n
}

// nolint:gocyclo
func (t *tracer) checkBuiltin(f *frame, e *ast.Expr, ev *topdown.Event, name string) {
	i := e.Index
	operands := e.Operands()
	nargs := builtinArity(name, len(operands))
	vals := make([]ast.Value, len(operands))
	tk := touchNone
	for j, o := range operands {
		v, k := t.resolve(f, i, o, ev)
		vals[j] = v
		tk = worse(tk, k)
	}
	refTouch := tk
	switch name {
	case ast.Member.Name, ast.MemberWithKey.Name:
		if nargs <= len(vals) && !t.sentinelOperand(f, operands[:nargs-1]) && t.membershipTouch(vals[:nargs]) {
			tk = touchValue
		}
		for j := nargs; j < len(vals); j++ {
			if vals[j] != nil && ast.IsConstant(vals[j]) && t.ph.has(vals[j]) {
				tk = touchValue
			}
		}
	case ast.Equal.Name, ast.NotEqual.Name:
		if len(vals) >= 2 && vals[0] != nil && vals[1] != nil && !t.sentinelOperand(f, operands[:2]) &&
			t.valuesTouch(vals[0], vals[1]) {
			tk = touchValue
		}
		for j := 2; j < len(vals); j++ {
			tk = worse(tk, t.operandTouch(name, j, vals))
		}
	default:
		for j := range vals {
			if j >= nargs {
				// An output: compared only when already bound, at the first Eval.
				if vals[j] != nil && ast.IsConstant(vals[j]) && t.ph.has(vals[j]) {
					tk = touchValue
				}
				continue
			}
			tk = worse(tk, t.operandTouch(name, j, vals))
		}
	}
	if tk == touchValue && refTouch != touchValue && msgBuiltins[name] && t.g.flow.messageOnly(f.rule, frameRuleKind(f), e) {
		t.markMessage(f, i, ev)
		return
	}
	t.mark(f, i, ev, tk, true)
}

// sentinelOperand reports whether one of terms is a sentinel or a variable bound to one: the
// expression then tests whether a value is unknown.
func (t *tracer) sentinelOperand(f *frame, terms []*ast.Term) bool {
	for _, o := range terms {
		switch v := o.Value.(type) {
		case ast.Ref:
			if isSentinelRef(v, t.g.sentinels) {
				return true
			}
		case ast.Var:
			if t.g.sentinelVars[f.rule][v] {
				return true
			}
		}
	}
	return false
}

func frameRuleKind(f *frame) ruleKind {
	switch f.kind {
	case kindPolicy:
		return rulePolicy
	case kindFunc:
		return ruleFunc
	}
	return ruleVdoc
}

// membershipTouch applies the rule of `x in c` and `k, x in c`, given their input operands:
// an element of c may equal the needle, an unknown taking part.
func (t *tracer) membershipTouch(in []ast.Value) bool {
	if len(in) < 2 {
		return false
	}
	needle, coll := in[:len(in)-1], in[len(in)-1]
	if coll == nil {
		return false
	}
	if t.ph.is(coll) {
		return true
	}
	for _, v := range needle {
		if v == nil {
			return false
		}
	}
	touched := false
	visit := func(k, v ast.Value) {
		if touched {
			return
		}
		if len(needle) == 2 {
			touched = t.valuesTouch(ast.NewArray(ast.NewTerm(needle[0]), ast.NewTerm(needle[1])), ast.NewArray(ast.NewTerm(k), ast.NewTerm(v)))
			return
		}
		touched = t.valuesTouch(needle[0], v)
	}
	switch c := coll.(type) {
	case *ast.Array:
		for i := 0; i < c.Len(); i++ {
			visit(ast.InternedTerm(i).Value, c.Elem(i).Value)
		}
	case ast.Object:
		_ = c.Iter(func(k, v *ast.Term) error {
			visit(k.Value, v.Value)
			return nil
		})
	case ast.Set:
		_ = c.Iter(func(e *ast.Term) error {
			visit(e.Value, e.Value)
			return nil
		})
	}
	return touched
}

// operandTouch applies the operand rule of builtin name to its operand j.
func (t *tracer) operandTouch(name string, j int, vals []ast.Value) touchKind {
	v := vals[j]
	if v == nil {
		return touchNone
	}
	switch {
	case name == ast.ArrayConcat.Name:
		// The concatenated list is incomplete only when an operand is unknown or holds a
		// placeholder element; unknowns nested inside elements do not change membership.
		return t.arrayElementsTouch(v)
	case name == ast.ObjectGet.Name:
		return t.objectGetOperandTouch(j, vals)
	case name == ast.Print.Name, name == ast.Trace.Name, name == ast.InternalPrint.Name:
		return touchNone
	case t.shapeOnlyOperand(name, v):
		if t.ph.is(v) {
			return touchValue
		}
		return touchNone
	case t.stringInspectBuiltin(name) && (t.ph.has(v) || t.ph.hasText(v)):
		// Regex/contains see placeholders embedded by jsonencode; sprintf
		// and object.union must not, or message-only findings look uncertain.
		return touchValue
	case t.ph.has(v):
		return touchValue
	}
	return touchNone
}

func (t *tracer) stringInspectBuiltin(name string) bool {
	switch name {
	case ast.RegexMatch.Name, ast.RegexFindAllStringSubmatch.Name, ast.Contains.Name,
		ast.StartsWith.Name, ast.EndsWith.Name, ast.IndexOf.Name, ast.Replace.Name,
		ast.Split.Name, ast.Substring.Name:
		return true
	}
	return false
}

func (t *tracer) shapeOnlyOperand(name string, v ast.Value) bool {
	switch {
	case name == ast.Count.Name:
		switch v.(type) {
		case *ast.Array, ast.Object:
			return true
		}
	case strings.HasPrefix(name, "is_"), name == ast.TypeNameBuiltin.Name, name == ast.ObjectKeys.Name:
		return true
	}
	return false
}

func (t *tracer) objectGetOperandTouch(j int, vals []ast.Value) touchKind {
	v := vals[j]
	switch j {
	case 0:
		if len(vals) > 1 && vals[1] != nil && t.objectGetTouch(v, vals[1]) {
			return touchValue
		}
		return touchNone
	case 2:
		return touchNone
	}
	if t.ph.has(v) {
		return touchValue
	}
	return touchNone
}

// arrayElementsTouch reports whether an array.concat operand is unknown as a whole or holds
// a placeholder element (an incomplete relation list).
func (t *tracer) arrayElementsTouch(v ast.Value) touchKind {
	if t.ph.is(v) {
		return touchValue
	}
	a, ok := v.(*ast.Array)
	if !ok {
		if t.ph.has(v) {
			return touchValue
		}
		return touchNone
	}
	for i := 0; i < a.Len(); i++ {
		if t.ph.is(a.Elem(i).Value) {
			return touchValue
		}
	}
	return touchNone
}

// objectGetTouch reports whether object.get steps into an unknown before reaching the end of
// its path: the default it returns would then be chosen by chance.
func (t *tracer) objectGetTouch(obj, path ast.Value) bool {
	keys := []ast.Value{path}
	if a, ok := path.(*ast.Array); ok {
		keys = keys[:0]
		for i := 0; i < a.Len(); i++ {
			keys = append(keys, a.Elem(i).Value)
		}
	}
	cur := obj
	for _, k := range keys {
		if t.ph.is(cur) {
			return true
		}
		next, err := cur.Find(ast.Ref{ast.NewTerm(k)})
		if err != nil {
			return false
		}
		cur = next
	}
	return false
}

// startCall attaches the call state of a function call to expression e and compares its
// plugged arguments with every rule head.
func (t *tracer) startCall(f *frame, e *ast.Expr, ev *topdown.Event, op ast.Ref, arity int) {
	i := e.Index
	operands := e.Operands()
	args := make([]*ast.Term, 0, arity+1)
	args = append(args, ast.NewTerm(op))
	vals := make([]ast.Value, arity)
	tk := touchNone
	for j := 0; j < arity && j < len(operands); j++ {
		v, k := t.resolve(f, i, operands[j], ev)
		tk = worse(tk, k)
		vals[j] = v
		if v == nil {
			args = append(args, operands[j])
		} else {
			args = append(args, ast.NewTerm(v))
		}
	}
	key := ast.NewArray(args...)
	m := t.memo(f.scopeAt(i))
	cs, ok := m.calls.get(key)
	if !ok {
		cs = &callState{}
		m.calls.put(key, cs)
	}
	if f.calls == nil {
		f.calls = map[int]*callState{}
	}
	f.calls[i] = cs
	for _, r := range t.g.rules.rules(op) {
		for j := 0; j < arity && j < len(r.Head.Args); j++ {
			if vals[j] != nil && t.valuesTouch(vals[j], r.Head.Args[j].Value) {
				cs.touched = true
			}
		}
	}
	t.mark(f, i, ev, tk, true)
}

// post runs the checks that need the result of expression e: memoised calls and virtual
// documents it read.
// nolint:gocyclo
func (t *tracer) post(f *frame, e *ast.Expr, ev *topdown.Event, success bool) {
	i := e.Index
	if cs := f.calls[i]; cs != nil {
		site := t.g.flow.messageOnly(f.rule, frameRuleKind(f), e)
		var tainted bool
		if success {
			tainted = cs.tainted(site)
		} else {
			tainted = (cs.touched && !cs.cleanPrimary) || cs.msg
		}
		switch {
		case tainted:
			t.mark(f, i, ev, touchValue, false)
		case success && cs.msg:
			t.markMessage(f, i, ev)
		}
	}
	m := t.memo(f.scopeAt(i))
	for _, r := range f.iterRefs[i] {
		if m.docs.related(r) {
			t.mark(f, i, ev, touchSet, false)
		}
	}
	delete(f.iterRefs, i)
	if ts, ok := e.Terms.([]*ast.Term); ok && !e.IsEquality() {
		name := e.Operator().String()
		if name == ast.Member.Name || name == ast.MemberWithKey.Name {
			if t.memberTouch(f, e, ev, success) {
				t.mark(f, i, ev, touchValue, false)
			}
		}
		ts = ts[1:]
		for _, o := range ts {
			t.postRefs(f, e, o, ev, success, m)
		}
		return
	}
	switch terms := e.Terms.(type) {
	case *ast.Term:
		t.postRefs(f, e, terms, ev, success, m)
	case []*ast.Term:
		for _, o := range terms[1:] {
			t.postRefs(f, e, o, ev, success, m)
		}
	case *ast.Every:
		t.postRefs(f, e, terms.Domain, ev, success, m)
	}
}

// postRefs checks the virtual document refs of term, an operand of e, after e ran.
func (t *tracer) postRefs(f *frame, e *ast.Expr, term *ast.Term, ev *topdown.Event, success bool, m *scopeMemo) {
	walkShallowRefs(term, func(r ast.Ref) {
		if !r.HasPrefix(ast.DefaultRootRef) {
			return
		}
		p := t.plugRef(r, ev)
		root := docRoot(t.g.traced, p)
		if root == 0 {
			return
		}
		gp := p.GroundPrefix()
		tainted := false
		switch {
		case !success:
			tainted = m.docs.related(gp) || t.lookupTouch(m, gp)
		case len(gp) == len(p):
			if el := m.docs.element(p); el != nil {
				tainted = el.tainted()
			} else {
				tainted = m.docs.related(p) && !t.g.flow.memberOnly(e)
			}
		}
		if tainted {
			t.mark(f, e.Index, ev, touchValue, false)
		}
	})
}

// memberTouch checks `x in S` against the memo of a virtual set S, read directly or through a
// variable defined by `v = data...` and only used in membership tests.
func (t *tracer) memberTouch(f *frame, e *ast.Expr, ev *topdown.Event, success bool) bool {
	ops := e.Operands()
	coll := ops[len(ops)-1]
	if e.Operator().String() == ast.Member.Name {
		coll = ops[1]
	}
	var ref ast.Ref
	switch x := coll.Value.(type) {
	case ast.Ref:
		ref = t.plugRef(x, ev)
	case ast.Var:
		ref = t.g.flow.memberDoc(f.rule, x)
	}
	if ref == nil || !ref.IsGround() || !ref.HasPrefix(ast.DefaultRootRef) {
		return false
	}
	m := t.memo(f.scopeAt(e.Index))
	x := ev.Plug(ops[0])
	if e.Operator().String() != ast.Member.Name || !x.IsGround() || !t.g.isSetDoc(ref) {
		return m.docs.related(ref)
	}
	el := ref.Append(x)
	if success {
		if n := m.docs.element(el); n != nil {
			return n.tainted()
		}
		return m.docs.related(el)
	}
	return m.docs.related(el) || t.lookupTouch(m, el)
}

// with starts a new memo scope for an expression with `with` modifiers and records the input
// its children see.
func (t *tracer) with(f *frame, e *ast.Expr, ev *topdown.Event) {
	i := e.Index
	t.scopes = append(t.scopes, newScopeMemo())
	if f.withScope == nil {
		f.withScope = map[int]int{}
	}
	f.withScope[i] = len(t.scopes) - 1
	input := f.input
	overridden := false
	for _, w := range e.With {
		v, _ := t.resolve(f, i, w.Value, ev)
		if v == nil || t.ph.has(v) {
			// A mocked value that is unknown, or that the tracer cannot resolve.
			t.mark(f, i, ev, touchValue, true)
		}
		target, ok := w.Target.Value.(ast.Ref)
		if !ok || !target.HasPrefix(ast.InputRootRef) || v == nil {
			continue
		}
		input = setPath(input, target[1:], v)
		overridden = true
	}
	if overridden {
		if f.withInput == nil {
			f.withInput = map[int]ast.Value{}
		}
		f.withInput[i] = input
	}
}

func setPath(root ast.Value, path ast.Ref, v ast.Value) ast.Value {
	if len(path) == 0 {
		return v
	}
	out := ast.NewObject()
	var child ast.Value
	if obj, ok := root.(ast.Object); ok {
		_ = obj.Iter(func(k, x *ast.Term) error {
			if k.Value.Compare(path[0].Value) == 0 {
				child = x.Value
				return nil
			}
			out.Insert(k, x)
			return nil
		})
	}
	out.Insert(path[0], ast.NewTerm(setPath(child, path[1:], v)))
	return out
}

// resolve returns the value of term at expression i, or nil when it is unbound, with the
// touch its ref steps make.
func (t *tracer) resolve(f *frame, i int, term *ast.Term, ev *topdown.Event) (ast.Value, touchKind) {
	switch x := term.Value.(type) {
	case ast.Var:
		p := ev.Plug(term)
		if _, ok := p.Value.(ast.Var); ok {
			return nil, touchNone
		}
		return p.Value, touchNone
	case ast.Ref:
		return t.resolveRef(f, i, x, ev)
	case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension:
		return nil, touchNone
	}
	if term.IsGround() {
		return term.Value, touchNone
	}
	tk := touchNone
	walkShallowRefs(term, func(r ast.Ref) {
		_, k := t.resolveRef(f, i, r, ev)
		tk = worse(tk, k)
	})
	return ev.Plug(term).Value, tk
}

func (t *tracer) resolveRef(f *frame, i int, ref ast.Ref, ev *topdown.Event) (ast.Value, touchKind) {
	head := ref[0]
	var cur ast.Value
	switch {
	case head.Equal(ast.DefaultRootDocument):
		for j, k := range ref[1:] {
			kv := t.plugKey(k, ev)
			if kv == nil {
				if docRoot(t.g.traced, ref[:j+1]) > 0 {
					if f.iterRefs == nil {
						f.iterRefs = map[int][]ast.Ref{}
					}
					f.iterRefs[i] = append(f.iterRefs[i], t.plugRef(ref[:j+1], ev))
				}
				return nil, touchNone
			}
			if t.ph.has(kv) {
				return nil, touchValue
			}
		}
		return nil, touchNone
	case head.Equal(ast.InputRootDocument):
		cur = f.inputAt(i)
		if cur == nil {
			return nil, touchNone
		}
	default:
		p := ev.Plug(head)
		if _, ok := p.Value.(ast.Var); ok {
			return nil, touchNone
		}
		cur = p.Value
	}
	return t.walk(cur, ref[1:], ev)
}

// walk follows the steps of a ref from cur. Stepping into an unknown, or with a key that holds
// one, is a value touch; iterating an unknown is a set touch.
func (t *tracer) walk(cur ast.Value, steps ast.Ref, ev *topdown.Event) (ast.Value, touchKind) {
	for j, k := range steps {
		kv := t.plugKey(k, ev)
		if kv != nil && t.ph.has(kv) {
			return nil, touchValue
		}
		if t.ph.is(cur) {
			if kv == nil {
				return nil, touchSet
			}
			return nil, touchValue
		}
		if kv == nil {
			if j == len(steps)-1 {
				return nil, touchNone
			}
			tk := touchNone
			eachChild(cur, func(c ast.Value) {
				if tk != touchNone {
					return
				}
				if t.ph.is(c) {
					tk = touchSet
					return
				}
				if _, k := t.walk(c, steps[j+1:], ev); k != touchNone {
					tk = touchSet
				}
			})
			return nil, tk
		}
		next, err := cur.Find(ast.Ref{ast.NewTerm(kv)})
		if err != nil {
			return nil, touchNone
		}
		cur = next
	}
	return cur, touchNone
}

func eachChild(v ast.Value, fn func(ast.Value)) {
	switch x := v.(type) {
	case *ast.Array:
		for i := 0; i < x.Len(); i++ {
			fn(x.Elem(i).Value)
		}
	case ast.Object:
		_ = x.Iter(func(_, e *ast.Term) error {
			fn(e.Value)
			return nil
		})
	case ast.Set:
		_ = x.Iter(func(e *ast.Term) error {
			fn(e.Value)
			return nil
		})
	}
}

// plugKey returns the ground value of a ref key, or nil.
func (t *tracer) plugKey(k *ast.Term, ev *topdown.Event) ast.Value {
	if k.IsGround() {
		return k.Value
	}
	p := ev.Plug(k)
	if !p.IsGround() {
		return nil
	}
	return p.Value
}

func (t *tracer) plugRef(r ast.Ref, ev *topdown.Event) ast.Ref {
	out := make(ast.Ref, len(r))
	for i, k := range r {
		if i == 0 || k.IsGround() {
			out[i] = k
			continue
		}
		out[i] = ev.Plug(k)
	}
	return out
}

// walkShallowRefs calls fn on the refs in term, outside comprehension bodies (they run in
// child queries).
func walkShallowRefs(term *ast.Term, fn func(ast.Ref)) {
	vis := ast.NewGenericVisitor(func(x any) bool {
		switch v := x.(type) {
		case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension:
			return true
		case ast.Ref:
			fn(v)
			return false
		}
		return false
	})
	vis.Walk(term)
}

// valuesTouch reports whether comparing a and b depends on an unknown: they may be equal,
// and an unknown meets a term that is not a variable. Variables and unevaluated refs match
// anything.
func (t *tracer) valuesTouch(a, b ast.Value) bool {
	may, touch := t.compare(a, b)
	return may && touch
}

// compare reports whether a and b may be equal for some values of the unknowns, and whether
// an unknown takes part in the comparison.
// nolint:gocyclo
func (t *tracer) compare(a, b ast.Value) (may, touch bool) {
	if isOpen(a) || isOpen(b) {
		return true, false
	}
	if t.ph.is(a) || t.ph.is(b) {
		return true, true
	}
	// Strings that embed the placeholder (jsonencode / templates) are
	// unknown for equality even when not equal to the sentinel alone.
	// Only scalar strings: walking composites would taint message objects.
	if _, ok := a.(ast.String); ok {
		if t.ph.hasText(a) || t.ph.hasText(b) {
			return true, true
		}
	} else if _, ok := b.(ast.String); ok {
		if t.ph.hasText(a) || t.ph.hasText(b) {
			return true, true
		}
	}
	switch x := a.(type) {
	case *ast.Array:
		y, ok := b.(*ast.Array)
		if !ok {
			return false, false
		}
		if x.Len() != y.Len() {
			// An unknown element stands for any number of dynamic block instances.
			u := t.ph.has(x) || t.ph.has(y)
			return u, u
		}
		may = true
		for i := 0; i < x.Len() && may; i++ {
			m, tc := t.compare(x.Elem(i).Value, y.Elem(i).Value)
			may = may && m
			touch = touch || tc
		}
		return may, touch
	case ast.Object:
		y, ok := b.(ast.Object)
		if !ok {
			return false, false
		}
		u := t.ph.has(x) || t.ph.has(y)
		if x.Len() != y.Len() {
			return u, u
		}
		may = true
		_ = x.Iter(func(k, v *ast.Term) error {
			w := y.Get(k)
			if w == nil || t.ph.has(k.Value) {
				may, touch = u, u
				return errStop
			}
			m, tc := t.compare(v.Value, w.Value)
			may = may && m
			touch = touch || tc
			if !may {
				return errStop
			}
			return nil
		})
		return may, touch
	case ast.Set:
		if _, ok := b.(ast.Set); !ok {
			return false, false
		}
		if t.ph.has(a) || t.ph.has(b) {
			return true, true
		}
		return true, false
	}
	return a.Compare(b) == 0, false
}

func isOpen(v ast.Value) bool {
	switch v.(type) {
	case ast.Var, ast.Ref, *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension, ast.Call:
		return true
	}
	return false
}
