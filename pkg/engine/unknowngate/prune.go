package unknowngate

import (
	"github.com/open-policy-agent/opa/v1/ast"
)

// comparisonConstants returns the scalar constants of rules that appear in an
// equality, inequality or membership comparison against a value that may hold
// the placeholder. Constants that only appear as object-literal keys (result
// fields, type-name maps) or that are never compared with an input-derived
// value are left out: substituting them cannot remove a result.
func comparisonConstants(rules []*ast.Rule, cr *compiledRules) []ast.Value {
	a := newPruneAnalyzer(rules, cr)
	a.analyze()
	return a.kept()
}

type pruneAnalyzer struct {
	rules []*ast.Rule
	cr    *compiledRules
	// mu[r][v]: v may hold an unknown in rule r.
	mu map[*ast.Rule]map[ast.Var]bool
	// elems[r][v]: ground scalars that v may take in rule r.
	elems map[*ast.Rule]map[ast.Var]*valueSet
	// paramMU[path][i]: argument i of the function at path may be unknown.
	paramMU map[string][]bool
	// paramElems[path][i]: ground scalars argument i may take across call sites.
	paramElems map[string][]*valueSet
	// inputDerived[path]: the rule at path reads input (directly or through
	// another input-derived rule). Its call results may hold unknowns even
	// when every argument is ground — tf.blocks / tf.json are the usual case.
	inputDerived map[string]bool
	keep         *valueSet
}

func newPruneAnalyzer(rules []*ast.Rule, cr *compiledRules) *pruneAnalyzer {
	return &pruneAnalyzer{
		rules:        rules,
		cr:           cr,
		mu:           map[*ast.Rule]map[ast.Var]bool{},
		elems:        map[*ast.Rule]map[ast.Var]*valueSet{},
		paramMU:      map[string][]bool{},
		paramElems:   map[string][]*valueSet{},
		inputDerived: map[string]bool{},
		keep:         newValueSet(),
	}
}

func (a *pruneAnalyzer) analyze() {
	a.markInputDerived()
	for {
		changed := false
		for _, r := range a.rules {
			if a.seedArgs(r) {
				changed = true
			}
			for _, e := range r.Body {
				if a.propagate(r, e) {
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	for _, r := range a.rules {
		for _, e := range r.Body {
			a.scan(r, e)
		}
	}
}

// markInputDerived is a fixed point over every indexed rule path: a path is
// input-derived when any of its rules reads input, or reads/calls another
// input-derived path. Without this, tf.blocks("t") looks ground and the
// unknown inside tf.json never reaches is_equal(..., "false").
func (a *pruneAnalyzer) markInputDerived() {
	for {
		changed := false
		for path, rules := range a.cr.byPath {
			if a.inputDerived[path] {
				continue
			}
			for _, r := range rules {
				if a.ruleReadsInput(r) {
					a.inputDerived[path] = true
					changed = true
					break
				}
			}
		}
		if !changed {
			return
		}
	}
}

func (a *pruneAnalyzer) ruleReadsInput(r *ast.Rule) bool {
	found := false
	ast.WalkRefs(r, func(ref ast.Ref) bool {
		if found {
			return true
		}
		if ref.HasPrefix(ast.InputRootRef) {
			found = true
			return true
		}
		if ref.HasPrefix(ast.DefaultRootRef) && a.inputDerived[ref.GroundPrefix().String()] {
			found = true
			return true
		}
		return false
	})
	if found {
		return true
	}
	// Else-chain and head value (virtual docs like _dd := input._dd).
	if r.Head != nil && r.Head.Value != nil {
		ast.WalkRefs(r.Head.Value, func(ref ast.Ref) bool {
			if found {
				return true
			}
			if ref.HasPrefix(ast.InputRootRef) {
				found = true
				return true
			}
			if ref.HasPrefix(ast.DefaultRootRef) && a.inputDerived[ref.GroundPrefix().String()] {
				found = true
				return true
			}
			return false
		})
	}
	return found
}

func (a *pruneAnalyzer) callReturnsMU(op ast.Ref) bool {
	return op.HasPrefix(ast.DefaultRootRef) && a.inputDerived[op.GroundPrefix().String()]
}

func (a *pruneAnalyzer) kept() []ast.Value {
	var out []ast.Value
	for _, bucket := range a.keep.m {
		out = append(out, bucket...)
	}
	return out
}

func (a *pruneAnalyzer) seedArgs(r *ast.Rule) bool {
	path := r.Ref().GroundPrefix().String()
	pm := a.paramMU[path]
	pe := a.paramElems[path]
	changed := false
	for i, arg := range r.Head.Args {
		v, ok := arg.Value.(ast.Var)
		if !ok {
			continue
		}
		if i < len(pm) && pm[i] {
			changed = a.markMU(r, v) || changed
		}
		if i < len(pe) && pe[i] != nil {
			changed = a.addElems(r, v, setValues(pe[i])) || changed
		}
	}
	return changed
}

func (a *pruneAnalyzer) markMU(r *ast.Rule, v ast.Var) bool {
	m := a.mu[r]
	if m == nil {
		m = map[ast.Var]bool{}
		a.mu[r] = m
	}
	if m[v] {
		return false
	}
	m[v] = true
	return true
}

func (a *pruneAnalyzer) addElems(r *ast.Rule, v ast.Var, vals []ast.Value) bool {
	if len(vals) == 0 {
		return false
	}
	m := a.elems[r]
	if m == nil {
		m = map[ast.Var]*valueSet{}
		a.elems[r] = m
	}
	set := m[v]
	if set == nil {
		set = newValueSet()
		m[v] = set
	}
	changed := false
	for _, x := range vals {
		if ast.IsScalar(x) && set.add(x) {
			changed = true
		}
	}
	return changed
}

func (a *pruneAnalyzer) markParam(ref ast.Ref, i int) bool {
	n := a.cr.funcArity(ref)
	if n < 0 || i < 0 || i >= n {
		return false
	}
	key := ref.String()
	pm := a.paramMU[key]
	if pm == nil {
		pm = make([]bool, n)
		a.paramMU[key] = pm
	}
	if pm[i] {
		return false
	}
	pm[i] = true
	return true
}

func (a *pruneAnalyzer) addParamElems(ref ast.Ref, i int, vals []ast.Value) bool {
	n := a.cr.funcArity(ref)
	if n < 0 || i < 0 || i >= n || len(vals) == 0 {
		return false
	}
	key := ref.String()
	pe := a.paramElems[key]
	if pe == nil {
		pe = make([]*valueSet, n)
		a.paramElems[key] = pe
	}
	if pe[i] == nil {
		pe[i] = newValueSet()
	}
	changed := false
	for _, v := range vals {
		if ast.IsScalar(v) && pe[i].add(v) {
			changed = true
		}
	}
	return changed
}

// nolint:gocyclo
func (a *pruneAnalyzer) propagate(r *ast.Rule, e *ast.Expr) bool {
	if e.Negated {
		// A negated call still passes arguments to callees.
		if e.IsCall() && !e.IsEquality() {
			return a.propagateCall(r, e)
		}
		return false
	}
	if len(e.With) > 0 {
		return false
	}
	if e.IsEquality() {
		return a.propagateEq(r, e.Operand(0), e.Operand(1))
	}
	if e.IsCall() {
		return a.propagateCall(r, e)
	}
	return false
}

func (a *pruneAnalyzer) propagateEq(r *ast.Rule, lhs, rhs *ast.Term) bool {
	changed := false
	if a.termMU(r, rhs) {
		changed = a.bindVar(r, lhs) || changed
	}
	if a.termMU(r, lhs) {
		changed = a.bindVar(r, rhs) || changed
	}
	if vals := a.termScalars(r, rhs); len(vals) > 0 {
		changed = a.bindElems(r, lhs, vals) || changed
	}
	if vals := a.termScalars(r, lhs); len(vals) > 0 {
		changed = a.bindElems(r, rhs, vals) || changed
	}
	changed = a.propagateRefAssign(r, lhs, rhs) || changed
	changed = a.propagateRefAssign(r, rhs, lhs) || changed
	changed = a.propagateCallAssign(r, lhs, rhs) || changed
	changed = a.propagateCallAssign(r, rhs, lhs) || changed
	return changed
}

// propagateCallAssign handles `v = f(...)` when the result may hold an
// unknown: either an argument may, or f itself reads input (tf.blocks /
// tf.json). Later comparisons then keep their constants.
func (a *pruneAnalyzer) propagateCallAssign(r *ast.Rule, dst, src *ast.Term) bool {
	call, ok := src.Value.(ast.Call)
	if !ok || len(call) == 0 {
		return false
	}
	op, ok := call[0].Value.(ast.Ref)
	if !ok {
		return false
	}
	anyMU := a.callReturnsMU(op)
	for _, arg := range call[1:] {
		if a.termMU(r, arg) {
			anyMU = true
			break
		}
	}
	if !anyMU {
		return false
	}
	if op.HasPrefix(ast.DefaultRootRef) {
		n := a.cr.funcArity(op)
		for i := 0; i < n && i+1 < len(call); i++ {
			if a.termMU(r, call[i+1]) {
				_ = a.markParam(op, i)
			}
			if vals := a.termScalars(r, call[i+1]); len(vals) > 0 {
				_ = a.addParamElems(op, i, vals)
			}
		}
	}
	return a.bindVar(r, dst)
}

// propagateRefAssign handles `v = ref` after the compiler rewrote iteration and
// field access into equality with a ref.
func (a *pruneAnalyzer) propagateRefAssign(r *ast.Rule, dst, src *ast.Term) bool {
	v, ok := dst.Value.(ast.Var)
	ref, isRef := src.Value.(ast.Ref)
	if !ok || !isRef || len(ref) == 0 || metaTypeOrKind(ref) {
		return false
	}
	if ref.HasPrefix(ast.InputRootRef) {
		return a.markMU(r, v) || a.markRefKeyVars(r, ref)
	}
	if ref.HasPrefix(ast.DefaultRootRef) {
		return a.propagateDataRef(r, v, ref)
	}
	return a.propagateLocalRef(r, v, ref)
}

func (a *pruneAnalyzer) propagateDataRef(r *ast.Rule, v ast.Var, ref ast.Ref) bool {
	vals := a.dataDocScalars(ref)
	if len(vals) == 0 {
		return false
	}
	changed := a.addElems(r, v, vals)
	if kv, ok := ref[len(ref)-1].Value.(ast.Var); ok {
		changed = a.addElems(r, kv, vals) || changed
	}
	return changed
}

func (a *pruneAnalyzer) propagateLocalRef(r *ast.Rule, v ast.Var, ref ast.Ref) bool {
	head, ok := ref[0].Value.(ast.Var)
	if !ok {
		return false
	}
	changed := false
	if a.mu[r][head] {
		changed = a.markMU(r, v) || a.markRefKeyVars(r, ref)
	}
	if len(ref) == 2 {
		if _, isVar := ref[1].Value.(ast.Var); isVar {
			changed = a.addElems(r, v, a.elemList(r, head)) || changed
		}
	}
	return changed
}

func (a *pruneAnalyzer) markRefKeyVars(r *ast.Rule, ref ast.Ref) bool {
	changed := false
	for _, t := range ref[1:] {
		if v, ok := t.Value.(ast.Var); ok {
			changed = a.markMU(r, v) || changed
		}
	}
	return changed
}

// nolint:gocyclo
func (a *pruneAnalyzer) propagateCall(r *ast.Rule, e *ast.Expr) bool {
	op := e.Operator()
	name := op.String()
	ops := e.Operands()
	changed := false
	switch name {
	case ast.ObjectKeys.Name:
		if len(ops) >= 2 {
			if vals := a.objectKeyScalars(r, ops[0]); len(vals) > 0 {
				changed = a.bindElems(r, ops[1], vals) || changed
			}
			if a.termMU(r, ops[0]) {
				changed = a.bindVar(r, ops[1]) || changed
			}
		}
	case ast.Lower.Name, ast.Upper.Name, ast.Trim.Name, ast.ToNumber.Name,
		ast.TrimLeft.Name, ast.TrimRight.Name, ast.TrimPrefix.Name, ast.TrimSuffix.Name:
		if len(ops) >= 2 {
			if a.termMU(r, ops[0]) {
				changed = a.bindVar(r, ops[1]) || changed
			}
			if vals := a.termScalars(r, ops[0]); len(vals) > 0 {
				changed = a.bindElems(r, ops[1], vals) || changed
			}
		}
	case ast.Member.Name:
		if len(ops) >= 2 {
			if vals := a.termScalars(r, ops[1]); len(vals) > 0 {
				changed = a.bindElems(r, ops[0], vals) || changed
			}
			if a.termMU(r, ops[1]) {
				changed = a.bindVar(r, ops[0]) || changed
			}
		}
	case ast.MemberWithKey.Name:
		if len(ops) >= 3 {
			if vals := a.termScalars(r, ops[2]); len(vals) > 0 {
				changed = a.bindElems(r, ops[0], vals) || changed
				changed = a.bindElems(r, ops[1], vals) || changed
			}
			if a.termMU(r, ops[2]) {
				changed = a.bindVar(r, ops[0]) || changed
				changed = a.bindVar(r, ops[1]) || changed
			}
		}
	}
	if op.HasPrefix(ast.DefaultRootRef) {
		n := a.cr.funcArity(op)
		if n >= 0 {
			anyMU := a.callReturnsMU(op)
			for i := 0; i < n && i < len(ops); i++ {
				if a.termMU(r, ops[i]) {
					anyMU = true
					changed = a.markParam(op, i) || changed
				}
				if vals := a.termScalars(r, ops[i]); len(vals) > 0 {
					changed = a.addParamElems(op, i, vals) || changed
				}
			}
			// A function that receives or produces an unknown may return one;
			// bind the output operand when present (f(x, out) form).
			if anyMU && n < len(ops) {
				changed = a.bindVar(r, ops[n]) || changed
			}
		}
	}
	return changed
}

func (a *pruneAnalyzer) bindVar(r *ast.Rule, t *ast.Term) bool {
	v, ok := t.Value.(ast.Var)
	if !ok {
		return false
	}
	return a.markMU(r, v)
}

func (a *pruneAnalyzer) bindElems(r *ast.Rule, t *ast.Term, vals []ast.Value) bool {
	v, ok := t.Value.(ast.Var)
	if !ok {
		return false
	}
	return a.addElems(r, v, vals)
}

func (a *pruneAnalyzer) termMU(r *ast.Rule, t *ast.Term) bool {
	if t == nil {
		return false
	}
	switch v := t.Value.(type) {
	case ast.Var:
		return a.mu[r][v]
	case ast.Ref:
		if metaTypeOrKind(v) {
			return false
		}
		if v.HasPrefix(ast.InputRootRef) {
			return true
		}
		if v.HasPrefix(ast.DefaultRootRef) && a.inputDerived[v.GroundPrefix().String()] {
			return true
		}
		if head, ok := v[0].Value.(ast.Var); ok {
			return a.mu[r][head]
		}
	case ast.Call:
		if len(v) == 0 {
			return false
		}
		op, ok := v[0].Value.(ast.Ref)
		return ok && a.callReturnsMU(op)
	}
	return false
}

func metaTypeOrKind(ref ast.Ref) bool {
	if len(ref) < 2 {
		return false
	}
	field, ok := ref[len(ref)-1].Value.(ast.String)
	if !ok || (field != "type" && field != "kind") {
		return false
	}
	meta, ok := ref[len(ref)-2].Value.(ast.String)
	return ok && meta == "_dd_meta"
}

func (a *pruneAnalyzer) termScalars(r *ast.Rule, t *ast.Term) []ast.Value {
	if t == nil {
		return nil
	}
	switch v := t.Value.(type) {
	case ast.String, ast.Number, ast.Boolean:
		return []ast.Value{v}
	case ast.Var:
		return a.elemList(r, v)
	case *ast.Array, ast.Set, ast.Object:
		return collectionScalarValues(v)
	case ast.Ref:
		return a.dataDocScalars(v)
	}
	return nil
}

func (a *pruneAnalyzer) dataDocScalars(ref ast.Ref) []ast.Value {
	if !ref.HasPrefix(ast.DefaultRootRef) {
		return nil
	}
	if vals := a.groundDocScalars(ref.GroundPrefix()); len(vals) > 0 {
		return vals
	}
	if len(ref) > 1 {
		return a.groundDocScalars(ref[:len(ref)-1].GroundPrefix())
	}
	return nil
}

func (a *pruneAnalyzer) groundDocScalars(prefix ast.Ref) []ast.Value {
	for _, rule := range a.cr.rules(prefix) {
		if groundRuleValue(rule) {
			return collectionScalarValues(rule.Head.Value.Value)
		}
	}
	return nil
}

func groundRuleValue(r *ast.Rule) bool {
	if r.Head.Value == nil || !ast.IsConstant(r.Head.Value.Value) {
		return false
	}
	for _, e := range r.Body {
		if e.Negated || len(e.With) > 0 {
			return false
		}
		if b, ok := e.Terms.(*ast.Term); ok {
			if bv, ok := b.Value.(ast.Boolean); ok && bool(bv) {
				continue
			}
		}
		return false
	}
	return true
}

func (a *pruneAnalyzer) objectKeyScalars(r *ast.Rule, t *ast.Term) []ast.Value {
	switch v := t.Value.(type) {
	case ast.Object:
		return objectKeys(v)
	case ast.Var:
		return a.objectKeysOfVar(r, v)
	case ast.Ref:
		return a.objectKeysOfRef(v)
	}
	return nil
}

func (a *pruneAnalyzer) objectKeysOfVar(r *ast.Rule, v ast.Var) []ast.Value {
	for _, e := range r.Body {
		if !e.IsEquality() || e.Negated {
			continue
		}
		other := a.eqOther(e, v)
		if other == nil {
			continue
		}
		if ref, ok := other.Value.(ast.Ref); ok {
			if keys := a.objectKeysOfRef(ref); len(keys) > 0 {
				return keys
			}
		}
		if obj, ok := other.Value.(ast.Object); ok {
			return objectKeys(obj)
		}
	}
	return nil
}

func (a *pruneAnalyzer) eqOther(e *ast.Expr, v ast.Var) *ast.Term {
	lhs, rhs := e.Operand(0), e.Operand(1)
	if lv, ok := lhs.Value.(ast.Var); ok && lv == v {
		return rhs
	}
	if rv, ok := rhs.Value.(ast.Var); ok && rv == v {
		return lhs
	}
	return nil
}

func (a *pruneAnalyzer) objectKeysOfRef(ref ast.Ref) []ast.Value {
	for _, rule := range a.cr.rules(ref.GroundPrefix()) {
		if groundRuleValue(rule) {
			if obj, ok := rule.Head.Value.Value.(ast.Object); ok {
				return objectKeys(obj)
			}
		}
	}
	return nil
}

func objectKeys(obj ast.Object) []ast.Value {
	var out []ast.Value
	_ = obj.Iter(func(k, _ *ast.Term) error {
		if ast.IsScalar(k.Value) {
			out = append(out, k.Value)
		}
		return nil
	})
	return out
}

func (a *pruneAnalyzer) elemList(r *ast.Rule, v ast.Var) []ast.Value {
	return setValues(a.elems[r][v])
}

func setValues(set *valueSet) []ast.Value {
	if set == nil {
		return nil
	}
	var out []ast.Value
	for _, bucket := range set.m {
		out = append(out, bucket...)
	}
	return out
}

func collectionScalarValues(v ast.Value) []ast.Value {
	var out []ast.Value
	switch x := v.(type) {
	case *ast.Array:
		for i := 0; i < x.Len(); i++ {
			if ast.IsScalar(x.Elem(i).Value) {
				out = append(out, x.Elem(i).Value)
			}
		}
	case ast.Set:
		_ = x.Iter(func(e *ast.Term) error {
			if ast.IsScalar(e.Value) {
				out = append(out, e.Value)
			}
			return nil
		})
	case ast.Object:
		_ = x.Iter(func(k, e *ast.Term) error {
			if ast.IsScalar(k.Value) {
				out = append(out, k.Value)
			}
			if ast.IsScalar(e.Value) {
				out = append(out, e.Value)
			}
			return nil
		})
	case ast.String, ast.Number, ast.Boolean:
		out = append(out, x)
	}
	return out
}

var compareOps = map[string]bool{
	ast.Equal.Name:         true,
	ast.NotEqual.Name:      true,
	ast.LessThan.Name:      true,
	ast.LessThanEq.Name:    true,
	ast.GreaterThan.Name:   true,
	ast.GreaterThanEq.Name: true,
	ast.Equality.Name:      true,
}

func (a *pruneAnalyzer) scan(r *ast.Rule, e *ast.Expr) {
	if len(e.With) > 0 {
		return
	}
	if e.IsEquality() {
		a.keepCompared(r, e.Operand(0), e.Operand(1))
		return
	}
	if !e.IsCall() {
		return
	}
	name := e.Operator().String()
	ops := e.Operands()
	switch {
	case compareOps[name]:
		if len(ops) >= 2 {
			a.keepCompared(r, ops[0], ops[1])
		}
	case name == ast.Member.Name:
		if len(ops) >= 2 {
			a.keepMember(r, ops[0], ops[1])
		}
	case name == ast.MemberWithKey.Name:
		if len(ops) >= 3 {
			a.keepMember(r, ops[0], ops[2])
			a.keepMember(r, ops[1], ops[2])
		}
	default:
		// Predicate helpers such as is_equal(x, "false"): keep scalar
		// operands when any other operand may hold an unknown.
		anyMU := false
		for _, op := range ops {
			if a.termMU(r, op) {
				anyMU = true
				break
			}
		}
		if anyMU {
			for _, op := range ops {
				a.keepAll(a.termScalars(r, op))
			}
		}
	}
}

func (a *pruneAnalyzer) keepCompared(r *ast.Rule, x, y *ast.Term) {
	if a.termMU(r, x) {
		a.keepAll(a.termScalars(r, y))
	}
	if a.termMU(r, y) {
		a.keepAll(a.termScalars(r, x))
	}
}

func (a *pruneAnalyzer) keepMember(r *ast.Rule, needle, coll *ast.Term) {
	if a.termMU(r, needle) {
		a.keepAll(a.termScalars(r, coll))
	}
	if a.termMU(r, coll) {
		a.keepAll(a.termScalars(r, needle))
	}
}

func (a *pruneAnalyzer) keepAll(vals []ast.Value) {
	for _, v := range vals {
		if ast.IsScalar(v) {
			a.keep.add(v)
		}
	}
}
