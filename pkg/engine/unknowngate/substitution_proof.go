package unknowngate

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// traceProvesObjectValueSubstitutions avoids counterfactual evaluations only when
// the entire trace observed no unknown-sensitive operation, including failed
// derivations. This is stronger than finding one clean derivation: a touched
// alternative could become a conflicting function or document definition.
//
// An individual object-value substitution keeps its enclosing collection
// shape. Other structural placeholders stay unchanged in that confirmation.
// Placeholder keys and sets (including derived ones), sentinel exemptions,
// and unknown result identities prevent the proof. Structural substitutions
// additionally require that the trace observed no array shape or index read.
func traceProvesObjectValueSubstitutions(st *resultState, c Candidate, input ast.Value, ph *placeholder) bool {
	id, _ := ph.identity(c.Result)
	if ph.has(id) || ph.hasText(id) {
		return false
	}
	if st.sentinelRead || st.substitutionSensitive || len(c.Scope) == 0 {
		return false
	}
	if unstableCompositeShape(input, ph) {
		return false
	}
	return true
}

// onlyObjectValueUnknowns lets the object-value proof skip all of stage 2
// without a structural proof. Mixed scopes retain the structural checks.
func onlyObjectValueUnknowns(c Candidate, input ast.Value, ph *placeholder) bool {
	for _, scope := range scopesOf(c, input) {
		if !objectValueUnknowns(scope, parentNone, ph) {
			return false
		}
	}
	return true
}
func objectValueUnknowns(v ast.Value, parent parentKind, ph *placeholder) bool {
	if ph.is(v) {
		return parent == parentObject
	}
	if !ph.has(v) {
		return true
	}
	switch x := v.(type) {
	case *ast.Array:
		for i := 0; i < x.Len(); i++ {
			if !objectValueUnknowns(x.Elem(i).Value, parentArray, ph) {
				return false
			}
		}
	case ast.Object:
		ok := true
		_ = x.Iter(func(k, e *ast.Term) error {
			if ph.has(k.Value) || !objectValueUnknowns(e.Value, parentObject, ph) {
				ok = false
				return errStop
			}
			return nil
		})
		return ok
	case ast.Set:
		return false
	}
	return true
}

// unstableCompositeShape finds unknown keys or sets whose cardinality can
// change even when the substituted placeholder is an object value.
func unstableCompositeShape(v ast.Value, ph *placeholder) bool {
	return compositeShapeHazard(v, ph, nil)
}

// compositeShapeHazard shares the same conservative shape test between the
// initial input and intermediate traced values. The optional cache belongs to
// one trace; AST values are immutable during evaluation.
func compositeShapeHazard(v ast.Value, ph *placeholder, cache map[ast.Value]bool) bool {
	if !ph.has(v) {
		return false
	}
	switch v.(type) {
	case *ast.Array, ast.Object, ast.Set:
	default:
		return false
	}
	if found, ok := cache[v]; ok {
		return found
	}
	found := false
	switch x := v.(type) {
	case ast.Set:
		found = true
	case *ast.Array:
		for i := 0; i < x.Len(); i++ {
			if compositeShapeHazard(x.Elem(i).Value, ph, cache) {
				found = true
				break
			}
		}
	case ast.Object:
		_ = x.Iter(func(k, e *ast.Term) error {
			if ph.has(k.Value) || compositeShapeHazard(e.Value, ph, cache) {
				found = true
				return errStop
			}
			return nil
		})
	}
	if cache != nil {
		cache[v] = found
	}
	return found
}

// directArrayUnknown detects a dynamic element whose removal or expansion
// changes the array length and subsequent indexes.
func (t *tracer) directArrayUnknown(v ast.Value) bool {
	a, ok := v.(*ast.Array)
	if !ok {
		return false
	}
	for i := 0; i < a.Len(); i++ {
		if t.ph.is(a.Elem(i).Value) {
			return true
		}
	}
	return false
}

// structuralUnknown includes nested arrays: whole-value comparisons and
// builtins may observe the shape of any contained collection.
func (t *tracer) structuralUnknown(v ast.Value) bool {
	if v == nil || !t.ph.has(v) {
		return false
	}
	switch x := v.(type) {
	case *ast.Array:
		if t.directArrayUnknown(x) {
			return true
		}
		for i := 0; i < x.Len(); i++ {
			if t.structuralUnknown(x.Elem(i).Value) {
				return true
			}
		}
	case ast.Object:
		found := false
		_ = x.Iter(func(k, e *ast.Term) error {
			if t.structuralUnknown(k.Value) || t.structuralUnknown(e.Value) {
				found = true
				return errStop
			}
			return nil
		})
		return found
	case ast.Set:
		return true
	}
	return false
}

// checkStructuralBuiltin tracks observations that scalar-value taint omits.
// Type tests and object keys remain stable; object.get observes only its path.
func (t *tracer) checkStructuralBuiltin(name string, vals []ast.Value, nargs int) {
	if t.structuralSensitive {
		return
	}
	switch {
	case name == ast.ObjectGet.Name:
		t.checkStructuralObjectGet(vals)
		return
	case strings.HasPrefix(name, "is_"), name == ast.TypeNameBuiltin.Name, name == ast.ObjectKeys.Name,
		name == ast.Print.Name, name == ast.Trace.Name, name == ast.InternalPrint.Name:
		return
	case name == ast.Count.Name:
		if len(vals) > 0 && t.directArrayUnknown(vals[0]) {
			t.structuralSensitive = true
		}
		return
	}
	for i, v := range vals {
		if i >= nargs {
			break
		}
		if t.structuralUnknown(v) {
			t.structuralSensitive = true
			return
		}
	}
}

func (t *tracer) checkStructuralObjectGet(vals []ast.Value) {
	if len(vals) < 2 || vals[0] == nil || vals[1] == nil {
		return
	}
	keys := []ast.Value{vals[1]}
	if a, ok := vals[1].(*ast.Array); ok {
		keys = nil
		for i := 0; i < a.Len(); i++ {
			keys = append(keys, a.Elem(i).Value)
		}
	}
	cur := vals[0]
	for _, key := range keys {
		if t.directArrayUnknown(cur) {
			t.structuralSensitive = true
			return
		}
		next, err := cur.Find(ast.Ref{ast.NewTerm(key)})
		if err != nil {
			return
		}
		cur = next
	}
}
