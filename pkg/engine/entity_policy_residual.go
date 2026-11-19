/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import "github.com/open-policy-agent/opa/v1/ast"

type entityFactGroup struct {
	good, constant bool
	ref            ast.Ref
}

// Only zero-argument Boolean support predicates with an unconditional true
// definition can be folded. Ownership checks include every original module.
func entitySupportFacts(modules []*ast.Module, owners []ast.Ref) map[string]bool {
	groups := map[string]*entityFactGroup{}
	roots := []ast.Ref{}
	for _, m := range modules {
		for _, r := range m.Rules {
			ref := append(m.Package.Path.Copy(), ast.StringTerm(string(r.Head.Name)))
			roots = append(roots, ref)
			key := ref.String()
			g := groups[key]
			if g == nil {
				g = &entityFactGroup{good: true, ref: ref}
				groups[key] = g
			}
			if !entityBooleanRule(r) {
				g.good = false
				continue
			}
			g.constant = g.constant || entityUnconditionalTrue(r.Body)
		}
	}
	facts := map[string]bool{}
	for key, g := range groups {
		if g.good && g.constant && entityFactOwned(g.ref, roots, owners) {
			facts[key] = true
		}
	}
	return facts
}
func entityBooleanRule(r *ast.Rule) bool {
	if r.Default || r.Else != nil || len(r.Head.Args) > 0 || r.Head.Key != nil {
		return false
	}
	return r.Head.Value != nil && r.Head.Value.Equal(ast.BooleanTerm(true)) && len(r.Head.Ref()) == 1
}
func entityUnconditionalTrue(body ast.Body) bool {
	for _, e := range body {
		term, ok := e.Terms.(*ast.Term)
		if !ok || len(e.With) > 0 {
			return false
		}
		value, ok := term.Value.(ast.Boolean)
		if !ok || bool(value) == e.Negated {
			return false
		}
	}
	return true
}
func entityFactOwned(ref ast.Ref, roots, owners []ast.Ref) bool {
	for _, other := range roots {
		if !other.Equal(ref) && other.HasPrefix(ref) {
			return false
		}
	}
	for _, other := range owners {
		if other.HasPrefix(ref) || ref.HasPrefix(other) {
			return false
		}
	}
	return true
}

// simplifyEntitySupportQuery changes only standalone predicate atoms and Boolean
// literals in query bodies. Support bodies, comparisons, calls and with scopes
// remain untouched. The OR of residual queries drops only literal-false bodies.
func simplifyEntitySupportQuery(body ast.Body, facts map[string]bool) (ast.Body, bool) {
	var out ast.Body
	for _, e := range body {
		if len(e.With) > 0 {
			out = append(out, e)
			continue
		}
		t, ok := e.Terms.(*ast.Term)
		if !ok {
			out = append(out, e)
			continue
		}
		var truth bool
		switch value := t.Value.(type) {
		case ast.Boolean:
			truth = bool(value)
		case ast.Ref:
			if !facts[value.String()] {
				out = append(out, e)
				continue
			}
			truth = true
		default:
			out = append(out, e)
			continue
		}
		if e.Negated {
			truth = !truth
		}
		if !truth {
			return nil, true
		}
	}
	return out, false
}

const maxEntityResidualAtoms = 64

type entityEquality struct {
	left, right *ast.Term
	negative    bool
}
type entityResidualAtom struct {
	equality     *entityEquality
	falseLiteral bool
}

// Exact complements only; no symbolic solver or support-body rewriting. Work
// is bounded and unsupported atoms leave the residual indeterminate.
func entityStaticContradiction(body ast.Body) bool {
	if len(body) > maxEntityResidualAtoms {
		return false
	}
	equalities := []entityEquality{}
	literalFalse := false
	for _, e := range body {
		atom, ok := parseEntityResidualAtom(e)
		if !ok {
			return false
		}
		literalFalse = literalFalse || atom.falseLiteral
		if atom.equality != nil {
			equalities = append(equalities, *atom.equality)
		}
	}
	if literalFalse {
		return true
	}
	for i, left := range equalities {
		for _, right := range equalities[i+1:] {
			if entityEqualitiesOppose(left, right) {
				return true
			}
		}
	}
	return false
}
func parseEntityResidualAtom(e *ast.Expr) (entityResidualAtom, bool) {
	if len(e.With) > 0 {
		return entityResidualAtom{}, false
	}
	terms, ok := e.Terms.([]*ast.Term)
	if !ok || len(terms) != 3 {
		return entityResidualAtom{}, false
	}
	equality := e.IsEquality() || e.Operator().Equal(ast.Equal.Ref())
	if !equality && !e.Operator().Equal(ast.NotEqual.Ref()) {
		return entityResidualAtom{}, false
	}
	if !entityStaticTerm(terms[1]) || !entityStaticTerm(terms[2]) {
		return entityResidualAtom{}, false
	}
	atom := entityResidualAtom{falseLiteral: entityLiteralFalse(terms[1], terms[2], equality, e.Negated)}
	if equality {
		atom.equality = &entityEquality{left: terms[1], right: terms[2], negative: e.Negated}
	}
	return atom, true
}
func entityStaticTerm(t *ast.Term) bool {
	switch value := t.Value.(type) {
	case ast.Null, ast.Boolean, ast.String, ast.Number:
		return true
	case ast.Ref:
		if len(value) < 3 || !value[0].Equal(ast.VarTerm("input")) || !value[1].Equal(ast.StringTerm("__dd_symbols")) {
			return false
		}
		for _, step := range value[1:] {
			switch step.Value.(type) {
			case ast.String, ast.Number:
			default:
				return false
			}
		}
		return true
	default:
		return false
	}
}
func entityEqualitiesOppose(left, right entityEquality) bool {
	if left.negative == right.negative {
		return false
	}
	return (left.left.Equal(right.left) && left.right.Equal(right.right)) ||
		(left.left.Equal(right.right) && left.right.Equal(right.left))
}

// Normalize only final residual queries, never arbitrary support bodies. Output
// bindings are kept for materialization and excluded from Boolean simplification.
func normalizeEntityResidual(body ast.Body, facts map[string]bool) (ast.Body, bool) {
	normalized, impossible := simplifyEntitySupportQuery(body, facts)
	if impossible {
		return nil, true
	}
	_, conditions := entityOutput(normalized)
	if entityStaticContradiction(conditions) {
		return nil, true
	}
	return normalized, false
}

func entityLiteralFalse(left, right *ast.Term, equality, negated bool) bool {
	if _, ok := left.Value.(ast.Ref); ok {
		return false
	}
	if _, ok := right.Value.(ast.Ref); ok {
		return false
	}
	return left.Equal(right) && ((!equality && !negated) || (equality && negated))
}
