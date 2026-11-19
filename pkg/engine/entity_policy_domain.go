/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
)

const entityBinaryCallTerms = 4
const entityFindingFunction = "data.iac.finding"

type entityRole uint8

const (
	roleEntity entityRole = 1 << iota
	roleEntities
	roleFinding
	roleObservation
	roleGround
)

type entityDomainRule struct {
	rule *ast.Rule
	name string
	vars map[ast.Var]entityRole
}
type entityDomainFunction struct {
	args     []entityRole
	result   entityRole
	observed bool
	rules    []*entityDomainRule
}
type entityDomain struct {
	functions    map[string]*entityDomainFunction
	roots        map[string]bool
	rootPrefixes map[string]bool
	active       []*entityDomainRule
	changed      bool
	failure      error
}

// planEntityPolicies validates opaque-handle roles over OPA's compiled,
// lexically scoped variables. It does not rewrite source or infer bindings
// from variable names. Only reachable definitions participate.
func planEntityPolicies(modules map[string]*ast.Module, decisions []string) (map[string][]entitySelector, error) {
	d := newEntityDomain(modules, decisions)
	for _, r := range d.active {
		if err := d.checkShape(r); err != nil {
			return nil, err
		}
	}
	if err := d.propagateRoles(); err != nil {
		return nil, err
	}
	// Pending helper roles are not observations. First converge ground proofs,
	// then classify unproved totality and propagate those dependencies. This
	// avoids making the result depend on whether callers or helpers run first.
	for _, r := range d.active {
		f := d.functions[r.name]
		if len(f.rules) != 1 || !d.totalBody(r) {
			f.result |= roleObservation
		}
	}
	if err := d.propagateRoles(); err != nil {
		return nil, err
	}
	for _, r := range d.active {
		if err := d.checkMetadata(r); err != nil {
			return nil, err
		}
		if d.roots[r.name] {
			head := r.rule.Head.Value
			if r.rule.Head.Key != nil {
				head = r.rule.Head.Key
			}
			if head == nil || d.termRole(r, head)&roleFinding == 0 {
				return nil, &policy.Unsupported{Operation: "entity decisions must return the finding constructor"}
			}
		}
	}
	return d.focusPlans()
}
func (d *entityDomain) propagateRoles() error {
	for d.changed = true; d.changed; {
		d.changed = false
		for _, r := range d.active {
			d.propagate(r)
			if d.failure != nil {
				return d.failure
			}
		}
	}
	return nil
}

func newEntityDomain(modules map[string]*ast.Module, decisions []string) *entityDomain {
	d := &entityDomain{functions: map[string]*entityDomainFunction{}, roots: map[string]bool{}, rootPrefixes: map[string]bool{}}
	for _, name := range decisions {
		d.roots[name] = true
		ref := ast.MustParseRef(name)
		for i := 1; i <= len(ref); i++ {
			d.rootPrefixes[ref[:i].String()] = true
		}
	}
	for _, m := range modules {
		if len(m.Package.Path) > 1 && m.Package.Path[1].Equal(ast.StringTerm("iac")) {
			continue
		}
		for _, r := range m.Rules {
			d.addRule(m, r)
		}
	}
	seen := map[string]bool{}
	queue := append([]string{}, decisions...)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		f := d.functions[name]
		if f == nil {
			continue
		}
		for _, r := range f.rules {
			d.active = append(d.active, r)
			ast.WalkRefs(r.rule, func(ref ast.Ref) bool {
				if _, ok := d.functions[ref.String()]; ok && !seen[ref.String()] {
					queue = append(queue, ref.String())
				}
				return false
			})
		}
	}
	return d
}
func (d *entityDomain) addRule(m *ast.Module, r *ast.Rule) {
	name := append(m.Package.Path.Copy(), ast.StringTerm(string(r.Head.Name))).String()
	f := d.functions[name]
	if f == nil {
		f = &entityDomainFunction{args: make([]entityRole, len(r.Head.Args))}
		d.functions[name] = f
	}
	for current := r; current != nil; current = current.Else {
		f.rules = append(f.rules, &entityDomainRule{rule: current, name: name, vars: map[ast.Var]entityRole{}})
	}
}
func (d *entityDomain) checkShape(r *entityDomainRule) error {
	if !d.roots[r.name] && (r.rule.Head.Key != nil || len(r.rule.Head.Ref()) != 1) {
		return &policy.Unsupported{Operation: "derived partial documents in entity policies"}
	}
	var unsupported bool
	ast.WalkTerms(r.rule, func(t *ast.Term) bool {
		switch t.Value.(type) {
		case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension:
			unsupported = true
		}
		return false
	})
	ast.WalkExprs(r.rule, func(e *ast.Expr) bool {
		if _, ok := e.Terms.(*ast.Every); ok {
			unsupported = true
		}
		return false
	})
	if unsupported {
		return &policy.Unsupported{Operation: "comprehension or every in the initial entity read domain"}
	}
	return nil
}
func (d *entityDomain) assign(r *entityDomainRule, t *ast.Term, role entityRole) {
	if v, ok := t.Value.(ast.Var); ok && r.vars[v]|role != r.vars[v] {
		r.vars[v] |= role
		d.changed = true
	}
}
func (d *entityDomain) propagate(r *entityDomainRule) {
	f := d.functions[r.name]
	for i, arg := range r.rule.Head.Args {
		if _, variable := arg.Value.(ast.Var); !variable && opaqueEntityRole(f.args[i]) {
			d.failure = &policy.Unsupported{Operation: "opaque entities cannot be destructured in helper parameters"}
			return
		}
		d.assign(r, arg, f.args[i])
	}
	for _, e := range r.rule.Body {
		d.expression(r, e)
	}
	if r.rule.Head.Value != nil {
		role := d.termRole(r, r.rule.Head.Value)
		if len(f.rules) != 1 || !d.totalBody(r) {
			role &^= roleGround
		}
		if f.observed {
			role |= roleObservation
		}
		if f.result|role != f.result {
			f.result |= role
			d.changed = true
		}
	}
}
func (d *entityDomain) termRole(r *entityDomainRule, t *ast.Term) entityRole {
	switch v := t.Value.(type) {
	case ast.Var:
		return r.vars[v]
	case ast.Ref:
		return d.refRole(r, v, t)
	case *ast.Array, ast.Object, ast.Set:
		return d.containerRole(r, t)
	case ast.Null, ast.Boolean, ast.Number, ast.String:
		return roleGround
	default:
		d.failure = &policy.Unsupported{Operation: "value form outside the supported entity policy domain"}
		return 0
	}
}
func (d *entityDomain) containerRole(r *entityDomainRule, t *ast.Term) entityRole {
	role := roleGround
	combine := func(term *ast.Term) {
		child := d.termRole(r, term)
		if opaqueEntityRole(child) {
			d.failure = &policy.Unsupported{Operation: "embedding opaque entities or findings in arbitrary containers"}
		}
		if child&roleGround == 0 {
			role &^= roleGround
		}
		role |= child & roleObservation
	}
	switch value := t.Value.(type) {
	case *ast.Array:
		for i := range value.Len() {
			combine(value.Elem(i))
		}
	case ast.Object:
		value.Foreach(func(k, v *ast.Term) { combine(k); combine(v) })
	case ast.Set:
		value.Foreach(combine)
	}
	return role
}
func opaqueEntityRole(role entityRole) bool { return role&(roleEntity|roleEntities|roleFinding) != 0 }
func (d *entityDomain) observed(r *entityDomainRule) {
	f := d.functions[r.name]
	if !f.observed {
		f.observed = true
		d.changed = true
	}
}

func (d *entityDomain) refRole(r *entityDomainRule, ref ast.Ref, t *ast.Term) entityRole {
	if len(ref) == 0 {
		return 0
	}
	role := d.termRole(r, ref[0])
	if role&(roleEntity|roleFinding) != 0 && len(ref) > 1 {
		d.failure = &policy.Unsupported{Operation: fmt.Sprintf("object observation of an opaque entity or finding at %s", t.Location)}
		return 0
	}
	if role&roleEntities != 0 && len(ref) > 1 {
		if len(ref) != 2 {
			d.failure = &policy.Unsupported{Operation: "field observation through an entity collection"}
		}
		return roleEntity | roleGround
	}
	if f := d.functions[ref.String()]; f != nil {
		return f.result
	}
	if ref[0].Equal(ast.VarTerm("input")) {
		return roleObservation
	}
	if len(ref) > 1 && role != 0 {
		role &^= roleGround
		role |= roleObservation
	}
	if ref[0].Equal(ast.VarTerm("data")) {
		d.failure = &policy.Unsupported{Operation: "policy data requires explicit helper/value references; namespace reflection is unsupported"}
		return 0
	}
	return role
}
func (d *entityDomain) expression(r *entityDomainRule, e *ast.Expr) {
	terms, ok := e.Terms.([]*ast.Term)
	if !ok {
		if term, ok := e.Terms.(*ast.Term); ok {
			d.observeTerm(r, term)
		}
		return
	}
	if len(terms) == 0 {
		return
	}
	if e.IsEquality() && len(terms) == 3 {
		d.unify(r, terms[1], terms[2])
		return
	}
	op := terms[0].String()
	switch op {
	case "data.iac.entities", entityTargetsFunction, "dd.entities", "dd.targets":
		if len(terms) == entityBinaryCallTerms {
			d.assign(r, terms[3], roleEntities|roleGround)
		}
	case entityFindingFunction:
		d.findingCall(r, terms)
	case "data.iac.raw", "data.iac.value", "data.iac.present", "data.iac.nonnull", "data.iac.valid_key", "data.iac.present_value":
		d.readCall(r, terms)
	case "internal.member_2", "internal.member_3":
		d.membership(r, terms)
	default:
		d.call(r, op, terms)
	}
	for _, term := range terms[1:] {
		if d.termRole(r, term)&roleObservation != 0 {
			d.observed(r)
		}
	}
}
func (d *entityDomain) observeTerm(r *entityDomainRule, term *ast.Term) {
	role := d.termRole(r, term)
	if role&roleObservation != 0 {
		d.observed(r)
	}
	if opaqueEntityRole(role) {
		d.failure = &policy.Unsupported{Operation: "opaque entities and findings cannot be observed as Boolean values"}
	}
}
func (d *entityDomain) unify(r *entityDomainRule, a, b *ast.Term) {
	left, right := d.termRole(r, a), d.termRole(r, b)
	if entityOpaquePattern(a, left, right) || entityOpaquePattern(b, right, left) {
		d.failure = &policy.Unsupported{Operation: "opaque entities cannot be matched to untyped structures or literals"}
		return
	}
	d.assign(r, a, right)
	d.assign(r, b, left)
}

func entityOpaquePattern(term *ast.Term, role, other entityRole) bool {
	_, variable := term.Value.(ast.Var)
	return opaqueEntityRole(other) && !opaqueEntityRole(role) && !variable
}

func (d *entityDomain) readCall(r *entityDomainRule, terms []*ast.Term) {
	d.observed(r)
	if len(terms) > 2 && opaqueEntityRole(d.termRole(r, terms[2])) {
		d.failure = &policy.Unsupported{Operation: "using an entity as a property path"}
	}
	if len(terms) == entityBinaryCallTerms {
		d.assign(r, terms[3], roleObservation)
	}
}

func (d *entityDomain) findingCall(r *entityDomainRule, terms []*ast.Term) {
	if len(terms) > 2 && opaqueEntityRole(d.termRole(r, terms[2])) {
		d.failure = &policy.Unsupported{Operation: "using an entity as a finding path"}
	}
	d.assign(r, terms[len(terms)-1], roleFinding)
}
func (d *entityDomain) membership(r *entityDomainRule, terms []*ast.Term) {
	if len(terms) < entityBinaryCallTerms {
		return
	}
	collection := d.termRole(r, terms[len(terms)-2])
	if collection&roleEntities != 0 {
		candidate := terms[len(terms)-3]
		if _, variable := candidate.Value.(ast.Var); !variable && !opaqueEntityRole(d.termRole(r, candidate)) {
			d.failure = &policy.Unsupported{Operation: "opaque entity collections require variable member bindings"}
			return
		}
		d.assign(r, candidate, roleEntity|roleGround)
	}
	if collection&roleObservation != 0 {
		d.assign(r, terms[len(terms)-3], roleObservation)
		d.observed(r)
	}
}
func (d *entityDomain) call(r *entityDomainRule, op string, terms []*ast.Term) {
	target := d.functions[op]
	if target == nil {
		d.builtin(r, op, terms)
		return
	}
	observed := target.observed
	for i := range target.args {
		if i+1 >= len(terms) {
			break
		}
		role := d.termRole(r, terms[i+1])
		observed = observed || role&roleObservation != 0
		if target.args[i]|role != target.args[i] {
			target.args[i] |= role
			d.changed = true
		}
	}
	role := target.result
	if observed {
		role |= roleObservation
		d.observed(r)
	}
	if len(terms) == len(target.args)+2 {
		d.assign(r, terms[len(terms)-1], role)
	}
}
func (d *entityDomain) builtin(r *entityDomainRule, op string, terms []*ast.Term) {
	role := roleObservation
	if op == ast.JSONMarshal.Name {
		role = roleGround
		for _, argument := range terms[1 : len(terms)-1] {
			argumentRole := d.termRole(r, argument)
			if argumentRole&roleGround == 0 {
				role &^= roleGround
			}
			role |= argumentRole & roleObservation
		}
	}
	for _, arg := range terms[1:] {
		argRole := d.termRole(r, arg)
		if opaqueEntityRole(argRole) {
			d.failure = &policy.Unsupported{Operation: fmt.Sprintf("opaque entity or finding passed to %s", op)}
		}
		role |= argRole & roleObservation
	}
	if role&roleObservation != 0 {
		d.observed(r)
	}

	if len(terms) > 1 {
		d.assign(r, terms[len(terms)-1], role)
	}
}

// Ground metadata is deliberately narrower than arbitrary Rego: literals,
// forwarding and total JSON encoding. Optional data must not add a hidden
// definedness/uncertainty condition to the security finding.
func (d *entityDomain) totalCall(r *entityDomainRule, terms []*ast.Term) bool {
	if len(terms) < 3 {
		return false
	}
	if terms[0].String() != ast.JSONMarshal.Name {
		return false
	}
	for _, arg := range terms[1 : len(terms)-1] {
		role := d.termRole(r, arg)
		if role&roleGround == 0 || role&roleObservation != 0 {
			return false
		}
	}
	return true
}
func (d *entityDomain) totalBody(r *entityDomainRule) bool {
	bound, valid := entityParameterBindings(r.rule.Head.Args)
	if !valid {
		return false
	}
	for _, e := range r.rule.Body {
		if term, ok := e.Terms.(*ast.Term); ok {
			if term.Equal(ast.BooleanTerm(true)) && !e.Negated {
				continue
			}
			return false
		}
		terms, ok := e.Terms.([]*ast.Term)
		if !ok || len(terms) < 3 || e.Negated {
			return false
		}
		output := terms[len(terms)-1]
		if e.IsEquality() {
			if !d.totalBinding(r, terms, bound) {
				return false
			}
			continue
		}
		if !d.totalCall(r, terms) {
			return false
		}
		variable, ok := output.Value.(ast.Var)
		if !ok || bound[variable] {
			return false
		}
		bound[variable] = true
	}
	return true
}
func entityParameterBindings(arguments []*ast.Term) (map[ast.Var]bool, bool) {
	bound := map[ast.Var]bool{}
	for _, argument := range arguments {
		variable, ok := argument.Value.(ast.Var)
		if !ok || bound[variable] {
			return nil, false
		}
		bound[variable] = true
	}
	return bound, true
}

func (d *entityDomain) totalBinding(r *entityDomainRule, terms []*ast.Term, bound map[ast.Var]bool) bool {
	for _, pair := range [][2]*ast.Term{{terms[1], terms[2]}, {terms[2], terms[1]}} {
		variable, ok := pair[0].Value.(ast.Var)
		role := d.termRole(r, pair[1])
		if ok && !bound[variable] && role&roleGround != 0 && role&roleObservation == 0 {
			bound[variable] = true
			return true
		}
	}
	return false
}

func (d *entityDomain) checkMetadata(r *entityDomainRule) error {
	for _, e := range r.rule.Body {
		terms, ok := e.Terms.([]*ast.Term)
		if !ok || len(terms) <= 3 || terms[0].String() != entityFindingFunction {
			continue
		}
		path := d.termRole(r, terms[2])
		if path&roleGround == 0 || path&roleObservation != 0 {
			return &policy.Unsupported{Operation: "finding paths must be ground typed descriptors; dynamic paths require a provenance adapter"}
		}
		role := d.termRole(r, terms[3])
		if role&roleGround == 0 || role&roleObservation != 0 {
			return &policy.Unsupported{Operation: "finding details must be ground declarative descriptors; use deferred references for dynamic data"}
		}
	}
	return nil
}

// Whole-data observations would change meaning when partial support is added.
func entityDataObservation(ref ast.Ref) bool {
	if len(ref) == 0 || !ref[0].Equal(ast.VarTerm("data")) {
		return false
	}
	if len(ref) < 2 {
		return true
	}
	if _, ok := ref[1].Value.(ast.String); !ok {
		return true
	}
	return strings.HasPrefix(ref.String(), "data."+entityPartialNamespace)
}
