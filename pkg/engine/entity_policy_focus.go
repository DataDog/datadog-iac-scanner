/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
)

const entityTargetsFunction = "data.iac.targets"

type entitySelector struct{ kind, typ string }
type entityAliases map[ast.Var]map[ast.Var]bool

// Focus is a driver, never a policy-observable inventory. Each supported decision clause
// iterates one primary selector and returns findings on that same occurrence.
// The global reader remains available to predicates, including under negation.
func (d *entityDomain) focusPlans() (map[string][]entitySelector, error) {
	plans := map[string][]entitySelector{}
	for _, r := range d.active {
		if d.observesDecision(r.rule.Body) {
			return nil, &policy.Unsupported{Operation: "observing entity decisions as policy data"}
		}
		if !d.roots[r.name] {
			var observes bool
			ast.WalkRefs(r.rule, func(ref ast.Ref) bool { observes = observes || ref.String() == entityTargetsFunction; return false })
			if observes {
				return nil, &policy.Unsupported{Operation: "primary targets outside a direct decision iterator"}
			}
			continue
		}
		selector, err := entityRuleFocus(r.rule)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.name, err)
		}
		if !slices.Contains(plans[r.name], selector) {
			plans[r.name] = append(plans[r.name], selector)
		}
	}
	for root := range d.roots {
		if _, ok := plans[root]; !ok {
			return nil, &policy.Unsupported{Operation: "missing entity decision and primary selector"}
		}
	}
	for _, selectors := range plans {
		slices.SortFunc(selectors, func(a, b entitySelector) int {
			if c := strings.Compare(a.kind, b.kind); c != 0 {
				return c
			}
			return strings.Compare(a.typ, b.typ)
		})
	}
	return plans, nil
}

func entityRuleFocus(rule *ast.Rule) (entitySelector, error) {
	if rule.Default || rule.Else != nil || rule.Head.RuleKind() != ast.MultiValue || len(rule.Head.Ref()) != 1 {
		return entitySelector{}, &policy.Unsupported{Operation: "entity decisions must be finding sets"}
	}
	selector, collection, selection, err := entityFocusSelector(rule.Body)
	if err != nil {
		return selector, err
	}
	aliases := entityRuleAliases(rule.Body)
	collections := aliases.reachable(collection)
	iteration, target, err := entityFocusIteration(rule, collections)
	if err != nil {
		return selector, err
	}
	head, ok := rule.Head.Key.Value.(ast.Var)
	if !ok {
		return selector, &policy.Unsupported{Operation: "entity decisions must return a bound finding"}
	}
	err = validateEntityFocusBody(rule.Body, selection, iteration, collections, aliases.reachable(target), aliases.reachable(head))
	return selector, err
}

func entityFocusSelector(body ast.Body) (entitySelector, ast.Var, *ast.Expr, error) {
	var selection *ast.Expr
	var collection ast.Var
	var selector entitySelector
	for _, e := range body {
		terms, ok := e.Terms.([]*ast.Term)
		if !ok || len(terms) == 0 || terms[0].String() != entityTargetsFunction {
			continue
		}
		if selection != nil || e.Negated || len(terms) != entityBinaryCallTerms {
			return selector, collection, nil, &policy.Unsupported{Operation: "exactly one positive primary selector per decision clause"}
		}
		kind, k := terms[1].Value.(ast.String)
		typ, t := terms[2].Value.(ast.String)
		output, v := terms[3].Value.(ast.Var)
		if !k || !t || !v {
			return selector, collection, nil, &policy.Unsupported{Operation: "primary selectors require literal kind and type"}
		}
		selection, collection, selector = e, output, entitySelector{string(kind), string(typ)}
	}
	if selection == nil {
		return selector, collection, nil, &policy.Unsupported{Operation: "entity decisions require a primary target iterator"}
	}
	return selector, collection, selection, nil
}

func validateEntityFocusBody(
	body ast.Body, selection, iteration *ast.Expr, collections, targets, outputs map[ast.Var]bool,
) error {
	found := false
	for _, e := range body {
		if e != selection && e != iteration && !entityCollectionAlias(e, collections) && entityObservesVars(e, collections) {
			return &policy.Unsupported{Operation: "primary target inventories cannot be observed as policy data"}
		}
		terms, ok := e.Terms.([]*ast.Term)
		if !ok || len(terms) == 0 || terms[0].String() != entityFindingFunction {
			continue
		}
		output, err := entityFocusFinding(e, targets, outputs)
		if err != nil {
			return err
		}
		found = found || output
	}
	if !found {
		return &policy.Unsupported{Operation: "entity decisions must return their direct target finding"}
	}
	return nil
}

const entityFindingCallTerms = 5

func entityFocusFinding(e *ast.Expr, targets, outputs map[ast.Var]bool) (bool, error) {
	terms := e.Terms.([]*ast.Term)
	if e.Negated || len(terms) != entityFindingCallTerms {
		return false, &policy.Unsupported{Operation: "entity findings require a direct positive constructor"}
	}
	owner, own := terms[1].Value.(ast.Var)
	if !own || !targets[owner] {
		return false, &policy.Unsupported{Operation: "finding owner must be the primary target or a direct alias"}
	}
	output, out := terms[entityFindingCallTerms-1].Value.(ast.Var)
	return out && outputs[output], nil
}

// OPA lowers `some entity in targets` to entity = targets[index]. The index
// must remain private to this iterator: observing batch-relative positions
// would change a policy's meaning when the engine changes its batch size.
func entityFocusIteration(rule *ast.Rule, collections map[ast.Var]bool) (*ast.Expr, ast.Var, error) {
	var iteration *ast.Expr
	var target ast.Var
	for _, e := range rule.Body {
		terms, ok := entityPositiveEquality(e)
		if !ok {
			continue
		}
		for _, pair := range [][2]*ast.Term{{terms[1], terms[2]}, {terms[2], terms[1]}} {
			candidate, v := pair[0].Value.(ast.Var)
			ref, r := pair[1].Value.(ast.Ref)
			if !v || !r || len(ref) != 2 {
				continue
			}
			root, rooted := ref[0].Value.(ast.Var)
			if !rooted || !collections[root] {
				continue
			}
			index, indexed := ref[1].Value.(ast.Var)
			if iteration != nil || !indexed || index == candidate || entityVarOccurrences(rule, index) != 1 {
				return nil, "", &policy.Unsupported{Operation: "primary targets require one unobserved iteration index"}
			}
			iteration, target = e, candidate
		}
	}
	if iteration == nil {
		return nil, "", &policy.Unsupported{Operation: "primary targets require a positive direct iterator"}
	}
	return iteration, target, nil
}
func entityRuleAliases(body ast.Body) entityAliases {
	aliases := entityAliases{}
	for _, e := range body {
		terms, ok := entityPositiveEquality(e)
		if !ok {
			continue
		}
		a, left := terms[1].Value.(ast.Var)
		b, right := terms[2].Value.(ast.Var)
		if !left || !right {
			continue
		}
		if aliases[a] == nil {
			aliases[a] = map[ast.Var]bool{}
		}
		if aliases[b] == nil {
			aliases[b] = map[ast.Var]bool{}
		}
		aliases[a][b], aliases[b][a] = true, true
	}
	return aliases
}
func (aliases entityAliases) reachable(start ast.Var) map[ast.Var]bool {
	seen := map[ast.Var]bool{start: true}
	queue := []ast.Var{start}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		for neighbor := range aliases[next] {
			if !seen[neighbor] {
				seen[neighbor] = true
				queue = append(queue, neighbor)
			}
		}
	}
	return seen
}
func entityPositiveEquality(e *ast.Expr) ([]*ast.Term, bool) {
	terms, ok := e.Terms.([]*ast.Term)
	return terms, ok && !e.Negated && len(terms) == 3 && (e.IsEquality() || e.Operator().Equal(ast.Equal.Ref()))
}
func entityCollectionAlias(e *ast.Expr, collections map[ast.Var]bool) bool {
	terms, ok := entityPositiveEquality(e)
	if !ok {
		return false
	}
	a, left := terms[1].Value.(ast.Var)
	b, right := terms[2].Value.(ast.Var)
	return left && right && collections[a] && collections[b]
}
func entityObservesVars(node any, variables map[ast.Var]bool) bool {
	found := false
	ast.WalkVars(node, func(v ast.Var) bool { found = found || variables[v]; return false })
	return found
}
func entityVarOccurrences(node any, variable ast.Var) int {
	count := 0
	ast.WalkVars(node, func(v ast.Var) bool {
		if v == variable {
			count++
		}
		return false
	})
	return count
}

// Whole-package and dynamic references can observe a decision too. Stop at the
// first dynamic step and compare the remaining constant prefix to all roots.
func (d *entityDomain) observesDecision(body ast.Body) bool {
	found := false
	ast.WalkRefs(body, func(ref ast.Ref) bool {
		if len(ref) == 0 || !ref[0].Equal(ast.VarTerm("data")) {
			return false
		}
		prefix := ref
		for i, step := range ref {
			if i > 0 {
				if _, ok := step.Value.(ast.String); !ok {
					prefix = ref[:i]
					break
				}
			}
		}
		found = found || d.rootPrefixes[prefix.String()]
		for i := 1; i <= len(prefix) && !found; i++ {
			found = d.roots[prefix[:i].String()]
		}
		return false
	})
	return found
}
