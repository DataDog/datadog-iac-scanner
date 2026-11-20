/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/v1/ast"
)

type entityUnitID string

type entityUnitPlan struct {
	id       entityUnitID
	ref      ast.Ref
	selector entitySelector
}

type entityPolicyPlan struct {
	decision  ast.Ref
	discovery ast.Ref
	units     []entityUnitPlan
	selectors []entitySelector
}

type entityUnresolved map[entityUnitID][]*ast.Term

// These source references live only during preparation. The compiled plan
// retains no rules or module pointers from the author-validation compiler.
type entityValidatedUnit struct {
	rule     *ast.Rule
	selector entitySelector
}

type entityValidatedPolicy struct {
	units     []entityValidatedUnit
	selectors []entitySelector
}

// Canonical unit roots are generated once after source validation. All native
// queries and the copied PE graph use these same opaque IDs and references.
func compileEntityUnits(
	author *entityCompilation, validated map[string]entityValidatedPolicy,
) (*entityCompilation, map[string]*entityPolicyPlan, error) {
	module, err := ast.ParseModule("__dd_entity_units.rego", "package "+entityRuleNamespace+".__units\nimport rego.v1\n")
	if err != nil {
		return nil, nil, err
	}
	ids := make([]string, 0, len(author.decisions))
	for id := range author.decisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	plans := make(map[string]*entityPolicyPlan, len(ids))
	for policyIndex, id := range ids {
		decision := author.decisions[id]
		source, ok := validated[decision]
		if !ok {
			return nil, nil, fmt.Errorf("missing validated policy %q", id)
		}
		plan := &entityPolicyPlan{decision: ast.MustParseRef(decision), selectors: source.selectors}
		discoveryName := fmt.Sprintf("discovery_p%d", policyIndex)
		plan.discovery = append(module.Package.Path.Copy(), ast.StringTerm(discoveryName))
		for clauseIndex, sourceUnit := range source.units {
			name := fmt.Sprintf("p%dc%d", policyIndex, clauseIndex)
			unit := entityUnitPlan{
				id: entityUnitID(name), ref: append(module.Package.Path.Copy(), ast.StringTerm(name)),
				selector: sourceUnit.selector,
			}
			rule := sourceUnit.rule.Copy()
			rule.Head.Name = ast.Var(name)
			rule.Head.Reference = ast.Ref{ast.VarTerm(name)}
			rule.Module = module
			module.Rules = append(module.Rules, rule)
			plan.units = append(plan.units, unit)
			// The original unit body is not copied again for discovery. Its private
			// target driver is focused by OPA's lexical input scope, while relations
			// continue using the full Reader through iac.entities.
			text := fmt.Sprintf(`%s contains {"unit":[%s,primary],"finding":finding} if {
	some primary in data.iac.targets(%s,%s)
	some finding in %s with input.__dd_focus as [%s,primary]
}`, discoveryName, ast.StringTerm(name), ast.StringTerm(unit.selector.kind),
				ast.StringTerm(unit.selector.typ), unit.ref.String(), ast.StringTerm(name))
			record, err := ast.ParseRuleWithOpts(text, ast.ParserOptions{RegoVersion: ast.RegoV1})
			if err != nil {
				return nil, nil, err
			}
			record.Module = module
			module.Rules = append(module.Rules, record)
		}
		plans[id] = plan
	}
	modules := copyEntityModules(author.compiler.Modules)
	modules["__dd_entity_units.rego"] = module
	compiler := ast.NewCompiler().WithCapabilities(author.capabilities)
	compiler.Compile(modules)
	attachEntityRuleModules(compiler.Modules)
	if compiler.Failed() {
		return nil, nil, compiler.Errors
	}
	compiled := *author
	compiled.compiler = compiler
	return &compiled, plans, nil
}

// Copy mutable module ASTs before transforming them. OPA's Module.Copy leaves
// nested Else.Module backlinks pointing at the prior graph.
func copyEntityModules(source map[string]*ast.Module) map[string]*ast.Module {
	modules := make(map[string]*ast.Module, len(source))
	for name, module := range source {
		modules[name] = module.Copy()
	}
	attachEntityRuleModules(modules)
	return modules
}

// Compilation copies modules again, so enforce ownership on its output too.
func attachEntityRuleModules(modules map[string]*ast.Module) {
	for _, module := range modules {
		ast.WalkRules(module, func(rule *ast.Rule) bool { rule.Module = module; return false })
	}
}
