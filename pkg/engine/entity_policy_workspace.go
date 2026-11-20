/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
)

type entityCompilation struct {
	compiler     *ast.Compiler
	capabilities *ast.Capabilities
	functions    []entityFunction
	decisions    map[string]string
	builtins     map[string]*topdown.Builtin
}

func compileEntitySources(sources, libraries map[string]string) (*entityCompilation, error) {
	modules, decisions, err := entityModules(sources, libraries)
	if err != nil {
		return nil, err
	}
	functions := entityFunctions()
	caps := *safeCapabilities()
	caps.Builtins = slices.DeleteFunc(slices.Clone(caps.Builtins), func(b *ast.Builtin) bool { return b.Nondeterministic })
	for _, f := range functions {
		caps.Builtins = append(caps.Builtins, &ast.Builtin{Name: f.definition.Name, Decl: f.definition.Decl})
	}
	compiler := ast.NewCompiler().WithCapabilities(&caps).
		WithStageAfter("ResolveRefs", ast.CompilerStageDefinition{
			Name: "IsolateEntityRuleReferences", MetricName: "compile_stage_entity_rule_references", Stage: isolateEntityRuleReferences,
		}).WithStageAfter("ResolveRefs", ast.CompilerStageDefinition{
		Name: "NormalizeEntityBooleanReads", MetricName: "compile_stage_entity_boolean_reads", Stage: normalizeEntityBooleanReads,
	})
	compiler.Compile(modules)
	attachEntityRuleModules(compiler.Modules)
	if compiler.Failed() {
		return nil, compiler.Errors
	}
	return &entityCompilation{
		compiler: compiler, capabilities: &caps, functions: functions, decisions: decisions,
		builtins: entityTopdownBuiltins(functions),
	}, nil
}

// Rule packages are private before resolution, so unqualified local references
// already point there. ResolveRefs also canonicalizes qualified self imports
// with lexical scoping. Relocate only those remaining references owned by the
// source rule, leaving sibling shared-library references unchanged.
func isolateEntityRuleReferences(compiler *ast.Compiler) *ast.Error {
	from := ast.MustParseRef("data.datadog")
	for name, module := range compiler.Modules {
		if !strings.HasPrefix(name, "__dd_entity_rule_") {
			continue
		}
		to := module.Package.Path
		owned := ast.NewSet()
		for _, rule := range module.Rules {
			owned.Add(ast.StringTerm(string(rule.Head.Name)))
		}
		ast.WalkTerms(module, func(term *ast.Term) bool {
			ref, ok := term.Value.(ast.Ref)
			if ok && len(ref) > len(from) && ref.HasPrefix(from) && owned.Contains(ref[len(from)]) {
				term.Value = append(to.Copy(), ref[len(from):]...)
				return true
			}
			return false
		})
	}
	return nil
}

// Bare Boolean-valued reads have the same truth condition as their predicate
// counterparts, including under negation. OPA PE can conflict when a bare
// complete function explores both true and false outputs. Normalize only these
// two assertion forms after import resolution, before graph and type checking;
// explicit output bindings and Boolean comparisons keep their value semantics.
func normalizeEntityBooleanReads(compiler *ast.Compiler) *ast.Error {
	predicates := map[string]ast.Ref{
		"data.iac.present_value": ast.MustParseRef("data.iac.present"),
		"data.iac.valid_key":     ast.MustParseRef("data.iac.nonnull"),
	}
	for _, module := range compiler.Modules {
		ast.WalkExprs(module, func(expr *ast.Expr) bool {
			terms, call := expr.Terms.([]*ast.Term)
			if !call || len(terms) != 3 || len(expr.With) != 0 {
				return false
			}
			if predicate, ok := predicates[terms[0].String()]; ok {
				terms[0] = ast.NewTerm(predicate.Copy())
			}
			return false
		})
	}
	return nil
}

func (c *entityCompilation) options(query func(*rego.Rego)) []func(*rego.Rego) {
	options := []func(*rego.Rego){
		query, rego.Compiler(c.compiler), rego.Capabilities(c.capabilities),
		rego.SetRegoVersion(ast.RegoV1), rego.StrictBuiltinErrors(true), rego.PartialNamespace(entityPartialNamespace),
	}
	for _, f := range c.functions {
		options = append(options, rego.FunctionDyn(f.definition, f.invoke))
	}
	return options
}

// OPA partial copy propagation can mutate arrays borrowed from compiled
// literals. Its workspace must not share ASTs with native evaluation or with
// another concurrent partial run. One lazily prepared workspace is leased
// through materialization; native programs remain independently concurrent.
// Infrastructure values stay in the caller's reader, never in this workspace.
type entitySymbolicWorkspace struct {
	gate     chan struct{}
	native   *entityCompilation
	plans    map[string]*entityPolicyPlan
	programs map[string]map[entityUnitID]entityClauseProjection
	boundary *entityDeferredBoundary
}

type entityClauseProjection struct {
	query        rego.PreparedPartialQuery
	opaqueErrors bool
}

// One workspace lease spans all grouped projections for the batch. No mutable
// residual nodes escape it; native buffers contain detached AST values.
func (w *entitySymbolicWorkspace) project(
	ctx context.Context, p *EntityProgram, input ast.Value, unresolved entityUnresolved,
) (entityWitnessBatch, error) {
	select {
	case w.gate <- struct{}{}:
		defer func() { <-w.gate }()
	case <-ctx.Done():
		return entityWitnessBatch{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return entityWitnessBatch{}, err
	}
	if w.programs == nil {
		if err := w.prepare(ctx); err != nil {
			return entityWitnessBatch{}, err
		}
	}
	programs, ok := w.programs[p.policyID]
	if !ok {
		return entityWitnessBatch{}, fmt.Errorf("missing symbolic clauses %q", p.policyID)
	}
	original, err := entitySessionFrom(ctx)
	if err != nil {
		return entityWitnessBatch{}, err
	}
	result := entityWitnessBatch{}
	var failures []error
	for _, unit := range p.plan.units {
		ids := unresolved[unit.id]
		if len(ids) == 0 {
			continue
		}
		program, ok := programs[unit.id]
		if !ok {
			return result, fmt.Errorf("missing symbolic unit %q", unit.id)
		}
		proof, err := program.projectGroup(ctx, p, input, w.boundary, original.reader, unit.selector, ids)
		if ctx.Err() != nil {
			return entityWitnessBatch{}, ctx.Err()
		}
		// projectGroup detached each successful attempt before the next Partial.
		result.indeterminate = result.indeterminate || proof.indeterminate
		result.values = append(result.values, proof.values...)
		if err != nil {
			failures = append(failures, err)
		}
	}

	return result, errors.Join(failures...)
}

// Detach before another Partial can mutate literals borrowed by its result.
func (b *entityWitnessBatch) appendDetached(proof entityWitnessBatch) {
	b.indeterminate = b.indeterminate || proof.indeterminate
	for _, value := range proof.values {
		b.values = append(b.values, value.Copy())
	}
}

// A successful group commits atomically. On error, replay only that group by
// primary using the same prepared query, preserving independent valid units.
func (q entityClauseProjection) projectGroup(
	ctx context.Context, p *EntityProgram, input ast.Value, boundary *entityDeferredBoundary,
	reader policy.Reader, selector entitySelector, ids []*ast.Term,
) (entityWitnessBatch, error) {
	run := func(ids []*ast.Term) (entityWitnessBatch, error) {
		targets := map[entitySelector]*ast.Term{selector: ast.ArrayTerm(ids...)}
		return q.evaluate(ctx, p, input, boundary, reader, targets)
	}
	proof, err := run(ids)
	if ctx.Err() != nil {
		return entityWitnessBatch{}, ctx.Err()
	}
	result := entityWitnessBatch{}
	if err == nil {
		result.appendDetached(proof)
		return result, nil
	}
	if len(ids) == 1 {
		return result, err
	}
	var failures []error
	for _, id := range ids {
		proof, err := run([]*ast.Term{id})
		if ctx.Err() != nil {
			return entityWitnessBatch{}, ctx.Err()
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		result.appendDetached(proof)
	}
	return result, errors.Join(failures...)
}

// Each attempt owns its reader facts. Its witnesses still borrow the leased
// graph; projectGroup discards failures and detaches successful results.
func (q entityClauseProjection) evaluate(
	ctx context.Context, p *EntityProgram, input ast.Value, boundary *entityDeferredBoundary,
	reader policy.Reader, targets map[entitySelector]*ast.Term,
) (entityWitnessBatch, error) {
	session := &entitySession{reader: reader, targets: targets}
	ctx = context.WithValue(ctx, entitySessionKey{}, session)
	unknowns := append([]string{"input.__dd_symbols"}, boundary.paths...)
	partial, err := q.query.Partial(ctx, rego.EvalParsedInput(input), rego.EvalUnknowns(unknowns))
	if session.failure != nil {
		return entityWitnessBatch{}, session.failure
	}
	if ctx.Err() != nil {
		return entityWitnessBatch{}, ctx.Err()
	}
	if err != nil {
		return entityWitnessBatch{}, err
	}
	proof, err := p.symbolicWitnesses(ctx, partial, input, boundary)
	proof.indeterminate = proof.indeterminate || q.opaqueErrors
	return proof, err
}

func (w *entitySymbolicWorkspace) prepare(ctx context.Context) error {
	boundary, lowered, err := prepareEntityDeferred(w.native)
	if err != nil {
		return err
	}
	programs := make(map[string]map[entityUnitID]entityClauseProjection, len(w.plans))
	for id, plan := range w.plans {
		units := make(map[entityUnitID]entityClauseProjection, len(plan.units))
		for _, unit := range plan.units {
			options := lowered.options(rego.Query("some finding in " + unit.ref.String() + "; result=finding"))
			query, err := rego.New(options...).PrepareForPartial(ctx)
			if err != nil {
				return err
			}
			rules := w.native.compiler.GetRulesExact(unit.ref)
			if len(rules) != 1 {
				return fmt.Errorf("expected one source body for unit %q", unit.id)
			}
			units[unit.id] = entityClauseProjection{query: query, opaqueErrors: entityClauseOpaqueErrors(w.native.compiler, boundary, rules[0].Body)}
		}
		programs[id] = units
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.programs = programs
	w.boundary = boundary
	w.native = nil
	w.plans = nil
	return nil
}
