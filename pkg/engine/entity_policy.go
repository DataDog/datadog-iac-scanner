/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	entityPartialNamespace = "__dd_entity_partial"
	entityRuleNamespace    = "__dd_entity_rules"
	entityCoreModuleName   = "__dd_entity_core.rego"
)

// EntityProgram is a prepared policy over opaque entities and typed reads.
// It owns no scan values. Evaluation sessions and caches are isolated, so one
// program can be shared across concurrent scans. This programmatic boundary
// does not activate a new contract in the CLI or change reporting identities.
type EntityProgram struct {
	native      rego.PreparedEvalQuery
	units       map[entityUnitID]rego.PreparedEvalQuery
	plan        *entityPolicyPlan
	compilation *entityCompilation
	symbolic    *entitySymbolicWorkspace
	discovery   rego.PreparedEvalQuery
	policyID    string
	owners      []ast.Ref
}

// EntityFinding is a confirmed security witness. Subject is an internal handle,
// not a document ID or persisted fingerprint. Reporting adapters resolve it.
// Details contains only business metadata, never another copy of Subject/Path.
type EntityFinding struct {
	Subject string
	Path    policy.Path
	Details map[string]any
}

// EntityEvaluation summarizes completed work. Confirmed counts findings accepted
// by Emit. An error or Indeterminate prevents a clean evaluation, independently
// of findings already emitted from independently completed primary/clause units.
type EntityEvaluation struct {
	Confirmed     int
	Indeterminate bool
	Symbolic      bool
}

// EntityEvaluationRequest separates engine budgets and output handling from
// ordinary rule arguments. The reader is the full immutable evaluation-unit
// view; changing BatchSize must never change what relations a rule can read.
type EntityEvaluationRequest struct {
	Reader    policy.Reader
	Arguments map[string]any
	BatchSize int
	Emit      func(EntityFinding) error
}

type entityBatch struct {
	findings      []EntityFinding
	indeterminate bool
	symbolic      bool
}

const defaultEntityBatchSize = 512

// PrepareEntityPolicies shares one immutable compiler and library graph across
// every native rule. Symbolic execution owns a separate lazy workspace because
// partial evaluation may mutate borrowed AST literals. Packages are isolated by
// rewriting AST references, including absolute references to their own helpers.
//
// The initial domain requires a direct iac.targets iterator per decision clause,
// a finding owned by that target, and ground path/details descriptors. Reads and
// related-entity predicates use the full reader. Unsupported constructs fail
// preparation explicitly; this is not unrestricted Rego or a CLI entry point.
func PrepareEntityPolicies(ctx context.Context, sources, libraries map[string]string) (map[string]*EntityProgram, error) {
	author, err := compileEntitySources(sources, libraries)
	if err != nil {
		return nil, err
	}
	roots := make([]string, 0, len(author.decisions))
	for _, decision := range author.decisions {
		roots = append(roots, decision)
	}
	validated, err := planEntityPolicies(author.compiler.Modules, roots)
	if err != nil {
		return nil, err
	}
	compiled, plans, err := compileEntityUnits(author, validated)
	if err != nil {
		return nil, err
	}
	workspace := &entitySymbolicWorkspace{gate: make(chan struct{}, 1), native: compiled, plans: plans}
	owners := entityModuleOwners(compiled.compiler.Modules)
	programs := make(map[string]*EntityProgram, len(plans))
	// Every native entry point exposes the same set/capture protocol. No body
	// is re-inferred after compilation, and no query needs JSON round-tripping.
	prepare := func(ref ast.Ref) (rego.PreparedEvalQuery, error) {
		options := append(compiled.options(rego.Query("some finding in "+ref.String()+"; result=finding")), rego.GenerateJSON(entityASTResult))
		return rego.New(options...).PrepareForEval(ctx)
	}
	for id, plan := range plans {
		native, err := prepare(plan.decision)
		if err != nil {
			return nil, err
		}
		discovery, err := prepare(plan.discovery)
		if err != nil {
			return nil, err
		}
		queries := make(map[entityUnitID]rego.PreparedEvalQuery, len(plan.units))
		for _, unit := range plan.units {
			query, err := prepare(unit.ref)
			if err != nil {
				return nil, err
			}
			queries[unit.id] = query
		}
		programs[id] = &EntityProgram{
			native: native, units: queries, plan: plan, compilation: compiled,
			symbolic: workspace, discovery: discovery, policyID: id, owners: owners,
		}
	}
	return programs, nil
}

func entityModules(sources, libraries map[string]string) (modules map[string]*ast.Module, decisions map[string]string, err error) {
	modules = map[string]*ast.Module{}
	for name, content := range libraries {
		if strings.HasPrefix(name, "__dd_entity_") {
			return nil, nil, fmt.Errorf("reserved entity module name %q", name)
		}
		m, err := parseEntityModule(name, content)
		if err != nil {
			return nil, nil, err
		}
		modules[name] = m
	}
	ids := make([]string, 0, len(sources))
	for id := range sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	decisions = make(map[string]string, len(ids))
	for i, id := range ids {
		name := fmt.Sprintf("__dd_entity_rule_%d.rego", i)
		m, err := parseEntityModule(name, sources[id])
		if err != nil {
			return nil, nil, err
		}
		if !m.Package.Path.Equal(ast.MustParseRef("data.datadog")) {
			return nil, nil, fmt.Errorf("entity policy %q must use package datadog", id)
		}
		m.Package.Path = ast.Ref{ast.VarTerm("data"), ast.StringTerm(entityRuleNamespace), ast.StringTerm(fmt.Sprintf("q%d", i))}
		modules[name] = m
		decisions[id] = m.Package.Path.String() + ".DatadogPolicy"
	}
	core, err := ast.ParseModule(entityCoreModuleName, entityLibrary)
	if err != nil {
		return nil, nil, err
	}
	modules[entityCoreModuleName] = core
	return modules, decisions, nil
}

func parseEntityModule(name, source string) (*ast.Module, error) {
	m, err := ast.ParseModuleWithOpts(name, source, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, err
	}
	if err = validateEntityModule(m); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return m, nil
}
func entityModuleOwners(modules map[string]*ast.Module) []ast.Ref {
	owners := []ast.Ref{}
	for _, m := range modules {
		for _, r := range m.Rules {
			owners = append(owners, r.Ref())
		}
	}
	return owners
}

func validateEntityModule(module *ast.Module) error {
	root := module.Package.Path
	if len(root) > 1 && (root[1].Equal(ast.StringTerm("iac")) ||
		root[1].Equal(ast.StringTerm(entityPartialNamespace)) || root[1].Equal(ast.StringTerm(entityRuleNamespace))) {
		return &policy.Unsupported{Operation: "defining an engine-owned policy namespace"}
	}
	var failure error
	ast.WalkExprs(module, func(e *ast.Expr) bool {
		if len(e.With) > 0 {
			failure = &policy.Unsupported{Operation: "with scopes in entity policies"}
		}
		return false
	})
	ast.WalkRefs(module, func(ref ast.Ref) bool {
		if entityDataObservation(ref) {
			failure = &policy.Unsupported{Operation: "observing an engine-owned namespace or whole data"}
		}
		if len(ref) == 0 {
			return false
		}
		if ref[0].Equal(ast.VarTerm("input")) && (len(ref) < 2 || !ref[1].Equal(ast.StringTerm("arguments"))) {
			failure = &policy.Unsupported{Operation: "observing engine-owned input"}
		}
		if strings.HasPrefix(ref.String(), "dd.") {
			failure = &policy.Unsupported{Operation: "calling internal entity builtins"}
		}
		return false
	})
	return failure
}

// Evaluate selects every primary target and streams confirmed findings in
// bounded batches. A batch restricts execution, never global reads or absence
// proofs. Prepared code is reused; no scan state is retained by the program.
func (p *EntityProgram) Evaluate(ctx context.Context, request EntityEvaluationRequest) (EntityEvaluation, error) {
	result := EntityEvaluation{}
	size, err := request.validate()
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	input, err := prepareEntityInput(request.Arguments)
	if err != nil {
		return result, err
	}
	selection, err := p.selectTargets(ctx, request.Reader)
	if err != nil {
		return result, err
	}
	var failures []error
	for from := 0; from < len(selection.ids); {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		count := min(size, len(selection.ids)-from)
		batch, batchErr := p.evaluateHybridBatch(ctx, request.Reader, input, selection.batch(selection.ids[from+count-1]))
		if err := ctx.Err(); err != nil {
			return result, err
		}
		result.Indeterminate = result.Indeterminate || batch.indeterminate
		result.Symbolic = result.Symbolic || batch.symbolic
		for _, finding := range batch.findings {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if err := request.Emit(finding); err != nil {
				return result, fmt.Errorf("emit entity finding: %w", err)
			}
			result.Confirmed++
		}
		if batchErr != nil {
			failures = append(failures, batchErr)
		}
		from += count
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, errors.Join(failures...)
}

func (r EntityEvaluationRequest) validate() (int, error) {
	if r.Reader == nil || r.Emit == nil {
		return 0, errors.New("entity reader and finding emitter are required")
	}
	if r.BatchSize < 0 {
		return 0, errors.New("entity batch size must be positive or zero for the default")
	}
	if r.BatchSize == 0 {
		return defaultEntityBatchSize, nil
	}
	return r.BatchSize, nil
}

type entityTargetInventory struct {
	selector entitySelector
	ids      []string
	next     int
}
type entityTargetSelection struct {
	ids         []string
	inventories []entityTargetInventory
}

func (p *EntityProgram) selectTargets(ctx context.Context, reader policy.Reader) (entityTargetSelection, error) {
	selected := entityTargetSelection{}
	for _, selector := range p.plan.selectors {
		ids, err := reader.Entities(selector.kind, selector.typ)
		if err != nil {
			return selected, err
		}
		if !slices.IsSorted(ids) {
			slices.Sort(ids)
		}
		for i, id := range ids {
			if err := ctx.Err(); err != nil {
				return selected, err
			}
			if i > 0 && ids[i-1] == id {
				return selected, fmt.Errorf("duplicate primary policy subject %q", id)
			}
		}
		selected.inventories = append(selected.inventories, entityTargetInventory{selector: selector, ids: ids})
		if len(p.plan.selectors) == 1 {
			selected.ids = ids
		} else {
			selected.ids = append(selected.ids, ids...)
		}
	}
	if len(p.plan.selectors) > 1 {
		slices.Sort(selected.ids)
		selected.ids = slices.Compact(selected.ids)
	}
	for _, id := range selected.ids {
		if err := ctx.Err(); err != nil {
			return selected, err
		}
		if err := reader.CheckSubject(id); err != nil {
			return selected, err
		}
	}
	return selected, nil
}

// Partition the union by subject identity, not by selector. Overlapping
// selectors see the same occurrence in the same batch, preserving Rego's set
// semantics without retaining an unbounded cross-batch finding dedup cache.
func (s *entityTargetSelection) batch(last string) map[entitySelector]*ast.Term {
	targets := make(map[entitySelector]*ast.Term, len(s.inventories))
	for i := range s.inventories {
		inventory := &s.inventories[i]
		start := inventory.next
		for inventory.next < len(inventory.ids) && inventory.ids[inventory.next] <= last {
			inventory.next++
		}
		terms := make([]*ast.Term, inventory.next-start)
		for j, id := range inventory.ids[start:inventory.next] {
			terms[j] = ast.StringTerm(id)
		}
		targets[inventory.selector] = ast.ArrayTerm(terms...)
	}
	return targets
}

type entityPolicyInput struct{ native, symbolic, discovery ast.Value }

// Arguments are converted once per invocation and shared by every batch and
// both modes. The two small envelopes own no infrastructure value copies.
func prepareEntityInput(arguments map[string]any) (entityPolicyInput, error) {
	value, err := ast.InterfaceToValue(arguments)
	if err != nil {
		return entityPolicyInput{}, err
	}
	args := ast.NewTerm(value)
	symbols := ast.ObjectTerm()
	var inputs [3]ast.Value
	for i, mode := range []string{"native", "symbolic", "native"} {
		inputs[i] = ast.NewObject(
			[2]*ast.Term{ast.StringTerm("__dd_mode"), ast.StringTerm(mode)},
			[2]*ast.Term{ast.StringTerm("arguments"), args},
			[2]*ast.Term{ast.StringTerm("__dd_symbols"), symbols},
			[2]*ast.Term{ast.StringTerm("__dd_focus"), ast.NullTerm()},
			[2]*ast.Term{ast.StringTerm("__dd_discovery"), ast.BooleanTerm(i == 2)},
		)
	}
	return entityPolicyInput{native: inputs[0], symbolic: inputs[1], discovery: inputs[2]}, nil
}

type entityWitnessBatch struct {
	values        []*ast.Term
	indeterminate bool
}

func (p *EntityProgram) symbolicWitnesses(
	ctx context.Context, partial *rego.PartialQueries, input ast.Value, boundary *entityDeferredBoundary,
) (entityWitnessBatch, error) {
	session, err := entitySessionFrom(ctx)
	if err != nil {
		return entityWitnessBatch{}, err
	}
	result := entityWitnessBatch{}
	seen := ast.NewSet()
	facts := entitySupportFacts(partial.Support, p.owners)
	appendValue := func(value *ast.Term) {
		if seen.Contains(value) {
			return
		}
		seen.Add(value)
		result.values = append(result.values, value)
	}
	for _, query := range partial.Queries {
		body, impossible := simplifyEntitySupportQuery(query, facts)
		if impossible {
			continue
		}
		body = entityPruneTotalExistentials(body, session.totalSymbols)
		value, rest := entityOutput(body)
		if entityStaticContradiction(rest) {
			continue
		}
		if value != nil && len(rest) == 0 {
			if _, err := ast.JSON(value.Value); err == nil {
				appendValue(value)
				continue
			}
		}
		values, uncertain, err := p.nativeResidual(ctx, body, input, boundary)
		if err != nil {
			return result, err
		}
		if uncertain {
			result.indeterminate = true
			continue
		}
		for _, value := range values {
			appendValue(value)
		}
	}
	return result, nil
}

// A binding used only to name a total value adds no condition to the query.
// Required observations prove value existence; path-presence guards stay separate.
func entityPruneTotalExistentials(body ast.Body, total map[string]struct{}) ast.Body {
	// Count the whole body, including the result binding, so captures stay live.
	value, _ := entityOutput(body)
	if value == nil || len(total) == 0 {
		return body
	}
	// Constant-path references are ground to OPA but still need a value.
	if _, err := ast.JSON(value.Value); err != nil {
		return body
	}
	uses := map[ast.Var]int{}
	ast.WalkVars(body, func(variable ast.Var) bool {
		uses[variable]++
		return false
	})
	prefix := ast.MustParseRef("input.__dd_symbols.values")
	out := make(ast.Body, 0, len(body))
	for _, expr := range body {
		if variable, origin, ok := entityValueBinding(expr, prefix); ok && uses[variable] == 1 {
			if _, known := total[origin]; known {
				continue
			}
		}
		out = append(out, expr)
	}
	return out
}

// Match only whole-variable equalities to one exact value-origin reference.
// Literal constraints, negation, with scopes and presence references do not match.
func entityValueBinding(expr *ast.Expr, prefix ast.Ref) (ast.Var, string, bool) {
	if expr.Negated || len(expr.With) != 0 || !expr.IsEquality() {
		return "", "", false
	}
	terms := expr.Terms.([]*ast.Term)
	for _, pair := range [][2]*ast.Term{{terms[1], terms[2]}, {terms[2], terms[1]}} {
		variable, variableOK := pair[0].Value.(ast.Var)
		ref, refOK := pair[1].Value.(ast.Ref)
		if !variableOK || !refOK || len(ref) != len(prefix)+1 || !ref.HasPrefix(prefix) {
			continue
		}
		if origin, concrete := ref[len(prefix)].Value.(ast.String); concrete {
			return variable, string(origin), true
		}
	}
	return "", "", false
}

func entityOutput(body ast.Body) (*ast.Term, ast.Body) {
	var value *ast.Term
	remaining := ast.Body{}
	for _, e := range body {
		if !e.Negated && len(e.With) == 0 && e.IsEquality() {
			ts := e.Terms.([]*ast.Term)
			for _, pair := range [][2]*ast.Term{{ts[1], ts[2]}, {ts[2], ts[1]}} {
				if pair[0].Equal(ast.VarTerm("result")) && pair[1].IsGround() {
					value = pair[1]
					goto captured
				}
			}
		}
		remaining = append(remaining, e)
	captured:
	}
	return value, remaining
}
func entityFinding(value any, reader policy.Reader) (EntityFinding, error) {
	fields, ok := value.(map[string]any)
	if !ok {
		return EntityFinding{}, errors.New("entity finding must be an object")
	}
	subject, ok := fields["_dd_id"].(string)
	if !ok {
		return EntityFinding{}, errors.New("entity finding requires a subject")
	}
	if err := reader.CheckSubject(subject); err != nil {
		return EntityFinding{}, err
	}
	for _, reserved := range []string{"documentId", "searchKey", "resourceName", "resourceType"} {
		if _, ok := fields[reserved]; ok {
			return EntityFinding{}, fmt.Errorf("entity policy supplied reporting field %q", reserved)
		}
	}
	raw, ok := fields["path"].([]any)
	if !ok {
		return EntityFinding{}, errors.New("entity finding requires a typed path")
	}
	path, err := entityFindingPath(raw)
	if err != nil {
		return EntityFinding{}, err
	}
	delete(fields, "_dd_id")
	delete(fields, "path")
	return EntityFinding{Subject: subject, Path: path, Details: fields}, nil
}
func entityFindingPath(raw []any) (policy.Path, error) {
	path := make(policy.Path, len(raw))
	for i, step := range raw {
		switch value := step.(type) {
		case string:
			path[i] = policy.Key(value)
		case json.Number:
			index, err := entityIndex(string(value))
			if err != nil {
				return nil, err
			}
			path[i] = policy.Index(index)
		default:
			return nil, fmt.Errorf("finding path steps must be property names or integer indexes")
		}
	}
	return path, nil
}
