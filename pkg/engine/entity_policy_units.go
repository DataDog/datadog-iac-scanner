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

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

func entityASTResult(term *ast.Term, _ *rego.EvalContext) (any, error) { return term.Copy(), nil }

// Every attempt has fresh uncertainty and failure state. A real first error
// remains authoritative even if OPA subsequently demanded an uncertain read.
func entityNativeAttempt(
	ctx context.Context, query rego.PreparedEvalQuery, reader policy.Reader, input ast.Value,
	targets map[entitySelector]*ast.Term, discovered map[entityDiscoveryUnit]bool,
) ([]*ast.Term, bool, error) {
	session := &entitySession{reader: reader, targets: targets, discovered: discovered}
	ctx = context.WithValue(ctx, entitySessionKey{}, session)
	rows, err := query.Eval(ctx, rego.EvalParsedInput(input))
	if session.failure != nil {
		return nil, false, session.failure
	}
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if err != nil && !errors.Is(err, errSymbolicRead) {
		return nil, false, err
	}
	if session.symbolic {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	values := []*ast.Term{}
	for _, row := range rows {
		raw, ok := row.Bindings["result"].(*ast.Term)
		if !ok {
			return nil, false, fmt.Errorf("missing AST query capture")
		}
		values = append(values, raw)
	}
	return values, false, nil
}

// Deduplicate OPA values before JSON conversion: sets and arrays can have the
// same JSON representation while remaining distinct Rego findings.
type entityBatchAccumulator struct {
	entityBatch
	reader policy.Reader
	seen   ast.Set
}

func (b *entityBatchAccumulator) accept(values []*ast.Term) error {
	for _, value := range values {
		if b.seen.Contains(value) {
			continue
		}
		raw, err := ast.JSON(value.Value)
		if err != nil {
			return err
		}
		finding, err := entityFinding(raw, b.reader)
		if err != nil {
			return err
		}
		b.seen.Add(value)
		b.findings = append(b.findings, finding)
	}
	return nil
}

type entityBatchWork struct {
	unresolved entityUnresolved
	failures   []error
}

func (p *EntityProgram) evaluateHybridBatch(
	ctx context.Context, reader policy.Reader, input entityPolicyInput, targets map[entitySelector]*ast.Term,
) (entityBatch, error) {
	batch := entityBatchAccumulator{reader: reader, seen: ast.NewSet()}
	values, unknown, bulkErr := entityNativeAttempt(ctx, p.native, reader, input.native, targets, nil)
	if ctx.Err() != nil {
		return batch.entityBatch, ctx.Err()
	}
	if bulkErr == nil && !unknown {
		err := batch.accept(values)
		return batch.entityBatch, err
	}
	var failures []error
	if bulkErr != nil {
		failures = append(failures, bulkErr)
	}
	unresolved := entityUnresolved{}
	discovered := false
	if unknown && bulkErr == nil {
		known, dirty, valid, err := p.discover(ctx, reader, input.discovery, targets)
		if err != nil {
			return batch.entityBatch, err
		}
		if valid {
			if err := batch.accept(known); err != nil {
				return batch.entityBatch, err
			}
			unresolved, discovered = dirty, true
		}
	}
	if !discovered {
		work, err := p.evaluateStrictUnits(ctx, input.native, targets, &batch)
		if err != nil {
			return batch.entityBatch, err
		}
		unresolved = work.unresolved
		failures = append(failures, work.failures...)
	}
	work := entityBatchWork{unresolved: unresolved, failures: failures}
	if err := p.projectBatch(ctx, input.symbolic, targets, &batch, &work); err != nil {
		return batch.entityBatch, err
	}

	return batch.entityBatch, errors.Join(work.failures...)
}

// Projection commits only detached, successful unit proofs. Its diagnostics
// aggregate with native failures; reporting conversion errors stop this batch.
func (p *EntityProgram) projectBatch(
	ctx context.Context, input ast.Value, targets map[entitySelector]*ast.Term,
	batch *entityBatchAccumulator, work *entityBatchWork,
) error {
	if len(work.unresolved) == 0 {
		return nil
	}
	session := &entitySession{reader: batch.reader, targets: targets}
	proof, err := p.symbolic.project(context.WithValue(ctx, entitySessionKey{}, session), p, input, work.unresolved)
	batch.symbolic = true
	batch.indeterminate = batch.indeterminate || proof.indeterminate
	if err != nil {
		work.failures = append(work.failures, err)
	}
	return batch.accept(proof.values)
}

// Evaluate complete clauses first. Only an uncertain or failed clause requires
// primary isolation, using the same prepared query and the unchanged Reader.
func (p *EntityProgram) evaluateStrictUnits(
	ctx context.Context, input ast.Value, targets map[entitySelector]*ast.Term, batch *entityBatchAccumulator,
) (entityBatchWork, error) {
	work := entityBatchWork{unresolved: entityUnresolved{}}
	for _, unit := range p.plan.units {
		values, unknown, err := entityNativeAttempt(ctx, p.units[unit.id], batch.reader, input, targets, nil)
		if ctx.Err() != nil {
			return work, ctx.Err()
		}
		if err == nil && !unknown {
			if err := batch.accept(values); err != nil {
				return work, err
			}
			continue
		}
		ids := targets[unit.selector].Value.(*ast.Array)
		if ids.Len() == 0 {
			batch.indeterminate = batch.indeterminate || unknown
			if err != nil {
				work.failures = append(work.failures, err)
			}
			continue
		}
		if err := p.isolateNativeUnit(ctx, input, unit, ids, batch, &work); err != nil {
			return work, err
		}
	}
	return work, nil
}

func (p *EntityProgram) isolateNativeUnit(
	ctx context.Context, input ast.Value, unit entityUnitPlan, ids *ast.Array,
	batch *entityBatchAccumulator, work *entityBatchWork,
) error {
	for i := 0; i < ids.Len(); i++ {
		focused := map[entitySelector]*ast.Term{unit.selector: ast.ArrayTerm(ids.Elem(i))}
		values, unknown, err := entityNativeAttempt(ctx, p.units[unit.id], batch.reader, input, focused, nil)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			work.failures = append(work.failures, err)
			continue
		}
		if unknown {
			work.unresolved[unit.id] = append(work.unresolved[unit.id], ids.Elem(i))
			continue
		}
		if err := batch.accept(values); err != nil {
			return err
		}
	}
	return nil
}

func entityClauseOpaqueErrors(compiler *ast.Compiler, boundary *entityDeferredBoundary, body ast.Body) bool {
	opaque := false
	visited := map[string]bool{}
	var inspect func(ast.Body)
	inspect = func(body ast.Body) {
		ast.WalkExprs(body, func(e *ast.Expr) bool {
			if !e.IsCall() {
				return false
			}
			op := e.Operator().String()
			switch op {
			case "data.iac.raw", "data.iac.value", "data.iac.present", "data.iac.nonnull", "data.iac.valid_key", "data.iac.present_value":
				terms := e.Terms.([]*ast.Term)
				if len(terms) < 3 {
					opaque = true
					return false
				}
				if _, ok := terms[2].Value.(*ast.Array); !ok {
					opaque = true
				} else if _, err := entityPath(terms[2]); err != nil {
					opaque = true
				}
			}
			return false
		})
		ast.WalkRefs(body, func(ref ast.Ref) bool {
			key := ref.String()
			if _, ok := boundary.original[key]; ok {
				opaque = true
				return false
			}
			if !ref.HasPrefix(ast.MustParseRef("data")) || ref.HasPrefix(ast.MustParseRef("data.iac")) || visited[key] {
				return false
			}
			visited[key] = true
			rules := compiler.GetRulesExact(ref)
			if len(rules) == 0 {
				opaque = true
				return false
			}
			for _, root := range rules {
				for r := root; r != nil; r = r.Else {
					inspect(r.Body)
				}
			}
			return false
		})
	}
	inspect(body)
	return opaque
}
