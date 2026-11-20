/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"cmp"
	"errors"
	"fmt"

	"slices"
	"strings"

	tfinstances "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// EvaluationDiagnostic is an unrecovered producer error in a completed module
// evaluation. It retains source and module identity, never an evaluation context
// or AST. It is separate from unknown values and from security findings.
type EvaluationDiagnostic struct {
	Summary       string
	Detail        string
	Subject       hcl.Range
	ModuleAddress string
}

type expressionFailure struct{ diagnostics []EvaluationDiagnostic }
type expressionValue struct {
	value   cty.Value
	failure *expressionFailure
}

// evaluateExpression preserves the evaluator's reference-recovery behavior and
// the errors remaining after recovery. Cached values keep that outcome together.
func evaluateExpression(expr hclsyntax.Expression, ctx *hcl.EvalContext) expressionValue {
	value, diagnostics := partial.Evaluate(expr, ctx)
	return expressionOutcome(value, diagnostics, expr.Range())
}

func expressionOutcome(value cty.Value, diagnostics hcl.Diagnostics, fallback hcl.Range) expressionValue {
	result := expressionValue{value: value}
	if failures := evaluationDiagnostics(diagnostics, fallback); len(failures) > 0 {
		result.failure = &expressionFailure{diagnostics: failures}
	}
	return result
}

// evaluationDiagnostics freezes errors at the producer boundary, without keeping
// HCL evaluation contexts or expressions alive through the shared outcome.
func evaluationDiagnostics(diagnostics hcl.Diagnostics, fallback hcl.Range) []EvaluationDiagnostic {
	var failures []EvaluationDiagnostic
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity != hcl.DiagError {
			continue
		}
		subject := fallback
		if diagnostic.Subject != nil {
			subject = *diagnostic.Subject
		}
		failures = append(failures, EvaluationDiagnostic{
			Summary: diagnostic.Summary, Detail: diagnostic.Detail, Subject: subject,
		})
	}
	return failures
}

// expressionDiagnostics replaces failures when a changing local is re-evaluated
// successfully. A speculative context must not publish into this recorder.
type expressionDiagnostics map[hclsyntax.Expression]*expressionFailure

func (d *expressionDiagnostics) update(expr hclsyntax.Expression, result expressionValue) {
	if d == nil {
		return
	}
	if result.failure == nil {
		delete(*d, expr)
		return
	}
	if *d == nil {
		*d = expressionDiagnostics{}
	}
	(*d)[expr] = result.failure
}

// Diagnostics returns a caller-owned inspection snapshot. Discarding or
// modifying it cannot detach producer failures from PolicyUnit.
func (r *ModuleEvaluation) Diagnostics() []EvaluationDiagnostic {
	return slices.Clone(r.diagnostics)
}

// PolicyUnit binds the policy view to the same evaluation's producer failures.
// It does not select subjects or infer inventory completeness; those remain
// responsibilities of the platform adapter constructing the reader.
func (r *ModuleEvaluation) PolicyUnit(reader policy.Reader) policy.Unit {
	if r.failure == nil && len(r.diagnostics) == 0 {
		return &modulePolicyUnit{reader: reader}
	}
	failures := make([]error, 0, len(r.diagnostics)+1)
	if r.failure != nil {
		failures = append(failures, r.failure)
	}
	for i := range r.diagnostics {
		diagnostic := r.diagnostics[i]
		failures = append(failures, &diagnostic)
	}
	return &modulePolicyUnit{reader: reader, failure: errors.Join(failures...)}
}

type modulePolicyUnit struct {
	reader  policy.Reader
	failure error
}

func (u *modulePolicyUnit) Reader() policy.Reader { return u.reader }
func (u *modulePolicyUnit) Failure() error        { return u.failure }

func (d *EvaluationDiagnostic) Error() string {
	location := d.Subject.String()
	if d.ModuleAddress != "" {
		location += " (" + d.ModuleAddress + ")"
	}
	return fmt.Sprintf("%s: %s: %s", location, d.Summary, d.Detail)
}

func (e *Evaluator) collectDiagnostics(addr string, scope *ModuleScope, resources, data []ResolvedResource) {
	seen := map[EvaluationDiagnostic]struct{}{}
	add := func(diagnostics []EvaluationDiagnostic) {
		for _, diagnostic := range diagnostics {
			diagnostic.ModuleAddress = addr
			if _, exists := seen[diagnostic]; exists {
				continue
			}
			seen[diagnostic] = struct{}{}
			e.diagnostics = append(e.diagnostics, diagnostic)
		}
	}
	for diagnostic := range scope.inputDiagnostics {
		add([]EvaluationDiagnostic{diagnostic})
	}
	for _, failure := range scope.diagnostics {
		add(failure.diagnostics)
	}
	for _, group := range [][]ResolvedResource{resources, data} {
		for i := range group {
			if group[i].diagnostics != nil {
				add(group[i].diagnostics.diagnostics)
			}
		}
	}
}

func sortEvaluationDiagnostics(diagnostics []EvaluationDiagnostic) {
	slices.SortFunc(diagnostics, func(a, b EvaluationDiagnostic) int {
		for _, pair := range [][2]string{{a.ModuleAddress, b.ModuleAddress}, {a.Subject.Filename, b.Subject.Filename}} {
			if c := strings.Compare(pair[0], pair[1]); c != 0 {
				return c
			}
		}
		if a.Subject.Start.Byte != b.Subject.Start.Byte {
			return cmp.Compare(a.Subject.Start.Byte, b.Subject.Start.Byte)
		}
		if a.Subject.End.Byte != b.Subject.End.Byte {
			return cmp.Compare(a.Subject.End.Byte, b.Subject.End.Byte)
		}
		if c := strings.Compare(a.Summary, b.Summary); c != 0 {
			return c
		}
		return strings.Compare(a.Detail, b.Detail)
	})
}

// recordModuleFailure retains an authoritative child failure after discarding
// its partial work. Deliberate depth/cycle skips remain coverage observations.
func (e *Evaluator) recordModuleFailure(err error, address string, anchor hcl.Range) {
	if errors.Is(err, ErrModuleNotEvaluated) {
		return
	}
	e.diagnostics = append(e.diagnostics, EvaluationDiagnostic{
		Summary: "Module evaluation failed", Detail: err.Error(), Subject: anchor, ModuleAddress: address,
	})
}

// recordExpansionDiagnostics replaces a block's authoritative planning failure,
// including zero-instance plans which cannot attach errors to a resource.
func recordExpansionDiagnostics(body *hclsyntax.Body, plan *tfinstances.Plan, recorder *expressionDiagnostics) {
	if recorder == nil {
		return
	}
	attr := body.Attributes[tfinstances.KindCount]
	if attr == nil {
		attr = body.Attributes[tfinstances.KindForEach]
	}
	if attr == nil {
		return
	}
	result := expressionValue{}
	if len(plan.Diagnostics) > 0 {
		failure := &expressionFailure{diagnostics: make([]EvaluationDiagnostic, 0, len(plan.Diagnostics))}
		for _, diagnostic := range plan.Diagnostics {
			failure.diagnostics = append(failure.diagnostics, EvaluationDiagnostic{
				Summary: diagnostic.Summary, Detail: diagnostic.Detail, Subject: diagnostic.Subject,
			})
		}
		result.failure = failure
	}
	recorder.update(attr.Expr, result)
}
