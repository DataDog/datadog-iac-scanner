/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"cmp"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// EvaluationDiagnostic is an unrecovered expression error in a completed module
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
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity != hcl.DiagError {
			continue
		}
		subject := fallback
		if diagnostic.Subject != nil {
			subject = *diagnostic.Subject
		}
		if result.failure == nil {
			result.failure = &expressionFailure{}
		}
		result.failure.diagnostics = append(result.failure.diagnostics, EvaluationDiagnostic{
			Summary: diagnostic.Summary, Detail: diagnostic.Detail, Subject: subject,
		})
	}
	return result
}

// expressionDiagnostics replaces failures when a changing local is re-evaluated
// successfully. A speculative context must not publish into this recorder.
type expressionDiagnostics map[hcl.Range]*expressionFailure

func (d *expressionDiagnostics) update(expr hclsyntax.Expression, result expressionValue) {
	if d == nil {
		return
	}
	if result.failure == nil {
		delete(*d, expr.Range())
		return
	}
	if *d == nil {
		*d = expressionDiagnostics{}
	}
	(*d)[expr.Range()] = result.failure
}

// TakeDiagnostics transfers the completed evaluation's expression diagnostics
// to the caller. Cache entries retain independent slices; forks start empty.
// This does not enable CLI reporting or classify unresolved inventory expansion.
func (e *Evaluator) TakeDiagnostics() []EvaluationDiagnostic {
	diagnostics := e.diagnostics
	e.diagnostics = nil
	return diagnostics
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
