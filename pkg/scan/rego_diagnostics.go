/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"errors"
	"sort"

	"github.com/open-policy-agent/opa/v1/ast"
)

// customRuleFileName is the name OPA and Regal parse the rule under, and the filename
// reported back in diagnostics.
const customRuleFileName = "query.rego"

// RegoValidationError is a single diagnostic about a custom rule. Every diagnostic means
// the rule is broken, so there is no severity to carry.
//
// Messages and locations come straight from OPA or Regal and are never rewritten: those
// tools already produce accurate diagnostics, and second-guessing them by inspecting
// source text drifts out of sync with the language.
type RegoValidationError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	StartLine int    `json:"start_line"`
	StartCol  int    `json:"start_col"`
	EndLine   int    `json:"end_line"`
	EndCol    int    `json:"end_col"`
}

// finalizeDiagnostics drops duplicates and orders diagnostics by source position, with
// unlocated ones last. OPA and Regal can report the same problem, and OPA itself may
// repeat one across phases.
func finalizeDiagnostics(errs []RegoValidationError) []RegoValidationError {
	type key struct {
		code    string
		message string
		line    int
		col     int
	}

	seen := make(map[key]bool, len(errs))
	out := make([]RegoValidationError, 0, len(errs))
	for _, e := range errs {
		k := key{e.Code, e.Message, e.StartLine, e.StartCol}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.StartLine == 0) != (b.StartLine == 0) {
			return b.StartLine == 0
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.StartCol < b.StartCol
	})

	return out
}

// regoValidationErrorsFrom converts OPA errors to diagnostics, preserving OPA's codes,
// messages, and locations verbatim.
func regoValidationErrorsFrom(err error) []RegoValidationError {
	var astErrs ast.Errors
	if !errors.As(err, &astErrs) {
		return []RegoValidationError{{Code: ast.CompileErr, Message: err.Error()}}
	}

	out := make([]RegoValidationError, 0, len(astErrs))
	for _, e := range astErrs {
		out = append(out, regoValidationErrorFromAST(e))
	}
	return out
}

func regoValidationErrorFromAST(e *ast.Error) RegoValidationError {
	ve := RegoValidationError{
		Code:    e.Code,
		Message: e.Message,
	}
	if e.Location != nil {
		ve.StartLine = e.Location.Row
		ve.StartCol = e.Location.Col
		ve.EndLine = e.Location.Row
		ve.EndCol = e.Location.Col + 1
		if len(e.Location.Text) > 0 {
			ve.EndCol = e.Location.Col + len(e.Location.Text)
		}
	}
	return ve
}
