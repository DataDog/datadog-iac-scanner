/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"encoding/json"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
)

// InspectionResult transfers confirmed findings and retains sealed producer
// failures. A failure snapshot cannot change whether this outcome failed.
// Absence of producer failures does not certify closed or known input values.
type InspectionResult struct {
	Findings       []model.Vulnerability
	failedCoverage model.EvaluationFailures
}

// MarshalJSON rejects failed SDK outcomes rather than silently dropping their
// private failure authority. Report summaries are the supported wire format.
func (r InspectionResult) MarshalJSON() ([]byte, error) {
	if r.failedCoverage.Len() > 0 {
		return nil, fmt.Errorf("failed inspection cannot be serialized implicitly; use FailedCoverage().Report and explicit findings")
	}
	type plain InspectionResult
	return json.Marshal(plain(r))
}

// FailedCoverage returns an immutable value; Snapshot provides owned metadata.
func (r InspectionResult) FailedCoverage() model.EvaluationFailures { return r.failedCoverage }

// IncompleteInspectionError makes failed coverage visible to ordinary public
// API error checks while the matching InspectionResult retains its findings.
// Only the exact top-level type identifies this outcome: an operational error
// joined with it is not a recoverable inspection outcome.
type IncompleteInspectionError struct{ failures model.EvaluationFailures }

func (e *IncompleteInspectionError) Error() string {
	return e.failures.Message()
}

// FailedCoverage returns the immutable failure authority carried by the error.
func (e *IncompleteInspectionError) FailedCoverage() model.EvaluationFailures { return e.failures }

func configurationCoverage(failure *moduleInputFailure, platforms []string, root string) model.EvaluationFailure {
	result := model.EvaluationFailure{Scope: model.EvaluationScope{Kind: "inspection", Platforms: platforms, Root: root}}
	for _, cause := range failure.configuration.Unwrap() {
		diagnostic, ok := cause.(*tfeval.EvaluationDiagnostic)
		if !ok {
			continue
		}
		result.Diagnostics = append(result.Diagnostics, model.EvaluationDiagnostic{
			Summary: diagnostic.Summary, Detail: diagnostic.Detail, ModuleAddress: diagnostic.ModuleAddress,
			Location: model.SourceLocation{
				Filename: diagnostic.Subject.Filename, LineStart: diagnostic.Subject.Start.Line,
				ColumnStart: diagnostic.Subject.Start.Column,
			},
		})
	}
	if len(result.Diagnostics) == 0 {
		result.Diagnostics = []model.EvaluationDiagnostic{{
			Summary: failure.configuration.Error(), Location: model.SourceLocation{Filename: failure.root},
		}}
	}
	return result
}
