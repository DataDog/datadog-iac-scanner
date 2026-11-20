/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"encoding/json"
	"fmt"
	"slices"
)

// EvaluationScope names the complete input domain whose evaluation failed.
// Inspection scope includes every document supplied to that inspection; query
// platform metadata does not restrict which documents a legacy rule can read.
type EvaluationScope struct {
	Kind      string   `json:"kind"`
	Platforms []string `json:"platforms,omitempty"`
	Root      string   `json:"root,omitempty"`
}

// EvaluationDiagnostic is an owned, frontend-neutral source fact. It retains
// no evaluator, syntax tree, filesystem, or arbitrary error implementation.
type EvaluationDiagnostic struct {
	Summary       string         `json:"summary"`
	Detail        string         `json:"detail,omitempty"`
	Location      SourceLocation `json:"location,omitempty"`
	ModuleAddress string         `json:"module_address,omitempty"`
}

// EvaluationFailure describes a producer failure, rather than normal unknown
// values or an open inventory. Unknown values do not become operational errors.
type EvaluationFailure struct {
	Scope       EvaluationScope        `json:"scope"`
	Diagnostics []EvaluationDiagnostic `json:"diagnostics"`
}

// EvaluationFailures owns immutable failure facts. An empty value says only
// that no producer failure was recorded; it is not a completeness certificate.
type EvaluationFailures struct{ records []EvaluationFailure }

// NewEvaluationFailures seals caller-owned metadata before it crosses phases.
func NewEvaluationFailures(records []EvaluationFailure) EvaluationFailures {
	return EvaluationFailures{records: cloneEvaluationFailures(records)}
}

// MergeEvaluationFailures aggregates already sealed outcomes. Their nested
// metadata is immutable and can be shared without another deep copy.
func MergeEvaluationFailures(groups ...EvaluationFailures) EvaluationFailures {
	count := 0
	for _, group := range groups {
		count += len(group.records)
	}
	if count == 0 {
		return EvaluationFailures{}
	}
	records := make([]EvaluationFailure, 0, count)
	for _, group := range groups {
		records = append(records, group.records...)
	}
	return EvaluationFailures{records: records}
}

// Len returns the number of failed scopes, not the number of unknown reads.
func (f EvaluationFailures) Len() int { return len(f.records) }

// Snapshot returns owned inspection data. Mutating it cannot erase a failure
// or change a later report generated from the sealed outcome.
func (f EvaluationFailures) Snapshot() []EvaluationFailure {
	return cloneEvaluationFailures(f.records)
}

func cloneEvaluationFailures(records []EvaluationFailure) []EvaluationFailure {
	cloned := slices.Clone(records)
	for index := range cloned {
		cloned[index].Scope.Platforms = slices.Clone(cloned[index].Scope.Platforms)
		cloned[index].Diagnostics = slices.Clone(cloned[index].Diagnostics)
	}
	return cloned
}

// MarshalJSON rejects implicit serialization of failed SDK ownership state.
// Call Report or Snapshot to explicitly choose its detached wire representation.
func (f EvaluationFailures) MarshalJSON() ([]byte, error) {
	if len(f.records) > 0 {
		return nil, fmt.Errorf("failed evaluation ownership cannot be serialized implicitly; use Report or Snapshot")
	}
	return []byte("{}"), nil
}

// EvaluationReport is a detached serialization snapshot, never failure authority.
type EvaluationReport struct {
	Status   string              `json:"status"`
	Failures []EvaluationFailure `json:"failures"`
}

// Report projects failures without asserting success or completeness for an empty value.
func (f EvaluationFailures) Report() *EvaluationReport {
	if len(f.records) == 0 {
		return nil
	}
	return &EvaluationReport{Status: "failed", Failures: f.Snapshot()}
}

// EvaluationFailuresFromReport validates and seals serialized failure metadata.
func EvaluationFailuresFromReport(report *EvaluationReport) (EvaluationFailures, error) {
	if report == nil {
		return EvaluationFailures{}, nil
	}
	if report.Status != "failed" || len(report.Failures) == 0 {
		return EvaluationFailures{}, fmt.Errorf("invalid failed evaluation report")
	}
	return NewEvaluationFailures(report.Failures), nil
}

// FailedCoverage returns immutable producer failures retained by the report summary.
func (s *Summary) FailedCoverage() EvaluationFailures { return s.failedCoverage }

//nolint:gocritic // encoding/json must retain failed coverage for values and pointers; this copy occurs only when reporting.
func (s Summary) MarshalJSON() ([]byte, error) {
	type plain Summary
	return json.Marshal(struct {
		plain
		Evaluation *EvaluationReport `json:"evaluation,omitempty"`
	}{plain: plain(s), Evaluation: s.failedCoverage.Report()})
}

func (s *Summary) UnmarshalJSON(data []byte) error {
	type plain Summary
	var wire struct {
		plain
		Evaluation *EvaluationReport `json:"evaluation"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	failures, err := EvaluationFailuresFromReport(wire.Evaluation)
	if err != nil {
		return err
	}
	*s = Summary(wire.plain)
	s.failedCoverage = failures
	return nil
}

// Message renders the original source point and cause without exposing mutable authority.
func (d *EvaluationDiagnostic) Message() string {
	message := d.Summary
	if d.Detail != "" {
		message += ": " + d.Detail
	}
	if d.Location.Filename != "" {
		message = fmt.Sprintf("%s:%d:%d: %s", d.Location.Filename, d.Location.LineStart, d.Location.ColumnStart, message)
	}
	if d.ModuleAddress != "" {
		message += " (" + d.ModuleAddress + ")"
	}
	return message
}

// Message summarizes failed scopes without treating unknown values as failures.
func (f EvaluationFailures) Message() string {
	if len(f.records) == 0 {
		return ""
	}
	message := fmt.Sprintf("%d evaluation input scopes failed", len(f.records))
	if len(f.records[0].Diagnostics) > 0 {
		message += ": " + f.records[0].Diagnostics[0].Message()
	}
	return message
}
