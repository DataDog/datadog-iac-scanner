/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"encoding/json"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// MarshalJSON rejects failed SDK outcomes rather than silently omitting their
// private failure authority. ScanMetadata and report summaries are wire formats.
//
//nolint:gocritic // The 112-byte report-only copy protects encoding/json values and pointers from silently losing failed coverage.
func (r Results) MarshalJSON() ([]byte, error) {
	if r.failedCoverage.Len() > 0 {
		return nil, fmt.Errorf("failed scan results cannot be serialized implicitly; use ScanMetadata or an explicit failure report")
	}
	type plain Results
	return json.Marshal(plain(r))
}

// FailedCoverage returns immutable producer failure authority, not a completeness claim.
func (r *Results) FailedCoverage() model.EvaluationFailures {
	if r == nil {
		return model.EvaluationFailures{}
	}
	return r.failedCoverage
}

// IncompleteScanError preserves ordinary public API error checks while results remain available.
type IncompleteScanError struct{ failures model.EvaluationFailures }

func (e *IncompleteScanError) Error() string {
	return e.failures.Message()
}

// FailedCoverage returns an immutable value whose snapshots are owned by their caller.
func (e *IncompleteScanError) FailedCoverage() model.EvaluationFailures { return e.failures }
