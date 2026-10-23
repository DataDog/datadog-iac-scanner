/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"errors"
)

// ErrEvaluationStopped is returned by an evaluation the scan's cancellation
// stopped. Nothing it evaluated is returned.
var ErrEvaluationStopped = errors.New("tfeval: evaluation canceled")

// cancelCheckEvery is how many steps pass between cancellation checks.
const cancelCheckEvery = 1024

// step is called once per unit of evaluation work and reports whether
// evaluation may go on: every cancelCheckEvery steps it checks whether the
// scan was canceled, so a canceled scan stops within a bounded amount of work.
func (e *Evaluator) step(ctx context.Context) bool {
	if e.canceled != nil {
		return false
	}
	e.steps++
	if e.steps >= cancelCheckEvery {
		e.steps = 0
		e.canceled = ctx.Err()
	}
	return e.canceled == nil
}

// stopped returns ErrEvaluationStopped once evaluation has noticed the scan
// was canceled.
func (e *Evaluator) stopped() error {
	if e.canceled != nil {
		return ErrEvaluationStopped
	}
	return nil
}
