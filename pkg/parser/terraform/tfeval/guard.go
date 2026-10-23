/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
)

// ErrEvaluationStopped is returned by an evaluation the guard stopped. Nothing
// it evaluated is returned: a stopped evaluation is never passed off as a
// complete one with fewer instances.
var ErrEvaluationStopped = errors.New("tfeval: evaluation stopped")

// Limits are the operational boundaries of one scan's module evaluation.
// Neither caps an expansion: a boundary that is reached stops the evaluation
// in progress, which then fails as a whole and is reported incomplete.
type Limits struct {
	// MaxInstances, when positive, is how many resource and data instances
	// the scan may instantiate, root module included. Zero is unbounded.
	MaxInstances int64
	// MemoryLimit, when positive, stops evaluation once the live heap
	// reaches it. Zero derives it from the Go memory limit (GOMEMLIMIT), and
	// leaves memory unbounded when none is set.
	MemoryLimit uint64
}

// memoryLimitShare is the part of the Go memory limit evaluation may fill
// with live heap before it stops: past it, the collector cannot keep the
// process under the limit and it is about to be killed for memory instead.
const memoryLimitShare = 0.9

// guardCheckEvery is how many steps pass between the cancellation and memory
// checks, which are cheap but not free.
const guardCheckEvery = 1024

// Guard enforces Limits and cancellation for a scan, across every evaluator
// forked for it. Once tripped it stays tripped.
type Guard struct {
	limits    Limits
	instances atomic.Int64

	mu     sync.Mutex
	reason string
	detail string
}

// NewGuard returns a guard enforcing limits.
func NewGuard(limits Limits) *Guard {
	if limits.MemoryLimit == 0 {
		if goLimit := debug.SetMemoryLimit(-1); goLimit > 0 && goLimit < math.MaxInt64 {
			limits.MemoryLimit = uint64(float64(goLimit) * memoryLimitShare)
		}
	}
	return &Guard{limits: limits}
}

// Stopped returns why the guard tripped, or "" when it has not.
func (g *Guard) Stopped() (reason, detail string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reason, g.detail
}

// Instances reports how many instances the guard has counted.
func (g *Guard) Instances() int64 { return g.instances.Load() }

func (g *Guard) trip(reason, detail string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reason == "" {
		g.reason, g.detail = reason, detail
	}
}

func (g *Guard) tripped() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reason != ""
}

// fits reports whether pending more instances stay within the limit,
// tripping the guard when they do not.
func (g *Guard) fits(pending int) bool {
	if limit := g.limits.MaxInstances; limit > 0 && g.instances.Load()+int64(pending) > limit {
		g.trip(ReasonInstanceLimit, fmt.Sprintf("more than %d instances", limit))
		return false
	}
	return true
}

// check verifies cancellation and memory.
func (g *Guard) check(ctx context.Context) bool {
	if err := ctx.Err(); err != nil {
		g.trip(ReasonCanceled, err.Error())
		return false
	}
	if g.limits.MemoryLimit > 0 {
		if live := liveHeapBytes(); live >= g.limits.MemoryLimit {
			g.trip(ReasonMemoryLimit, fmt.Sprintf("live heap %d bytes reached the %d byte boundary", live, g.limits.MemoryLimit))
			return false
		}
	}
	return !g.tripped()
}

var liveHeapSample = []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
var liveHeapMu sync.Mutex

// liveHeapBytes is the heap the last collection found live.
func liveHeapBytes() uint64 {
	liveHeapMu.Lock()
	defer liveHeapMu.Unlock()
	metrics.Read(liveHeapSample)
	if liveHeapSample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return liveHeapSample[0].Value.Uint64()
}

// step is called once per unit of evaluation work and reports whether
// evaluation may go on; every guardCheckEvery steps it checks cancellation and
// memory, which speculative sibling evaluation honors too.
func (e *Evaluator) step(ctx context.Context) bool {
	e.steps++
	if e.steps >= guardCheckEvery {
		e.steps = 0
		return e.guard.check(ctx)
	}
	return !e.guard.tripped()
}

// admit reports whether pending instances, not yet emitted, fit the limit.
// Speculative sibling evaluation emits nothing and is not limited.
func (e *Evaluator) admit(pending int) bool {
	return e.prepassDepth > 0 || e.guard.fits(pending)
}

// emit counts n instances that are part of the evaluation's result.
func (e *Evaluator) emit(n int) bool {
	if e.prepassDepth > 0 || n == 0 {
		return true
	}
	e.guard.instances.Add(int64(n))
	return e.guard.fits(0)
}

// stopped returns ErrEvaluationStopped once the guard has tripped.
func (e *Evaluator) stopped() error {
	if e.guard.tripped() {
		return ErrEvaluationStopped
	}
	return nil
}
