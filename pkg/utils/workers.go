/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"context"
	"runtime"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// AdjustNumWorkers normalizes a requested worker count. A value of 0 means
// "auto-detect": use the number of CPUs the process may actually use.
func AdjustNumWorkers(workers int) int {
	if workers == 0 {
		return AvailableCPUs()
	}
	return workers
}

// AvailableCPUs returns the number of CPUs this process can realistically use,
// as a whole number >= 1. We trust GOMAXPROCS: as of Go 1.25 the runtime
// initializes GOMAXPROCS from the cgroup CPU bandwidth limit on Linux (and keeps
// it updated), so in a container it already reflects the CPU quota rather than
// the host core count.
func AvailableCPUs() int {
	return max(runtime.GOMAXPROCS(-1), 1)
}

// cpuBudget is the process-wide pool of CPU-bound work slots, sized to
// AvailableCPUs(). Every nested worker pool that does CPU-heavy work (Rego eval,
// HCL parsing) acquires a slot before working and releases it after. Because the
// budget is shared, deeply nested fan-out (e.g. N services each running its own
// query pool) can no longer oversubscribe the machine: at most AvailableCPUs()
// CPU-bound goroutines run at once, regardless of how the pools nest.
//
// The budget equals the core count (no oversubscription): a benchmark sweep over
// oversubscription factors showed >1.0 never helped and slightly hurt, because
// the CPU-bound phase is compute-saturated and extra workers only add scheduler
// and GC contention.
//
// Sizing is lazy and one-shot (sync.Once): the semaphore is created on the first
// CPU-bound scan, by which point GOMAXPROCS has stabilized to the cgroup quota
// (init happens long before any scan). We intentionally do NOT resize if
// GOMAXPROCS later grows — semaphore.Weighted has no resize API, and the only
// case this matters is a long-lived server (serve mode) that captured a
// transient low quota straddling its very first scan. That is a known, accepted
// limitation; a resizable gate was judged not worth the hand-rolled concurrency.
var (
	cpuBudgetOnce sync.Once
	cpuBudget     *semaphore.Weighted
)

func cpuBudgetSem() *semaphore.Weighted {
	cpuBudgetOnce.Do(func() {
		cpuBudget = semaphore.NewWeighted(int64(AvailableCPUs()))
	})
	return cpuBudget
}

// CPUBound runs fn while holding one slot of the process-wide CPU budget. It
// blocks until a slot is free or ctx is canceled (returning ctx.Err()).
func CPUBound(ctx context.Context, fn func() error) error {
	sem := cpuBudgetSem()
	if err := sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer sem.Release(1)
	return fn()
}

// IO worker bounds. I/O-bound pools (file open/read) fan out wider than the
// core count because workers spend most of their time blocked on the kernel, so
// more goroutines than cores keeps the disk/FS queue full. The floor guarantees
// useful parallelism on tiny machines; the ceiling caps open file descriptors.
const (
	IOMinWorkers = 4
	IOMaxWorkers = 64
)

// PoolOptions configures ForEach.
type PoolOptions struct {
	// Workers is the desired fan-out width. 0 means auto-detect (AvailableCPUs).
	Workers int
	// MinWorkers, when > 0, raises an AUTO-DETECTED worker count up to this floor.
	// It does not apply when Workers is set explicitly: an explicit low count is
	// a deliberate concurrency limit and must be honored, not floored.
	MinWorkers int
	// MaxWorkers, when > 0, caps Workers at this ceiling (applies to both
	// auto-detected and explicit counts; e.g. an open-file-descriptor cap).
	MaxWorkers int
	// CPUBound, when true, makes each item acquire one slot of the shared CPU
	// budget before running. Leave false for I/O-bound work (file reads, network)
	// so it does not occupy a CPU slot while blocked.
	CPUBound bool
}

func (o PoolOptions) resolveWorkers(items int) int {
	w := AdjustNumWorkers(o.Workers)
	// The floor lifts a small auto-detected count on tiny machines, but an
	// explicit Workers value is a caller-imposed limit we must not raise.
	if o.Workers == 0 && o.MinWorkers > 0 && w < o.MinWorkers {
		w = o.MinWorkers
	}
	if o.MaxWorkers > 0 && w > o.MaxWorkers {
		w = o.MaxWorkers
	}
	if items > 0 && w > items {
		w = items
	}
	return max(w, 1)
}

// ForEach runs fn over every item using a bounded worker pool. It replaces the
// hand-rolled "jobs channel + N goroutines + WaitGroup + closer" pattern that
// was duplicated across the engine, analyzer and Terraform-module parsers.
//
// fn receives the original slice index so callers can write results into a
// preallocated, index-aligned output slice without sharing mutable state.
//
// If opts.CPUBound is set, each invocation of fn is wrapped in CPUBound so the
// work draws from the shared process-wide CPU budget. The first non-nil error
// cancels the remaining work and is returned.
//
// SetLimit and CPUBound are two distinct limits and both are needed:
//   - g.SetLimit caps goroutines for THIS pool. It bounds fan-out width and
//     memory per pool, and applies to I/O-bound pools too (where it can exceed
//     the core count, e.g. [4,64], so blocked file reads keep the disk busy).
//   - CPUBound draws from a single semaphore shared by ALL pools process-wide.
//     It bounds how much CPU-heavy work runs at once regardless of how pools
//     nest — N per-platform scans each running their own query pool cannot
//     collectively oversubscribe the cores. SetLimit alone can't do this: each
//     pool's limit is independent, so nesting would multiply (N x limit).
func ForEach[T any](ctx context.Context, items []T, opts PoolOptions, fn func(ctx context.Context, item T, index int) error) error {
	if len(items) == 0 {
		return nil
	}

	numWorkers := opts.resolveWorkers(len(items))

	g, gctx := errgroup.WithContext(ctx)
	// Per-pool goroutine cap (fan-out width / memory). The cross-pool CPU cap is
	// the shared semaphore applied via CPUBound below, not this limit.
	g.SetLimit(numWorkers)

	for i := range items {
		// Stop scheduling once the group is canceled (first error or parent
		// cancellation). g.SetLimit throttles launches but does not halt this
		// producer, so without this check a canceled run over a large slice would
		// still queue O(len(items)) no-op goroutines before g.Wait returns.
		if gctx.Err() != nil {
			break
		}
		g.Go(func() error {
			// A goroutine may have been queued behind the SetLimit gate before the
			// group was canceled; skip its work rather than run it needlessly.
			if gctx.Err() != nil {
				return gctx.Err()
			}
			run := func() error { return fn(gctx, items[i], i) }
			if opts.CPUBound {
				return CPUBound(gctx, run)
			}
			return run()
		})
	}

	err := g.Wait()
	if err == nil {
		// Breaking out of the loop above (or launching zero error-returning
		// goroutines) can leave g.Wait with nothing to report even though the run
		// was canceled. Surface the cancellation so callers do not mistake a
		// canceled run for a complete one.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	return err
}
