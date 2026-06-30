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
	return atLeastOne(runtime.GOMAXPROCS(-1))
}

func atLeastOne(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// cpuBudget is the process-wide pool of CPU-bound work slots. Every nested
// worker pool that does CPU-heavy work (Rego eval, HCL parsing, file-type
// detection) acquires a slot before working and releases it after. Because the
// budget is shared, deeply nested fan-out (e.g. N services each running its own
// query pool) can no longer oversubscribe the machine: at most AvailableCPUs()
// CPU-bound goroutines run at once, regardless of how the pools nest.
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

// PoolOptions configures ForEach.
type PoolOptions struct {
	// Workers is the desired fan-out width. 0 means auto-detect (AvailableCPUs).
	Workers int
	// MinWorkers, when > 0, raises Workers up to this floor.
	MinWorkers int
	// MaxWorkers, when > 0, caps Workers at this ceiling.
	MaxWorkers int
	// CPUBound, when true, makes each item acquire one slot of the shared CPU
	// budget before running. Leave false for I/O-bound work (file reads, network)
	// so it does not occupy a CPU slot while blocked.
	CPUBound bool
}

func (o PoolOptions) resolveWorkers(items int) int {
	w := AdjustNumWorkers(o.Workers)
	if o.MinWorkers > 0 && w < o.MinWorkers {
		w = o.MinWorkers
	}
	if o.MaxWorkers > 0 && w > o.MaxWorkers {
		w = o.MaxWorkers
	}
	if items > 0 && w > items {
		w = items
	}
	return atLeastOne(w)
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
func ForEach[T any](ctx context.Context, items []T, opts PoolOptions, fn func(ctx context.Context, item T, index int) error) error {
	if len(items) == 0 {
		return nil
	}

	numWorkers := opts.resolveWorkers(len(items))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(numWorkers)

	for i := range items {
		g.Go(func() error {
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

	return g.Wait()
}
