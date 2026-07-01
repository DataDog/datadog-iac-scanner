/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestAdjustNumWorkers(t *testing.T) {
	if got := AdjustNumWorkers(7); got != 7 {
		t.Fatalf("explicit count: got %d, want 7", got)
	}
	if got := AdjustNumWorkers(0); got < 1 {
		t.Fatalf("auto-detect must be >= 1, got %d", got)
	}
}

func TestAvailableCPUs(t *testing.T) {
	if got := AvailableCPUs(); got < 1 {
		t.Fatalf("AvailableCPUs must be >= 1, got %d", got)
	}
}

func TestIOWorkerBounds(t *testing.T) {
	if IOMinWorkers < 1 || IOMaxWorkers < IOMinWorkers {
		t.Fatalf("invalid IO bounds [%d,%d]", IOMinWorkers, IOMaxWorkers)
	}
}

func TestForEach_AllItemsProcessedIndexAligned(t *testing.T) {
	const n = 100
	items := make([]int, n)
	for i := range items {
		items[i] = i * 2
	}
	out := make([]int, n)

	err := ForEach(context.Background(), items, PoolOptions{Workers: 8, CPUBound: true},
		func(_ context.Context, item, i int) error {
			out[i] = item + 1 // index-aligned write, no shared mutable state
			return nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := range out {
		if want := i*2 + 1; out[i] != want {
			t.Fatalf("out[%d] = %d, want %d", i, out[i], want)
		}
	}
}

func TestForEach_Empty(t *testing.T) {
	called := false
	err := ForEach(context.Background(), []int{}, PoolOptions{}, func(context.Context, int, int) error {
		called = true
		return nil
	})
	if err != nil || called {
		t.Fatalf("empty slice should not call fn or error; err=%v called=%v", err, called)
	}
}

func TestForEach_FirstErrorReturnedAndCancels(t *testing.T) {
	sentinel := errors.New("boom")
	items := make([]int, 50)
	var ran atomic.Int64

	err := ForEach(context.Background(), items, PoolOptions{Workers: 4},
		func(ctx context.Context, _, i int) error {
			ran.Add(1)
			if i == 0 {
				return sentinel
			}
			// Later items should observe cancellation rather than all running.
			<-ctx.Done()
			return ctx.Err()
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

func TestResolveWorkers_ExplicitCountNotFlooredByMinWorkers(t *testing.T) {
	// An explicit low Workers count is a deliberate concurrency limit and must
	// be honored rather than raised to MinWorkers.
	if got := (PoolOptions{Workers: 2, MinWorkers: IOMinWorkers, MaxWorkers: IOMaxWorkers}).resolveWorkers(100); got != 2 {
		t.Fatalf("explicit low count should be honored, got %d, want 2", got)
	}
	// The floor still lifts an auto-detected count on tiny machines.
	if got := (PoolOptions{Workers: 0, MinWorkers: IOMinWorkers}).resolveWorkers(100); got < IOMinWorkers {
		t.Fatalf("auto-detected count should be floored to %d, got %d", IOMinWorkers, got)
	}
	// The ceiling still caps an explicit count that exceeds it.
	if got := (PoolOptions{Workers: 1000, MaxWorkers: IOMaxWorkers}).resolveWorkers(10000); got != IOMaxWorkers {
		t.Fatalf("explicit count above ceiling should be capped to %d, got %d", IOMaxWorkers, got)
	}
}

func TestForEach_CanceledContextStopsSchedulingAndSurfacesErr(t *testing.T) {
	// A pre-canceled context must surface ctx.Err() and run few (ideally zero)
	// items rather than scheduling a no-op goroutine per element.
	items := make([]int, 10000)
	var ran atomic.Int64

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ForEach(ctx, items, PoolOptions{Workers: 4},
		func(context.Context, int, int) error {
			ran.Add(1)
			return nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if n := ran.Load(); n > int64(len(items)/2) {
		t.Fatalf("canceled run scheduled too many items: %d of %d", n, len(items))
	}
}

func TestForEach_WorkerCapBound(t *testing.T) {
	// CPUBound work must never exceed the shared budget concurrently.
	budget := AvailableCPUs()
	var inFlight, maxInFlight atomic.Int64
	items := make([]int, 200)

	err := ForEach(context.Background(), items, PoolOptions{Workers: 64, CPUBound: true},
		func(context.Context, int, int) error {
			cur := inFlight.Add(1)
			for {
				old := maxInFlight.Load()
				if cur <= old || maxInFlight.CompareAndSwap(old, cur) {
					break
				}
			}
			inFlight.Add(-1)
			return nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if int(maxInFlight.Load()) > budget {
		t.Fatalf("CPU-bound concurrency %d exceeded budget %d", maxInFlight.Load(), budget)
	}
}
