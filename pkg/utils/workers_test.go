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
