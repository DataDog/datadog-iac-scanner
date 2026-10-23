/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// These guardrails pin how evaluation scales, by structure and ratios rather
// than timings: the cost of an instance does not grow with the number of
// instances, nothing is allocated for instances that are not evaluated, and
// identical evaluations are reused while distinct ones are not.

// fanOut writes a root expanding a module outer times, whose resource block
// expands inner times; every instance has its own inputs.
func fanOut(t *testing.T, outer, inner int) string {
	t.Helper()
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": fmt.Sprintf(`
variable "path" {}
resource "aws_s3_bucket" "b" {
  count  = %d
  bucket = "${var.path}-${count.index}"
  acl    = "private"
  tags   = { owner = "team", path = var.path }
}
output "names" { value = aws_s3_bucket.b[*].bucket }
`, inner)})
	return writeModule(t, root, "stack", map[string]string{"main.tf": fmt.Sprintf(`
module "m" {
  source = "../leaf"
  count  = %d
  path   = "p${count.index}"
}
output "n" { value = length(flatten(module.m[*].names)) }
`, outer)})
}

// allocsPerInstance evaluates stack and returns the allocations and bytes it
// took per resolved instance.
func allocsPerInstance(t *testing.T, stack string, want int) (allocs, bytes float64) {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	require.Len(t, resources, want)
	return float64(after.Mallocs-before.Mallocs) / float64(want), float64(after.TotalAlloc-before.TotalAlloc) / float64(want)
}

// Four times the instances cost four times as much, not more: no work or
// copy is repeated per instance for every other instance or every level.
func TestGuardrail_AllocationsPerInstanceStayFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates tens of thousands of instances")
	}
	smallAllocs, smallBytes := allocsPerInstance(t, fanOut(t, 50, 50), 2500)
	largeAllocs, largeBytes := allocsPerInstance(t, fanOut(t, 100, 100), 10000)
	t.Logf("per instance: %.0f allocs / %.0f bytes at 2500, %.0f allocs / %.0f bytes at 10000",
		smallAllocs, smallBytes, largeAllocs, largeBytes)
	require.Less(t, largeAllocs, smallAllocs*1.25, "allocations per instance grow with the instance count")
	require.Less(t, largeBytes, smallBytes*1.25, "bytes per instance grow with the instance count")
}

// A count far beyond what can be evaluated reserves nothing up front:
// stopped after one check interval, the evaluation has allocated in proportion
// to the instances it evaluated, not to the count it was asked for.
func TestGuardrail_HugeCountIsNotPreallocated(t *testing.T) {
	for _, src := range []string{
		fmt.Sprintf(`resource "aws_s3_bucket" "b" { count = %d }`, math.MaxInt32),
		fmt.Sprintf("module \"m\" {\n  source = \"../leaf\"\n  count  = %d\n}\n", math.MaxInt32),
	} {
		root := t.TempDir()
		writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`})
		stack := writeModule(t, root, "stack", map[string]string{"main.tf": src})
		e := New()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		// The first check, at the start, passes; the next, one interval in, stops.
		ctx := &checksAfter{Context: context.Background(), pass: 1}
		resources, _, _, err := e.EvaluateModule(ctx, stack, nil)
		runtime.ReadMemStats(&after)
		require.ErrorIs(t, err, ErrEvaluationStopped)
		require.Empty(t, resources, "a canceled evaluation returns nothing rather than a prefix")
		require.LessOrEqual(t, e.Report().InstanceEvaluations, 2*cancelCheckEvery)
		require.LessOrEqual(t, e.Report().ModuleEvaluations, 2*cancelCheckEvery)
		require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<20),
			"allocated %d bytes for a count of %d", after.TotalAlloc-before.TotalAlloc, math.MaxInt32)
	}
}

// checksAfter is a context that is canceled once Err has been called more
// than pass times.
type checksAfter struct {
	context.Context
	pass  int
	calls int
}

func (c *checksAfter) Err() error {
	c.calls++
	if c.calls > c.pass {
		return context.Canceled
	}
	return nil
}

// Identical inputs are evaluated once and reused at every other address;
// distinct inputs are each evaluated, and the cache holds no copy for them.
func TestGuardrail_CacheEntriesFollowDistinctInputs(t *testing.T) {
	const n = 200
	for _, c := range []struct {
		name           string
		input          string
		entries, hits  int
		moduleEvaluate int
	}{
		{name: "identical", input: `"same"`, entries: 2, hits: n - 1, moduleEvaluate: 2},
		{name: "distinct", input: `"p${count.index}"`, entries: n + 1, hits: 0, moduleEvaluate: n + 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeModule(t, root, "leaf", map[string]string{"main.tf": passthroughLeaf})
			stack := writeModule(t, root, "stack", map[string]string{"main.tf": fmt.Sprintf(
				"module \"m\" {\n  source = \"../leaf\"\n  count  = %d\n  name   = %s\n}\n", n, c.input)})
			e := New()
			resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
			require.NoError(t, err)
			require.Len(t, resources, n)
			seen := map[string]bool{}
			for _, r := range resources {
				seen[r.ModuleAddress] = true
			}
			require.Len(t, seen, n, "every instance keeps its own address")
			report := e.Report()
			require.Equal(t, c.entries, report.CacheEntries)
			require.Equal(t, c.hits, report.CacheHits)
			require.Equal(t, c.moduleEvaluate, report.ModuleEvaluations)
			require.Equal(t, n, cachedResources(e), "the cache keeps nothing beyond the root's own result")
		})
	}
}
