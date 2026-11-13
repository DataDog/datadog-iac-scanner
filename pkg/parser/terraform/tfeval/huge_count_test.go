/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// A module with one sane call and one call whose count cannot be enumerated in
// any machine's lifetime must not panic while planning the huge call, and must
// stop at the context instead of running to completion.
func TestEvaluateModule_HugeCountSiblingDoesNotPanicAndStopsAtTheContext(t *testing.T) {
	fixture := func(t *testing.T) string {
		root := t.TempDir()
		writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
output "out" { value = var.in }
`})
		return writeModule(t, root, "stack", map[string]string{"main.tf": `
module "sane" {
  source = "../child"
  count  = 2
  in     = "sane-${count.index}"
}
module "huge" {
  source = "../child"
  count  = 9223372036854775807
  in     = "huge-${count.index}"
}
`})
	}

	t.Run("already_canceled_context", func(t *testing.T) {
		dir := fixture(t)
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		require.NotPanics(t, func() {
			resources, _, _, err := New().EvaluateModule(canceled, dir, nil)
			require.ErrorIs(t, err, context.Canceled)
			require.Empty(t, resources)
		})
	})

	t.Run("short_deadline", func(t *testing.T) {
		dir := fixture(t)
		deadline, dl := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer dl()
		start := time.Now()
		require.NotPanics(t, func() {
			resources, _, _, err := New().EvaluateModule(deadline, dir, nil)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			// The partial tree is discarded, never returned as a completed
			// evaluation.
			require.Empty(t, resources)
		})
		require.Less(t, time.Since(start), 10*time.Second)
	})
}

// A for_each over a collection far larger than any scan enumerates expands
// many distinct instances and stops at the context; the identical-key shape
// would dedupe to one instance and never exercise the expansion loop.
func TestEvaluateModule_HugeForEachSiblingDoesNotPanicAndStopsAtTheContext(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
	moduleSrc := func(expr string) string {
		return `
module "sane" {
  source = "../child"
  count  = 2
  in     = "sane-${count.index}"
}
module "huge" {
  source   = "../child"
  for_each = ` + expr + `
  in       = "huge-${each.key}"
}
`
	}
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
variable "keys" { type = set(string) }
` + moduleSrc("var.keys")})

	distinctKeys := func(n int) cty.Value {
		values := make([]cty.Value, n)
		for i := range values {
			values[i] = cty.StringVal(fmt.Sprintf("k%07d", i))
		}
		return cty.SetVal(values)
	}

	t.Run("a_moderate_distinct_collection_expands_every_instance", func(t *testing.T) {
		resources, _, _, err := New().EvaluateModule(context.Background(), dir, map[string]cty.Value{
			"keys": distinctKeys(2000),
		})
		require.NoError(t, err)
		require.Len(t, resources, 2002)
	})

	t.Run("a_huge_distinct_collection_stops_at_the_context", func(t *testing.T) {
		// Built before the context: the deadline window is spent expanding,
		// not constructing the input.
		keys := distinctKeys(300000)
		deadline, dl := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer dl()
		start := time.Now()
		require.NotPanics(t, func() {
			resources, _, _, err := New().EvaluateModule(deadline, dir, map[string]cty.Value{
				"keys": keys,
			})
			require.ErrorIs(t, err, context.DeadlineExceeded)
			// The partial tree is discarded, never returned as a completed
			// evaluation.
			require.Empty(t, resources)
		})
		require.Less(t, time.Since(start), 10*time.Second)
	})
}
