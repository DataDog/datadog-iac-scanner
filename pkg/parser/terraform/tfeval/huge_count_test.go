/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

// A for_each over a collection larger than any scan enumerates keeps the call
// unresolved and stops at the context, like the huge count.
func TestEvaluateModule_HugeForEachSiblingDoesNotPanicAndStopsAtTheContext(t *testing.T) {
	var keys []string
	for i := 0; i < 300000; i++ {
		keys = append(keys, `"k"`)
	}
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "sane" {
  source = "../child"
  count  = 2
  in     = "sane-${count.index}"
}
module "huge" {
  source   = "../child"
  for_each = toset([` + strings.Join(keys, ", ") + `])
  in       = "huge-${each.key}"
}
`})

	deadline, dl := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer dl()
	start := time.Now()
	require.NotPanics(t, func() {
		resources, _, _, err := New().EvaluateModule(deadline, dir, nil)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Empty(t, resources)
	})
	require.Less(t, time.Since(start), 10*time.Second)
}
