/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A scan that is canceled or timed out stops expanding promptly, however large
// the expansion is, and reports the context error rather than a partial result.
func TestEvaluateModule_StopsWhenTheContextIsDone(t *testing.T) {
	keys := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf(`"k%06d"`, i))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	list := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("%d", i))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	fixtures := map[string]func(t *testing.T) string{
		// A count far past any machine's memory: any up-front sizing would
		// panic or OOM before the context is ever checked.
		"huge resource count": func(t *testing.T) string {
			return writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" {
  count  = 1000000000000
  bucket = "b-${count.index}"
}
`})
		},
		"huge resource for_each": func(t *testing.T) string {
			return writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": fmt.Sprintf(`
locals {
  keys = toset(%s)
}
resource "aws_s3_bucket" "b" {
  for_each = local.keys
  bucket   = "b-${each.key}"
}
`, keys(100000))})
		},
		"huge module count": func(t *testing.T) string {
			root := t.TempDir()
			writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
			return writeModule(t, root, "stack", map[string]string{"main.tf": `
module "m" {
  source = "../child"
  count  = 1000000000000
  in     = "in-${count.index}"
}
`})
		},
		"huge module for_each": func(t *testing.T) string {
			root := t.TempDir()
			writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
			return writeModule(t, root, "stack", map[string]string{"main.tf": fmt.Sprintf(`
locals {
  keys = toset(%s)
}
module "m" {
  source   = "../child"
  for_each = local.keys
  in       = "in-${each.key}"
}
`, keys(100000))})
		},
		"huge dynamic block": func(t *testing.T) string {
			return writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": fmt.Sprintf(`
locals {
  rules = [%s]
}
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = local.rules
    content {
      from_port = ingress.value
    }
  }
}
`, list(100000))})
		},
	}

	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			dir := fixture(t)
			// Already canceled: nothing further may be evaluated.
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			start := time.Now()
			resources, outputs, _, err := New().EvaluateModule(canceled, dir, nil)
			require.ErrorIs(t, err, context.Canceled)
			require.Empty(t, resources)
			require.Empty(t, outputs)

			// A short deadline: expansion must stop within it, not run to
			// completion or until some generous outer bound.
			deadline, dl := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer dl()
			start = time.Now()
			_, _, _, err = New().EvaluateModule(deadline, dir, nil)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Less(t, time.Since(start), 10*time.Second, "expansion must stop promptly at the deadline")
		})
	}
}

// A canceled evaluation is not memoized: the next evaluation on the same
// evaluator re-evaluates rather than reusing the partial result.
func TestEvaluateModule_CanceledEvaluationIsNotCached(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "m" {
  source = "../child"
  count  = 200000
  in     = "in-${count.index}"
}
`})
	e := New()
	deadline, dl := context.WithTimeout(context.Background(), 100*time.Millisecond)
	resources, _, _, err := e.EvaluateModule(deadline, dir, nil)
	dl()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	// The partial root is discarded, not returned as a completed evaluation.
	require.Empty(t, resources)

	resources, _, _, err = e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 200000)
}

// The iterators a data block's expansion would consume respect the context
// through the module data refresh as well.
func TestEvaluateModule_DataExpansionStopsWhenTheContextIsDone(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
locals {
  rules = [for i in range(100000) : i]
}
data "aws_iam_policy_document" "p" {
  dynamic "statement" {
    for_each = local.rules
    content {
      actions   = ["s3:GetObject"]
      resources = ["arn:${statement.value}"]
    }
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	resources, _, _, err := New().EvaluateModule(canceled, dir, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, resources)
}
