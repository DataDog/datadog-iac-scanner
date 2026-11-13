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
	"github.com/zclconf/go-cty/cty"
)

// A scan that is canceled or timed out stops expanding promptly, however large
// the expansion is: the context error comes back, nothing partial is returned,
// and the partial tree is not memoized. Every expansion shape is covered by
// one row of this table; each row runs with an already-canceled context and
// with a short deadline that expires mid-expansion.
func TestEvaluateModule_StopsWhenTheContextIsDone(t *testing.T) {
	// distinctKeys builds a for_each collection whose enumeration cannot
	// finish inside the deadline window.
	distinctKeys := func(n int) cty.Value {
		values := make([]cty.Value, n)
		for i := range values {
			values[i] = cty.StringVal(fmt.Sprintf("k%06d", i))
		}
		return cty.SetVal(values)
	}
	literalList := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("%d", i)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}

	// callerWithChild returns a stack directory calling child with the given
	// body, plus the inputs its evaluation reads.
	callerWithChild := func(t *testing.T, callBody string) (dir string, inputs map[string]cty.Value) {
		t.Helper()
		root := t.TempDir()
		writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
		dir = writeModule(t, root, "stack", map[string]string{"main.tf": callBody})
		return dir, nil
	}

	rows := map[string]struct {
		fixture func(t *testing.T) (dir string, inputs map[string]cty.Value)
	}{
		"huge resource count": {fixture: func(t *testing.T) (string, map[string]cty.Value) {
			return writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" {
  count  = 1000000000000
  bucket = "b-${count.index}"
}
`}), nil
		}},
		"huge resource for_each": {fixture: func(t *testing.T) (string, map[string]cty.Value) {
			return writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
variable "keys" { type = set(string) }
resource "aws_s3_bucket" "b" {
  for_each = var.keys
  bucket   = "b-${each.key}"
}
`}), map[string]cty.Value{"keys": distinctKeys(100000)}
		}},
		"huge data for_each": {fixture: func(t *testing.T) (string, map[string]cty.Value) {
			// The keys arrive as an input variable, and each data instance
			// renders a computed policy document, so the expansion outlasts
			// the deadline.
			return writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
variable "keys" { type = set(string) }
data "aws_iam_policy_document" "p" {
  for_each = var.keys
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::bucket-${each.key}"]
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`}), map[string]cty.Value{"keys": distinctKeys(50000)}
		}},
		"huge dynamic block": {fixture: func(t *testing.T) (string, map[string]cty.Value) {
			return writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
locals {
  rules = ` + literalList(300000) + `
}
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = local.rules
    content {
      from_port = ingress.value
    }
  }
}
`}), nil
		}},
		"huge module count": {fixture: func(t *testing.T) (string, map[string]cty.Value) {
			return callerWithChild(t, `
module "m" {
  source = "../child"
  count  = 1000000000000
  in     = "in-${count.index}"
}
`)
		}},
		"huge module for_each": {fixture: func(t *testing.T) (string, map[string]cty.Value) {
			dir, _ := callerWithChild(t, `
variable "keys" { type = set(string) }
module "m" {
  source   = "../child"
  for_each = var.keys
  in       = "in-${each.key}"
}
`)
			return dir, map[string]cty.Value{"keys": distinctKeys(100000)}
		}},
	}

	for name, row := range rows {
		t.Run(name, func(t *testing.T) {
			dir, inputs := row.fixture(t)

			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			require.NotPanics(t, func() {
				resources, outputs, _, err := New().EvaluateModule(canceled, dir, inputs)
				require.ErrorIs(t, err, context.Canceled)
				require.Empty(t, resources)
				require.Empty(t, outputs)
			})

			// The deadline expires mid-expansion: the shapes above cannot
			// finish enumerating inside it. The result is the context error,
			// never a partial tree.
			deadline, dl := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer dl()
			require.NotPanics(t, func() {
				resources, _, _, err := New().EvaluateModule(deadline, dir, inputs)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.Empty(t, resources)
			})
		})
	}

	// A canceled evaluation is not memoized: a deadline that expires
	// mid-expansion leaves nothing cached, so a fresh evaluation of the same
	// evaluator runs to completion and produces every instance.
	t.Run("a_canceled_evaluation_is_not_cached", func(t *testing.T) {
		root := t.TempDir()
		writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
		dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "m" {
  source = "../child"
  count  = 50000
  in     = "in-${count.index}"
}
`})
		e := New()
		deadline, dl := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _, _, err := e.EvaluateModule(deadline, dir, nil)
		dl()
		require.ErrorIs(t, err, context.DeadlineExceeded)

		// A reused partial root would come back short or with the context
		// error; a fresh evaluation produces every instance.
		resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		require.Len(t, resources, 50000)
	})
}
