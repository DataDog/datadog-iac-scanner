/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The sizes sit well above the limits earlier engine builds stopped expanding
// past: 50 count/for_each instances per block, 512-entry output shapes and
// 1024 generated dynamic blocks per resource.
const pastLimitN = 600

// every instance of a count/for_each expansion is evaluated, however large.
func TestEvaluateModule_ExpansionsPastTheOldLimitsEvaluateEveryInstance(t *testing.T) {
	keys := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf(`"k%04d"`, i))
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

	t.Run("resource_count", func(t *testing.T) {
		resources := evaluateWithChild(t, New(), map[string]string{"main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "b" {
  count  = %d
  bucket = "bucket-${count.index}"
}
`, pastLimitN)}, callChild)
		require.Len(t, resources, pastLimitN)
		for i := range pastLimitN {
			r := findResource(t, resources, "aws_s3_bucket", fmt.Sprintf("b[%d]", i))
			require.Equal(t, fmt.Sprintf("bucket-%d", i), r.Attributes["bucket"].AsString())
		}
	})

	t.Run("resource_for_each", func(t *testing.T) {
		resources := evaluateWithChild(t, New(), map[string]string{"main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "b" {
  for_each = toset(%s)
  bucket   = "bucket-${each.key}"
}
`, keys(pastLimitN))}, callChild)
		require.Len(t, resources, pastLimitN)
		r := findResource(t, resources, "aws_s3_bucket", fmt.Sprintf("b[%q]", fmt.Sprintf("k%04d", pastLimitN-1)))
		require.Equal(t, fmt.Sprintf("bucket-k%04d", pastLimitN-1), r.Attributes["bucket"].AsString())
	})

	t.Run("data_count", func(t *testing.T) {
		resources := evaluateWithChild(t, New(), map[string]string{"main.tf": fmt.Sprintf(`
data "aws_region" "r" {
  count = %d
}
`, pastLimitN)}, callChild)
		require.Len(t, resources, pastLimitN)
		findResource(t, resources, "aws_region", fmt.Sprintf("r[%d]", pastLimitN-1))
	})

	t.Run("data_for_each", func(t *testing.T) {
		resources := evaluateWithChild(t, New(), map[string]string{"main.tf": fmt.Sprintf(`
data "aws_region" "r" {
  for_each = toset(%s)
}
`, keys(pastLimitN))}, callChild)
		require.Len(t, resources, pastLimitN)
		findResource(t, resources, "aws_region", fmt.Sprintf("r[%q]", fmt.Sprintf("k%04d", pastLimitN-1)))
	})

	t.Run("references_past_the_old_shape", func(t *testing.T) {
		// A reference to an instance past the old per-block cap resolves to
		// that instance's value, not to unknown.
		resources := evaluateWithChild(t, New(), map[string]string{"main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "b" {
  count  = %d
  bucket = "bucket-${count.index}"
}
resource "aws_s3_bucket" "ref" {
  bucket = aws_s3_bucket.b[%d].bucket
}
`, pastLimitN, pastLimitN-1)}, callChild)
		ref := findResource(t, resources, "aws_s3_bucket", "ref")
		require.Equal(t, fmt.Sprintf("bucket-%d", pastLimitN-1), ref.Attributes["bucket"].AsString())
	})

	t.Run("dynamic_blocks_past_the_old_total", func(t *testing.T) {
		resources := evaluateWithChild(t, New(), map[string]string{"main.tf": fmt.Sprintf(`
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = %s
    content {
      from_port = ingress.value
    }
  }
}
`, list(pastLimitN))}, callChild)
		sg := findResource(t, resources, "aws_security_group", "sg")
		blocks := sg.Attributes["ingress"].AsValueSlice()
		require.Len(t, blocks, pastLimitN)
	})
}

// Module outputs past the old shape limit are the tuple or object of every
// instance's outputs, not an unknown.
func TestEvaluateModule_ModuleOutputsPastTheOldShapeAreExact(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		root := t.TempDir()
		writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
output "out" { value = var.in }
`})
		dir := writeModule(t, root, "root", map[string]string{"main.tf": fmt.Sprintf(`
locals {
  last = module.m[%d].out
}
resource "aws_s3_bucket" "probe" { bucket = local.last }
module "m" {
  source = "../child"
  count  = %d
  in     = "out-${count.index}"
}
`, pastLimitN-1, pastLimitN)})
		resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		require.Len(t, resources, pastLimitN+1)
		// A local reading module.m[<last>].out only resolves to its value when
		// the caller's module.m output is the tuple of every instance.
		probe := findResource(t, resources, "aws_s3_bucket", "probe")
		require.Equal(t, fmt.Sprintf("out-%d", pastLimitN-1), probe.Attributes["bucket"].AsString())
	})

	t.Run("for_each", func(t *testing.T) {
		var keyList []string
		for i := 0; i < pastLimitN; i++ {
			keyList = append(keyList, fmt.Sprintf(`"k%04d"`, i))
		}
		root := t.TempDir()
		writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
output "out" { value = var.in }
`})
		dir := writeModule(t, root, "root", map[string]string{"main.tf": fmt.Sprintf(`
locals {
  last = module.m["k%04d"].out
}
resource "aws_s3_bucket" "probe" { bucket = local.last }
module "m" {
  source   = "../child"
  for_each = toset([%s])
  in       = "out-${each.key}"
}
`, pastLimitN-1, strings.Join(keyList, ", "))})
		resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		require.Len(t, resources, pastLimitN+1)
		probe := findResource(t, resources, "aws_s3_bucket", "probe")
		require.Equal(t, fmt.Sprintf("out-k%04d", pastLimitN-1), probe.Attributes["bucket"].AsString())
	})

	t.Run("module_count", func(t *testing.T) {
		root := t.TempDir()
		writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
		dir := writeModule(t, root, "root", map[string]string{"main.tf": fmt.Sprintf(`
module "m" {
  source = "../child"
  count  = %d
  in     = "in-${count.index}"
}
`, pastLimitN)})
		resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		// Module instances keep the child resource's name; the instance index
		// lives in the module address, so every instance is named b.
		var last *ResolvedResource
		for i := range resources {
			if resources[i].Type == "aws_s3_bucket" && resources[i].Attributes["bucket"].AsString() == fmt.Sprintf("in-%d", pastLimitN-1) {
				last = &resources[i]
			}
		}
		require.NotNil(t, last, "the instance past the old per-block cap must be evaluated")
	})
}

// A module whose expansion fully resolves is instantiated, so its directory is
// not also scanned as written.
func TestEvaluateModule_FullyExpandedModuleIsInstantiated(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": fmt.Sprintf(`
module "m" {
  source = "../child"
  count  = %d
  in     = "in-${count.index}"
}
`, pastLimitN)})
	e := New()
	resources, _, visited, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, pastLimitN)
	child := filepath.Join(root, "child")
	require.True(t, visited[child], "the fully instantiated module must be marked as called")
	require.NotContains(t, e.NotEvaluatedDirs(), child)
}
