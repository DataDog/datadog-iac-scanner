/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// rootsLayout is a layout of roots that call one shared module, so concurrent
// roots read the same parse.
func rootsLayout(t *testing.T, n int) *Layout {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"modules/bucket/main.tf": `
variable "name" {}
variable "n" { default = 2 }
resource "aws_s3_bucket" "b" {
  count  = var.n
  bucket = "${var.name}-${count.index}"
}
`,
	}
	for i := range n {
		files[fmt.Sprintf("root%02d/main.tf", i)] = fmt.Sprintf(`
module "bucket" {
  source = "../modules/bucket"
  name   = "r%d"
  n      = %d
}
resource "aws_s3_bucket" "own" { bucket = "own-%d" }
`, i, i%3+1, i)
	}
	writeTree(t, dir, files)
	layout, err := ScanLayout(context.Background(), dir, &Options{})
	require.NoError(t, err)
	require.Len(t, layout.Roots, n)
	return layout
}

// rootShapes is, per root in the order take received them, the root's ID and
// the addresses of its bucket instances.
func rootShapes(t *testing.T, workers int) []string {
	t.Helper()
	prev := rootWorkers
	rootWorkers = workers
	t.Cleanup(func() { rootWorkers = prev })
	layout := rootsLayout(t, 12)
	var shapes []string
	require.NoError(t, layout.EachRoot(context.Background(), nil, layout.Roots, func(r *Root) error {
		blocks := blocksOf(r, "resource", "aws_s3_bucket")
		shapes = append(shapes, fmt.Sprint(r.ID, addresses(blocks), bucketNames(blocks)))
		return nil
	}))
	return shapes
}

func bucketNames(blocks []*Block) []string {
	var out []string
	for _, b := range blocks {
		for _, inst := range b.Instances {
			out = append(out, fmt.Sprint(conv(inst.Attrs["bucket"])))
		}
	}
	slices.Sort(out)
	return out
}

func TestEachRoot_ConcurrentRootsMatchOneAtATime(t *testing.T) {
	serial := rootShapes(t, 1)
	require.Len(t, serial, 12)
	require.Contains(t, serial[0], "module.bucket.aws_s3_bucket.b[0]")
	require.Equal(t, serial, rootShapes(t, 4), "roots evaluated concurrently reach take in order with the same model")
}

func TestEachRoot_StopsAtTheFirstTakeError(t *testing.T) {
	prev := rootWorkers
	rootWorkers = 4
	t.Cleanup(func() { rootWorkers = prev })
	layout := rootsLayout(t, 12)
	stop := errors.New("stop")
	taken := 0
	err := layout.EachRoot(context.Background(), nil, layout.Roots, func(*Root) error {
		taken++
		if taken == 3 {
			return stop
		}
		return nil
	})
	require.ErrorIs(t, err, stop)
	require.Equal(t, 3, taken)
}

func TestEachRoot_StopsWhenCancelled(t *testing.T) {
	layout := rootsLayout(t, 6)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := layout.EachRoot(ctx, nil, layout.Roots, func(*Root) error { return nil })
	require.ErrorIs(t, err, context.Canceled)
}
