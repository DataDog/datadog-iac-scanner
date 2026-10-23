/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectionView_PrepareOnceConcurrently(t *testing.T) {
	file := &FileMetadata{OriginalData: "from alpine\nrun echo hello\n"}
	file.SetLazyLines()
	var calls, otherCalls atomic.Int32
	prepare := func(lines []string) []string {
		calls.Add(1)
		prepared := slices.Clone(lines)
		prepared[0] = "prepared"
		return prepared
	}
	results := make(chan string, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			results <- file.DetectionView("prepared", prepare).Lines()[0]
			file.DetectionView("other", func(lines []string) []string {
				otherCalls.Add(1)
				return slices.Clone(lines)
			})
		})
	}
	workers.Wait()
	close(results)
	for got := range results {
		require.Equal(t, "prepared", got)
	}
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 1, otherCalls.Load())
	require.Equal(t, "from alpine", file.Lines()[0], "cached preparation must not change source text")
}

func TestDetectionView_IndependentTransformationsAndIndexes(t *testing.T) {
	file := &FileMetadata{OriginalData: "from alpine\nrun echo hello\n"}
	file.SetLazyLines()
	first := file.DetectionView("upper", func(lines []string) []string {
		result := slices.Clone(lines)
		result[0] = "FROM alpine"
		return result
	})
	source := file.DetectionLines("raw", func(lines []string) []string { return slices.Clone(lines) })
	require.Equal(t, "from alpine", source[0])
	second := file.DetectionView("mask", func(lines []string) []string {
		return []string{"", lines[1]}
	})
	require.Equal(t, "FROM alpine", first.Lines()[0])
	require.Equal(t, "", second.Lines()[0])
	indexes, ok := first.LinesContaining("FROM")
	require.True(t, ok)
	require.Equal(t, []int{0}, indexes)
	indexes, ok = second.LinesContaining("FROM")
	require.True(t, ok)
	require.Empty(t, indexes)
	indexes, ok = file.LinesContaining("FROM")
	require.True(t, ok)
	require.Empty(t, indexes)
	require.Equal(t, "from alpine", file.Lines()[0])
}
