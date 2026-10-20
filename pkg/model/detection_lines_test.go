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

func TestDetectionLines_PrepareOnceConcurrently(t *testing.T) {
	file := &FileMetadata{OriginalData: "from alpine\nrun echo hello\n"}
	file.SetLazyLines()
	var calls atomic.Int32
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
			results <- file.DetectionLines(prepare)[0]
		})
	}
	workers.Wait()
	close(results)
	for got := range results {
		require.Equal(t, "prepared", got)
	}
	require.EqualValues(t, 1, calls.Load())
	require.Equal(t, "from alpine", file.Lines()[0], "cached preparation must not change source text")
}
