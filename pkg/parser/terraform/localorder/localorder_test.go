/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package localorder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStronglyConnectedOrdersDependenciesFirst(t *testing.T) {
	// 0 reads 1, 1 reads 2; 3 and 4 read each other; 5 reads itself.
	edges := Edges([][]int{{1}, {2}, nil, {4}, {3}, {5}}, make([]bool, 6))
	var order [][]int
	for _, c := range StronglyConnected(edges) {
		if c[0] == 6 {
			continue
		}
		order = append(order, c)
	}
	pos := map[int]int{}
	for i, c := range order {
		for _, v := range c {
			pos[v] = i
		}
	}
	require.Less(t, pos[2], pos[1])
	require.Less(t, pos[1], pos[0])
	require.Equal(t, pos[3], pos[4])
	for _, c := range order {
		switch c[0] {
		case 3, 5:
			require.True(t, Cyclic(edges, c), "%v", c)
		default:
			require.False(t, Cyclic(edges, c), "%v", c)
		}
	}
}

func TestEdgesOrderWholeReadsAfterOtherLocals(t *testing.T) {
	// 0 reads local as a whole; 1 reads 2; 3 reads 0.
	reads := [][]int{nil, {2}, nil, {0}}
	whole := []bool{true, false, false, false}
	edges := Edges(reads, whole)
	pos := map[int]int{}
	for i, c := range StronglyConnected(edges) {
		require.False(t, Cyclic(edges, c), "%v", c)
		for _, v := range c {
			pos[v] = i
		}
	}
	require.Less(t, pos[1], pos[0])
	require.Less(t, pos[2], pos[0])
	require.Less(t, pos[0], pos[3])
}
