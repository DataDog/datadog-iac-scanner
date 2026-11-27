/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package localorder orders the locals of a Terraform module by what they read
// of each other, so each is evaluated once, after the locals it reads. The
// plain Terraform parser orders root-module locals with it; module evaluation
// (tfeval) still keeps its own copy of the same ordering.
package localorder

import "slices"

// Edges returns reads, the declared locals each local reads by index, and
// orders a read of local as a whole (whole) through a barrier vertex,
// numbered len(reads): the whole read waits for the barrier, which waits for
// every local reaching no whole read through named reads. Such a local cannot
// lead back to a whole read, so the barrier closes no cycle, and the whole
// read sees every local it can. Terraform rejects the read itself.
func Edges(reads [][]int, whole []bool) [][]int {
	n := len(reads)
	edges := make([][]int, n+1)
	copy(edges, reads)
	if !slices.Contains(whole, true) {
		return edges
	}
	readers := make([][]int, n)
	for v, read := range reads {
		for _, w := range read {
			readers[w] = append(readers[w], v)
		}
	}
	reachesWhole := make([]bool, n)
	var stack []int
	for v, isWhole := range whole {
		if isWhole && !reachesWhole[v] {
			reachesWhole[v] = true
			stack = append(stack, v)
		}
	}
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, w := range readers[v] {
			if !reachesWhole[w] {
				reachesWhole[w] = true
				stack = append(stack, w)
			}
		}
	}
	for v, isWhole := range whole {
		if isWhole {
			edges[v] = append(slices.Clone(edges[v]), n)
		}
		if !reachesWhole[v] {
			edges[n] = append(edges[n], v)
		}
	}
	return edges
}

// StronglyConnected groups the vertices of a graph into strongly connected
// components, each emitted after every component it has an edge to (Tarjan).
func StronglyConnected(edges [][]int) [][]int {
	n := len(edges)
	visited := make([]int, n) // 0 when unvisited, else the visit order from 1
	low := make([]int, n)
	onStack := make([]bool, n)
	stack := make([]int, 0, n)
	next := 1
	var components [][]int
	var visit func(v int)
	visit = func(v int) {
		visited[v], low[v] = next, next
		next++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range edges[v] {
			switch {
			case visited[w] == 0:
				visit(w)
				low[v] = min(low[v], low[w])
			case onStack[w]:
				low[v] = min(low[v], visited[w])
			}
		}
		if low[v] != visited[v] {
			return
		}
		var members []int
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[w] = false
			members = append(members, w)
			if w == v {
				break
			}
		}
		slices.Sort(members)
		components = append(components, members)
	}
	for v := range n {
		if visited[v] == 0 {
			visit(v)
		}
	}
	return components
}

// Cyclic reports whether component, one StronglyConnected returned for edges,
// is a cycle: several vertices, or one reading itself.
func Cyclic(edges [][]int, component []int) bool {
	return len(component) > 1 || slices.Contains(edges[component[0]], component[0])
}
