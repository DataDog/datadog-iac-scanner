/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// moduleDependencyOrder selects single-pass evaluation only when every call's
// changing inputs are explicit sibling outputs, directly or via named locals,
// and those dependencies form a DAG. A coarse module cycle can be valid when
// outputs do not depend on all inputs, so nil preserves existing orchestration
// for cycles and for resource/data-mediated or opaque namespace dependencies.
func moduleDependencyOrder(dp *dirParse) []int {
	n := len(dp.modules)
	if n <= 1 {
		return nil
	}
	names := make(map[string]int, n)
	for i, block := range dp.modules {
		if len(block.Labels) != 1 {
			return nil
		}
		name := block.Labels[0]
		if _, duplicate := names[name]; name == "" || duplicate {
			return nil
		}
		names[name] = i
	}
	graph := moduleOrderGraph{
		names: names, locals: dp.locals,
		edges:  make([][]int, n+len(dp.locals.names)),
		queued: make([]bool, len(dp.locals.names)),
		queue:  make([]int, n, n+len(dp.locals.names)),
	}
	for i := range n {
		graph.queue[i] = i
	}
	for cursor := 0; cursor < len(graph.queue); cursor++ {
		v := graph.queue[cursor]
		if v < n {
			if !graph.readBody(v, dp.modules[v].Body, true) {
				return nil
			}
			continue
		}
		for _, traversal := range graph.locals.exprs[v-n].Variables() {
			if !graph.read(v, traversal) {
				return nil
			}
		}
	}
	return graph.order()
}

// moduleOrderGraph keeps direct edges, including local vertices, instead of
// copying transitive module dependencies into every local alias and consumer.
type moduleOrderGraph struct {
	names  map[string]int
	locals *localGraph
	edges  [][]int
	queued []bool
	queue  []int
}

func (g *moduleOrderGraph) read(v int, t hcl.Traversal) bool {
	const rootEach = "each"
	switch t.RootName() {
	case blockTypeModule:
		name, ok := staticAttributeName(t)
		if !ok {
			return false
		}
		if w, exists := g.names[name]; exists {
			g.edges[v] = append(g.edges[v], w)
		}
	case rootLocal:
		name, ok := staticAttributeName(t)
		if !ok {
			return false
		}
		w, exists := g.locals.index[name]
		if !exists {
			return false
		}
		node := len(g.names) + w
		g.edges[v] = append(g.edges[v], node)
		if !g.queued[w] {
			g.queued[w] = true
			g.queue = append(g.queue, node)
		}
	case rootVar, metaArgCount, rootEach, rootPath, rootTerraform:
	default:
		return false
	}
	return true
}

func (g *moduleOrderGraph) readBody(v int, body *hclsyntax.Body, moduleBody bool) bool {
	for name, attr := range body.Attributes {
		// Provider bindings are references to provider configurations, not
		// child input values. Other bodies may have an ordinary providers key.
		if moduleBody && name == "providers" {
			continue
		}
		for _, traversal := range attr.Expr.Variables() {
			if !g.read(v, traversal) {
				return false
			}
		}
	}
	for _, nested := range body.Blocks {
		if !g.readBody(v, nested.Body, false) {
			return false
		}
	}
	return true
}

func (g *moduleOrderGraph) order() []int {
	order := make([]int, 0, len(g.names))
	for _, component := range stronglyConnected(g.edges) {
		if len(component) > 1 || slices.Contains(g.edges[component[0]], component[0]) {
			return nil
		}
		if component[0] < len(g.names) {
			order = append(order, component[0])
		}
	}
	return order
}
