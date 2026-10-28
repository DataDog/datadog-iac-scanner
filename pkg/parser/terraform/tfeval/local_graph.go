/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"maps"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// localGraph is what the locals of a module directory read of each other and
// of the roots that change during evaluation. It depends on the module's HCL
// alone, so it is built once per parse and shared by every evaluation of the
// module. It gives the order the locals resolve in, the roots each local
// follows, what each local reads that sibling module calls change, and the
// data blocks reading their own result.
type localGraph struct {
	names []string
	index map[string]int
	exprs []hclsyntax.Expression
	// reads holds the declared locals each local reads by name, by index;
	// whole is set for a local reading local as a whole.
	reads [][]int
	whole []bool

	// order holds the locals in dependency order: each comes after the locals
	// it reads, except the other members of its cycle. cyclic is set for the
	// locals in a cycle, which Terraform rejects and evaluation reads as
	// unknown; cycles lists the names of each cycle. rank is each local's
	// position in order.
	order  []int
	rank   []int
	cyclic []bool
	cycles [][]string

	// deps classifies each local by the roots changing during evaluation it
	// reads, directly or through other locals. readsResources and readsModules
	// are set when some local reads the module's resources or module.*.
	deps           []localDeps
	readsResources bool
	readsModules   bool
	// dataLocals are the locals reading data.*, and dataOrder the same locals
	// in dependency order.
	dataLocals map[string]bool
	dataOrder  []int
	// siblings is what each local reads that the module calls can change.
	siblings []siblingReads

	// dataBlocks are the module's data blocks, and cyclicData those reading
	// their own result through other data blocks and locals, found once per
	// directory by cyclicDataBlocks.
	dataBlocks []*hclsyntax.Block
	cyclicData map[*hclsyntax.Block]bool
}

// localDeps records which changing roots a local's value follows. The
// classification is transitive: a local reading another local that reads
// resources is marked as reading resources too.
type localDeps struct {
	resources bool
	modules   bool
	data      bool
}

func (d localDeps) or(o localDeps) localDeps {
	return localDeps{resources: d.resources || o.resources, modules: d.modules || o.modules, data: d.data || o.data}
}

// newLocalGraph builds the graph of a module's locals and data blocks.
// resourceTypes are the resource types the module declares.
func newLocalGraph(
	exprs map[string]hclsyntax.Expression, resourceTypes map[string]struct{}, dataBlocks []*hclsyntax.Block,
) *localGraph {
	names := slices.Sorted(maps.Keys(exprs))
	n := len(names)
	g := &localGraph{
		names:      names,
		index:      make(map[string]int, n),
		exprs:      make([]hclsyntax.Expression, n),
		reads:      make([][]int, n),
		whole:      make([]bool, n),
		rank:       make([]int, n),
		cyclic:     make([]bool, n),
		deps:       make([]localDeps, n),
		siblings:   make([]siblingReads, n),
		dataBlocks: dataBlocks,
	}
	for i, name := range names {
		g.index[name] = i
		g.exprs[i] = exprs[name]
	}
	g.sortLocals(g.noteReads(resourceTypes))
	g.cyclicData = cyclicDataBlocks(dataBlocks, exprs)
	return g
}

// noteReads records what each local reads, and returns the changing roots
// each reads directly, with one more entry for the barrier of orderingEdges.
func (g *localGraph) noteReads(resourceTypes map[string]struct{}) []localDeps {
	direct := make([]localDeps, len(g.names)+1)
	for i, expr := range g.exprs {
		for _, t := range expr.Variables() {
			g.siblings[i].add(t)
			root := t.RootName()
			_, resource := resourceTypes[root]
			direct[i].resources = direct[i].resources || resource
			direct[i].modules = direct[i].modules || root == blockTypeModule
			direct[i].data = direct[i].data || root == blockTypeData
			if root != rootLocal {
				continue
			}
			if name, ok := terraform.LocalTraversalName(t); !ok {
				g.whole[i] = true
			} else if j, declared := g.index[name]; declared {
				g.reads[i] = append(g.reads[i], j)
			}
		}
		g.readsResources = g.readsResources || direct[i].resources
		g.readsModules = g.readsModules || direct[i].modules
	}
	return direct
}

// sortLocals puts the locals in dependency order, finds their cycles and
// classifies each by the changing roots it follows, from deps, what each reads
// directly. The components come in dependency order, so the classification of
// every local a component reads is final when it is visited, and the members
// of a cycle share theirs.
func (g *localGraph) sortLocals(deps []localDeps) {
	n := len(g.names)
	edges := g.orderingEdges()
	for _, c := range stronglyConnected(edges) {
		var follows localDeps
		for _, v := range c {
			follows = follows.or(deps[v])
			for _, w := range edges[v] {
				follows = follows.or(deps[w])
			}
		}
		for _, v := range c {
			deps[v] = follows
		}
		if c[0] == n {
			continue // the barrier ordering whole-local reads
		}
		cyclic := len(c) > 1 || slices.Contains(edges[c[0]], c[0])
		var cycle []string
		for _, v := range c {
			g.rank[v] = len(g.order)
			g.order = append(g.order, v)
			g.cyclic[v] = cyclic
			if cyclic {
				cycle = append(cycle, rootLocal+"."+g.names[v])
			}
		}
		if cyclic {
			g.cycles = append(g.cycles, cycle)
		}
	}
	g.dataLocals = map[string]bool{}
	for _, v := range g.order {
		g.deps[v] = deps[v]
		if deps[v].data {
			g.dataLocals[g.names[v]] = true
			g.dataOrder = append(g.dataOrder, v)
		}
	}
}

// orderingEdges returns the reads of each local, and orders a read of local as
// a whole through a barrier vertex, numbered after the locals: the whole read
// waits for the barrier, which waits for every local reaching no whole read
// through named reads. Such a local cannot lead back to a whole read, so the
// barrier closes no cycle, and the whole read sees every local it can.
// Terraform rejects the read itself.
func (g *localGraph) orderingEdges() [][]int {
	n := len(g.names)
	edges := make([][]int, n+1)
	copy(edges, g.reads)
	if !slices.Contains(g.whole, true) {
		return edges
	}
	readers := make([][]int, n)
	for v, reads := range g.reads {
		for _, w := range reads {
			readers[w] = append(readers[w], v)
		}
	}
	reachesWhole := make([]bool, n)
	var stack []int
	for v, whole := range g.whole {
		if whole && !reachesWhole[v] {
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
	for v, whole := range g.whole {
		if whole {
			edges[v] = append(slices.Clone(edges[v]), n)
		}
		if !reachesWhole[v] {
			edges[n] = append(edges[n], v)
		}
	}
	return edges
}

// stronglyConnected groups the vertices of a graph into strongly connected
// components, each emitted after every component it has an edge to (Tarjan).
func stronglyConnected(edges [][]int) [][]int {
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

// readable is the local.* a local is evaluated against: the locals it reads,
// or all of values for a read of local as a whole. A local it reads that has
// no value yet is absent, so try and can fall back past it; an unknown value
// is present, and they do not.
func (g *localGraph) readable(v int, values map[string]cty.Value) cty.Value {
	if g.whole[v] {
		return objectOrEmpty(values)
	}
	attrs := make(map[string]cty.Value, len(g.reads[v]))
	for _, w := range g.reads[v] {
		if value, ok := values[g.names[w]]; ok {
			attrs[g.names[w]] = value
		}
	}
	return objectOrEmpty(attrs)
}

// resolveLocals evaluates the locals of g listed in members, which are in
// dependency order, once each and into values. values holds the other locals
// the members read, at the value they keep. A local in a cycle is unknown, as
// Terraform rejects the cycle.
func (e *Evaluator) resolveLocals(g *localGraph, base *hcl.EvalContext, values map[string]cty.Value, members []int) {
	for _, v := range members {
		name := g.names[v]
		if g.cyclic[v] {
			values[name] = cty.DynamicVal
			continue
		}
		ctx := base.NewChild()
		ctx.Variables = map[string]cty.Value{rootLocal: g.readable(v, values)}
		values[name] = e.localValue(g.exprs[v], ctx)
	}
}
