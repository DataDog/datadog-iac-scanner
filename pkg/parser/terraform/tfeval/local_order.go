/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// cycleMaxPasses caps the resolution passes of locals that read each other,
// which Terraform rejects.
const cycleMaxPasses = 10

// localGraph is a module's locals and the locals each one reads, grouped into
// components in dependency order: a component only reads the components
// before it and itself. It depends on the module's HCL alone, so it is built
// once per parse and shared by every evaluation of the module.
type localGraph struct {
	names []string
	exprs []hclsyntax.Expression
	// roots holds the distinct root names each local reads.
	roots [][]string
	// reads holds the declared locals each local reads, by index. A local
	// reading local.* without naming a local reads every other local.
	reads      [][]int
	whole      []bool
	components []localComponent
	// cycles lists the locals of each cycle the way Terraform reports one.
	cycles []string

	// deps classifies each local by the roots that change during evaluation
	// it reads, directly or through other locals; dataLocals are the locals
	// reading data.*. readsResources and readsModules are set when a local
	// reads the module's resources or module.* directly.
	deps           map[string]localDeps
	dataLocals     map[string]bool
	readsResources bool
	readsModules   bool
}

// localComponent is a local, or locals that read each other.
type localComponent struct {
	members []int
	cyclic  bool
}

// newLocalGraph builds the graph of a module's locals. resourceTypes are the
// resource types the module declares.
func newLocalGraph(exprs map[string]hclsyntax.Expression, resourceTypes map[string]struct{}) *localGraph {
	names := slices.Sorted(maps.Keys(exprs))
	index := make(map[string]int, len(names))
	for i, name := range names {
		index[name] = i
	}
	g := &localGraph{
		names: names,
		exprs: make([]hclsyntax.Expression, len(names)),
		roots: make([][]string, len(names)),
		reads: make([][]int, len(names)),
		whole: make([]bool, len(names)),
	}
	for i, name := range names {
		g.note(i, exprs[name], index)
	}
	g.components = orderComponents(g.reads)
	for _, c := range g.components {
		if !c.cyclic {
			continue
		}
		refs := make([]string, len(c.members))
		for i, v := range c.members {
			refs[i] = rootLocal + "." + names[v]
		}
		g.cycles = append(g.cycles, strings.Join(refs, ", "))
	}
	g.classify(resourceTypes)
	return g
}

// note records what one local reads: its root names and the locals it reads.
// A read of local as a whole reads every other local.
func (g *localGraph) note(i int, expr hclsyntax.Expression, index map[string]int) {
	g.exprs[i] = expr
	for _, t := range expr.Variables() {
		g.roots[i] = append(g.roots[i], t.RootName())
		if t.RootName() != rootLocal {
			continue
		}
		read, ok := terraform.LocalTraversalName(t)
		if !ok {
			g.whole[i] = true
			continue
		}
		if j, declared := index[read]; declared {
			g.reads[i] = append(g.reads[i], j)
		}
	}
	slices.Sort(g.roots[i])
	g.roots[i] = slices.Compact(g.roots[i])
	slices.Sort(g.reads[i])
	g.reads[i] = slices.Compact(g.reads[i])
	if g.whole[i] {
		g.reads[i] = make([]int, 0, len(g.names)-1)
		for j := range g.names {
			if j != i {
				g.reads[i] = append(g.reads[i], j)
			}
		}
	}
}

// classify records which changing roots each local follows.
func (g *localGraph) classify(resourceTypes map[string]struct{}) {
	resourceReaders := g.reading(resourceTypes)
	moduleReaders := g.reading(moduleRoot)
	dataReaders := g.reading(dataRoot)
	g.deps = make(map[string]localDeps, len(g.names))
	g.dataLocals = make(map[string]bool, len(dataReaders))
	for _, name := range g.names {
		g.deps[name] = localDeps{
			resources: resourceReaders[name],
			modules:   moduleReaders[name],
			data:      dataReaders[name],
		}
		if dataReaders[name] {
			g.dataLocals[name] = true
		}
	}
	g.readsResources = g.readsAny(resourceTypes)
	g.readsModules = g.readsAny(moduleRoot)
}

// orderComponents groups the vertices of a graph into strongly connected
// components, each emitted after every component it has an edge to (Tarjan).
func orderComponents(edges [][]int) []localComponent {
	n := len(edges)
	visited := make([]int, n) // 0 when unvisited, else the visit order from 1
	low := make([]int, n)
	onStack := make([]bool, n)
	stack := make([]int, 0, n)
	next := 1
	var components []localComponent
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
		cyclic := len(members) > 1 || slices.Contains(edges[v], v)
		components = append(components, localComponent{members: members, cyclic: cyclic})
	}
	for v := range n {
		if visited[v] == 0 {
			visit(v)
		}
	}
	return components
}

// warn reports what Terraform would reject in a module's locals: a cycle,
// and a read of local as a whole. Either fails a Terraform plan; the scan
// goes on with what the passes resolved.
func (g *localGraph) warn(ctx context.Context, dir string) {
	contextLogger := logger.FromContext(ctx)
	for v, whole := range g.whole {
		if whole {
			contextLogger.Warn().Str("module_dir", dir).
				Msgf("tfeval: local.%s reads local as a whole, which Terraform rejects", g.names[v])
		}
	}
	for _, cycle := range g.cycles {
		contextLogger.Warn().Str("module_dir", dir).Msgf("tfeval: cycle among locals: %s", cycle)
	}
}

// readsAny reports whether a local reads one of roots directly.
func (g *localGraph) readsAny(roots map[string]struct{}) bool {
	for v := range g.names {
		if g.readsRoot(v, roots) {
			return true
		}
	}
	return false
}

// reading returns the locals reading roots, directly or through other locals.
func (g *localGraph) reading(roots map[string]struct{}) map[string]bool {
	if len(roots) == 0 {
		return map[string]bool{}
	}
	reads := make([]bool, len(g.names))
	for _, c := range g.components {
		hit := false
		for _, v := range c.members {
			if g.readsRoot(v, roots) || slices.ContainsFunc(g.reads[v], func(w int) bool { return reads[w] }) {
				hit = true
				break
			}
		}
		if hit {
			for _, v := range c.members {
				reads[v] = true
			}
		}
	}
	out := map[string]bool{}
	for v, hit := range reads {
		if hit {
			out[g.names[v]] = true
		}
	}
	return out
}

func (g *localGraph) readsRoot(v int, roots map[string]struct{}) bool {
	for _, root := range g.roots[v] {
		if _, ok := roots[root]; ok {
			return true
		}
	}
	return false
}

// readable is the local.* a local is evaluated against: the locals it reads
// that resolved to a known value. The others are absent, so try and can fall
// back past them.
func (g *localGraph) readable(v int, resolved map[string]cty.Value) cty.Value {
	if g.whole[v] {
		return objectOrEmpty(resolved)
	}
	attrs := make(map[string]cty.Value, len(g.reads[v]))
	for _, w := range g.reads[v] {
		if value, ok := resolved[g.names[w]]; ok {
			attrs[g.names[w]] = value
		}
	}
	return objectOrEmpty(attrs)
}

// resolveLocalsWith resolves the locals of g, keeping the locals in fixed at
// their value, for a refresh only some locals depend on. Each local is
// evaluated once, after the locals it reads.
func (e *Evaluator) resolveLocalsWith(
	g *localGraph,
	base *hcl.EvalContext,
	fixed map[string]cty.Value,
) map[string]cty.Value {
	resolved := make(map[string]cty.Value, len(g.names))
	for name, value := range fixed {
		if value.IsKnown() {
			resolved[name] = value
		}
	}
	for _, c := range g.components {
		if c.cyclic {
			e.resolveCycle(g, c.members, base, fixed, resolved)
			continue
		}
		v := c.members[0]
		name := g.names[v]
		if _, ok := fixed[name]; ok {
			continue
		}
		ctx := base.NewChild()
		ctx.Variables = map[string]cty.Value{rootLocal: g.readable(v, resolved)}
		if value := e.localValue(g.exprs[v], ctx); value.IsKnown() {
			resolved[name] = value
		}
	}
	for _, name := range g.names {
		if _, ok := resolved[name]; !ok {
			resolved[name] = cty.UnknownVal(cty.DynamicPseudoType)
		}
	}
	return resolved
}

// resolveCycle resolves locals reading each other in passes, each against the
// values the previous pass left, until a pass changes nothing.
func (e *Evaluator) resolveCycle(
	g *localGraph,
	members []int,
	base *hcl.EvalContext,
	fixed, resolved map[string]cty.Value,
) {
	if !slices.ContainsFunc(members, func(v int) bool { _, ok := fixed[g.names[v]]; return !ok }) {
		return
	}
	// The members are evaluated against themselves and the locals they read.
	visible := map[string]bool{}
	for _, v := range members {
		visible[g.names[v]] = true
		for _, w := range g.reads[v] {
			visible[g.names[w]] = true
		}
	}
	for range cycleMaxPasses {
		progressed := false
		attrs := make(map[string]cty.Value, len(visible))
		for name := range visible {
			if value, ok := resolved[name]; ok {
				attrs[name] = value
			}
		}
		ctx := base.NewChild()
		ctx.Variables = map[string]cty.Value{rootLocal: objectOrEmpty(attrs)}
		for _, v := range members {
			name := g.names[v]
			if _, ok := fixed[name]; ok {
				continue
			}
			prev, seen := resolved[name]
			if seen && prev.IsWhollyKnown() {
				continue
			}
			value := e.localValue(g.exprs[v], ctx)
			if !value.IsKnown() || (seen && e.keyMemo.equal(prev, value)) {
				continue
			}
			resolved[name] = value
			progressed = true
		}
		if !progressed {
			return
		}
	}
}
