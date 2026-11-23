/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"maps"
	"path/filepath"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const scheduledResource = "resource"

// blockGraph is shared by every evaluation of a parsed directory. Resources
// and data sources are units; local references contribute the dependencies
// of the local expressions. Each unit runs after the values it reads are final.
// Results remain in declaration order, independently of evaluation order.
type blockGraph struct {
	blocks          []*hclsyntax.Block
	resources, data int
	edges, locals   [][]int
	components      [][]int
	cyclic          []bool
}

func newBlockGraph(dp *dirParse) *blockGraph {
	g := &blockGraph{resources: len(dp.resources), data: len(dp.locals.dataBlocks)}
	g.blocks = append(g.blocks, dp.resources...)
	g.blocks = append(g.blocks, dp.locals.dataBlocks...)
	byName := map[string][]int{}
	byRoot := map[string][]int{}
	for i, b := range g.blocks {
		root, name := b.Type, blockLabel(b)
		if b.Type == scheduledResource {
			root = b.Labels[0]
			name = b.Labels[1]
		}
		if b.Type == blockTypeData {
			name = b.Labels[0] + "." + b.Labels[1]
		}
		byName[root+"."+name] = append(byName[root+"."+name], i)
		byRoot[root] = append(byRoot[root], i)
	}
	localReads := &localUnitReads{graph: dp.locals, byName: byName, byRoot: byRoot, memo: map[int][]int{}}
	g.edges = make([][]int, len(g.blocks))
	g.locals = make([][]int, len(g.blocks))
	for i, b := range g.blocks {
		reads := dependencyReads{
			byName: byName, byRoot: byRoot, graph: dp.locals, units: localReads,
			deps: map[int]bool{}, locals: map[int]bool{},
		}
		for _, t := range terraform.BodyTraversals(b.Body) {
			reads.add(t)
		}
		deps, locals := reads.deps, reads.locals
		for v := range deps {
			g.edges[i] = append(g.edges[i], v)
		}
		slices.Sort(g.edges[i])
		for v := range locals {
			g.locals[i] = append(g.locals[i], v)
		}
		slices.SortFunc(g.locals[i], func(a, b int) int { return dp.locals.rank[a] - dp.locals.rank[b] })
	}
	g.components = stronglyConnected(g.edges)
	for _, c := range g.components {
		g.cyclic = append(g.cyclic, len(c) > 1 || slices.Contains(g.edges[c[0]], c[0]))
	}
	return g
}

// dependencyReads expands local aliases while classifying declared addresses.
type dependencyReads struct {
	byName, byRoot map[string][]int
	graph          *localGraph
	deps, locals   map[int]bool
	units          *localUnitReads
}

// Local closures are memoized as unit dependencies, not copied as lists of
// every intermediate alias into each consumer's scope.
type localUnitReads struct {
	graph          *localGraph
	byName, byRoot map[string][]int
	memo           map[int][]int
}

func (l *localUnitReads) of(v int) []int {
	if units, done := l.memo[v]; done {
		return units
	}
	if l.graph.cyclic[v] {
		return nil
	}
	l.memo[v] = nil // Break broad namespace reads that include this local itself.
	r := dependencyReads{byName: l.byName, byRoot: l.byRoot, graph: l.graph, units: l, deps: map[int]bool{}}
	for _, t := range l.graph.exprs[v].Variables() {
		r.add(t)
	}
	units := make([]int, 0, len(r.deps))
	for unit := range r.deps {
		units = append(units, unit)
	}
	slices.Sort(units)
	l.memo[v] = units
	return units
}
func (r *dependencyReads) local(v int) {
	if r.locals != nil {
		r.locals[v] = true
	}
	for _, unit := range r.units.of(v) {
		r.deps[unit] = true
	}
}
func (r *dependencyReads) add(t hcl.Traversal) {
	if len(t) == 0 {
		return
	}
	root := t.RootName()
	name, named := staticAttributeName(t)
	if root == rootLocal {
		if named {
			if v, ok := r.graph.index[name]; ok {
				r.local(v)
			}
		} else {
			for v := range r.graph.names {
				r.local(v)
			}
		}
		return
	}
	if root == blockTypeData && named {
		if len(t) > 2 {
			if n, ok := staticAttributeName(hcl.Traversal{hcl.TraverseRoot{}, t[2]}); ok {
				name += "." + n
			} else {
				named = false
			}
		} else {
			named = false
		}
	}
	units := r.byRoot[root]
	if named {
		units = r.byName[root+"."+name]
	}
	for _, v := range units {
		r.deps[v] = true
	}
}

// resourceSchedule evaluates the resources and data blocks of one module after
// the existing module-call orchestration has published its outputs. Module
// inputs/outputs require a finer dependency graph and are not scheduled here.
// Each completed block's cty reference value and each final local are built
// once; consumers receive only their directly required names.
type resourceSchedule struct {
	e                  *Evaluator
	ctx                context.Context
	graph              *blockGraph
	scope              *ModuleScope
	base               *hcl.EvalContext
	globals            map[string]cty.Value
	data               *moduleData
	addr               string
	chain              *callChain
	resources, exposed [][]ResolvedResource
	references         map[int]cty.Value
	cyclic             []bool
	localValues        map[string]cty.Value
}

func (e *Evaluator) scheduleResources(
	ctx context.Context, blocks []*hclsyntax.Block, scope *ModuleScope, evalCtx *hcl.EvalContext,
	data *moduleData, addr string, chain *callChain,
) []ResolvedResource {
	g := scope.static.resources
	s := &resourceSchedule{
		e: e, ctx: ctx, graph: g, scope: scope, base: evalCtx, data: data, addr: addr, chain: chain,
		resources: make([][]ResolvedResource, len(g.blocks)), exposed: make([][]ResolvedResource, len(g.blocks)),
		references: map[int]cty.Value{}, cyclic: make([]bool, len(g.blocks)), localValues: map[string]cty.Value{},
		globals: maps.Clone(evalCtx.Variables),
	}
	// The pre-module phase may have provisional managed values. Never let those
	// leak into a unit whose dependencies have not run in this schedule.
	for _, b := range blocks {
		delete(s.globals, b.Labels[0])
	}
	delete(s.globals, blockTypeData)
	delete(s.globals, rootLocal)
	for name, v := range scope.localCache {
		local := scope.localGraph.index[name]
		deps := scope.localGraph.deps[local]
		if !deps.resources && !deps.data {
			s.localValues[name] = v
		}
	}
	for i, c := range g.components {
		if ctx.Err() != nil {
			break
		}
		if g.cyclic[i] {
			s.cycle(c)
			continue
		}
		s.evaluate(c[0])
	}
	if ctx.Err() == nil {
		s.finish()
	}
	var resources []ResolvedResource
	for i := range g.resources {
		resources = append(resources, s.resources[i]...)
	}
	return resources
}

func (s *resourceSchedule) reference(unit int) cty.Value {
	if v, ok := s.references[unit]; ok {
		return v
	}
	if s.cyclic[unit] {
		return cty.DynamicVal
	}
	b := s.graph.blocks[unit]
	instances := s.exposed[unit]
	if len(instances) == 0 {
		if _, count := b.Body.Attributes[metaArgCount]; count {
			return cty.EmptyTupleVal
		}
		if _, each := b.Body.Attributes[metaArgForEach]; each {
			return cty.EmptyObjectVal
		}
		return cty.NilVal
	}
	for i := range instances {
		r := &instances[i]
		if r.InstanceKey != cty.NilVal && !r.InstanceKey.IsKnown() {
			return cty.DynamicVal
		}
	}
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{}}
	var referenced map[string][]string
	if b.Type == scheduledResource {
		referenced = s.scope.static.resourceAttrs
	}
	injectResourceRefs(ctx, instances, referenced)
	// Reference injection groups expanded instance names under their base name.
	// A malformed declaration may itself use instance-like labels, so its
	// declared name is not guaranteed to exist in that namespace.
	v := cty.DynamicVal
	if refs, ok := ctx.Variables[b.Labels[0]]; ok && refs.IsKnown() && !refs.IsNull() &&
		refs.Type().IsObjectType() && refs.Type().HasAttribute(b.Labels[1]) {
		v = refs.GetAttr(b.Labels[1])
	}
	s.references[unit] = v
	return v
}

func (s *resourceSchedule) context(units, locals []int) *hcl.EvalContext {
	ctx := &hcl.EvalContext{Variables: maps.Clone(s.globals), Functions: s.base.Functions}
	resources, data := map[string]map[string]cty.Value{}, map[string]map[string]cty.Value{}
	for _, unit := range units {
		b := s.graph.blocks[unit]
		values := resources
		if b.Type == blockTypeData {
			values = data
		}
		value := s.reference(unit)
		if value == cty.NilVal {
			continue
		}
		typ, name := b.Labels[0], b.Labels[1]
		if values[typ] == nil {
			values[typ] = map[string]cty.Value{}
		}
		if _, exists := values[typ][name]; !exists {
			values[typ][name] = value
		}
	}
	for typ, values := range resources {
		ctx.Variables[typ] = objectOrEmpty(values)
	}
	dtypes := make(map[string]cty.Value, len(data))
	for typ, values := range data {
		dtypes[typ] = objectOrEmpty(values)
	}
	ctx.Variables[blockTypeData] = objectOrEmpty(dtypes)
	values := make(map[string]cty.Value, len(locals))
	for _, v := range locals {
		s.local(v, ctx)
		values[s.scope.localGraph.names[v]] = s.localValues[s.scope.localGraph.names[v]]
	}
	ctx.Variables[rootLocal] = objectOrEmpty(values)
	return ctx
}

func (s *resourceSchedule) local(v int, ctx *hcl.EvalContext) {
	g := s.scope.localGraph
	name := g.names[v]
	if _, done := s.localValues[name]; done {
		return
	}
	if g.cyclic[v] {
		s.localValues[name] = cty.DynamicVal
		return
	}
	for _, read := range g.reads[v] {
		s.local(read, ctx)
	}
	s.e.resolveLocals(g, ctx, s.localValues, []int{v})
}

func (s *resourceSchedule) evaluate(unit int) {
	b := s.graph.blocks[unit]
	ctx := s.context(s.graph.edges[unit], s.graph.locals[unit])
	if b.Type == scheduledResource {
		s.resources[unit] = s.e.expandBlock(s.ctx, b, ctx, s.addr, s.chain, false)
		s.exposed[unit] = s.resources[unit]
		return
	}
	inputs := blockEvalInputs(b, ctx)
	cached, exists := s.data.evalCache[b]
	if !exists || !sameCtyValues(cached.inputs, inputs) {
		cached = s.data.evalBlock(s.ctx, b, ctx, inputs)
	}
	s.resources[unit], s.exposed[unit] = cached.instances, cached.exposed
}

func (s *resourceSchedule) cycle(component []int) {
	dir := filepath.Dir(s.graph.blocks[component[0]].TypeRange.Filename)
	if _, seen := s.e.cycleWarned.LoadOrStore(dir, true); !seen {
		names := make([]string, 0, len(component))
		for _, v := range component {
			b := s.graph.blocks[v]
			names = append(names, b.Type+"."+b.Labels[0]+"."+b.Labels[1])
		}
		log := logger.FromContext(s.ctx)
		log.Warn().Strs("blocks", names).Msgf("tfeval: resource/data reference cycle at %s; the blocks are read as unknown", dir)
	}
	for _, unit := range component {
		s.cyclic[unit] = true
		b := s.graph.blocks[unit]
		copyBlock, copyBody := *b, *b.Body
		copyBody.Attributes = maps.Clone(b.Body.Attributes)
		for name, a := range copyBody.Attributes {
			copyAttr := *a
			copyAttr.Expr = &hclsyntax.LiteralValueExpr{Val: cty.DynamicVal, SrcRange: a.Expr.Range()}
			copyBody.Attributes[name] = &copyAttr
		}
		copyBlock.Body = &copyBody
		rs := s.e.expandBlock(s.ctx, &copyBlock, s.base, s.addr, s.chain, b.Type == blockTypeData)
		for i := range rs {
			rs[i].Body = b.Body
			for name := range rs[i].Attributes {
				rs[i].Attributes[name] = cty.DynamicVal
			}
		}
		s.resources[unit], s.exposed[unit] = rs, rs
	}
}

func (s *resourceSchedule) finish() {
	units := make([]int, len(s.graph.blocks))
	for i := range units {
		units[i] = i
	}
	ctx := s.context(units, s.scope.localGraph.order)
	s.base.Variables = ctx.Variables
	s.scope.localCache = s.localValues
	if s.data != nil {
		s.data.instances = nil
		for i := s.graph.resources; i < s.graph.resources+s.graph.data; i++ {
			s.data.instances = append(s.data.instances, s.resources[i]...)
		}
	}
}
