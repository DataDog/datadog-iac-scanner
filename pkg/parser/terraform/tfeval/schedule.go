/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// blockSchedule evaluates the resource blocks and module calls of one module
// evaluation in the order their references need: a block runs after every
// block it reads, so what it reads is final when it runs, however long the
// chain and whatever the file order. A group of blocks reading each other,
// which Terraform rejects, is evaluated repeatedly until its values settle.
//
// What a block reads is kept current lazily: the references to the resources,
// the locals and the data blocks are refreshed just before a block reading them
// runs, after a block they read was evaluated.
type blockSchedule struct {
	e   *Evaluator
	ctx context.Context

	dir, rootDir, packageRoot, addr string
	chain                           []CallSite
	depth                           int
	visiting, allVisited            map[string]bool

	graph          *unitGraph
	resourceBlocks []*hclsyntax.Block
	moduleBlocks   []*hclsyntax.Block
	scope          *ModuleScope
	evalCtx        *hcl.EvalContext
	data           *moduleData

	// reads is what each unit reads that the module calls change.
	reads         []siblingReads
	siblings      *siblingOutputs
	moduleOutputs map[string]cty.Value
	refs          *refInjector

	// results of the last evaluation of each unit.
	resources [][]ResolvedResource
	empty     []bool
	children  [][]ResolvedResource

	// evaluated is the tick each unit was last evaluated at, and localsAt and
	// dataAt the tick of the references the locals and the data blocks were
	// last refreshed against.
	tick, localsAt, dataAt int
	evaluated              []int
	// refsAt is the tick the references to the resources were last installed
	// at, and refsStale is set when a resource was evaluated since.
	refsAt    int
	refsStale bool
}

// scheduledBlocks is what a schedule produced, each in file order.
type scheduledBlocks struct {
	resources      []ResolvedResource
	empty          []EmptyBlock
	childResources []ResolvedResource
}

func (s *blockSchedule) run() scheduledBlocks {
	for i, component := range s.graph.components {
		if s.ctx.Err() != nil {
			break
		}
		if s.graph.cyclic[i] {
			s.settle(component)
			continue
		}
		s.evalUnit(component[0])
	}
	if s.ctx.Err() == nil {
		s.finish()
	}
	return s.collect()
}

func (s *blockSchedule) evalUnit(unit int) {
	s.sync(unit)
	if unit < s.graph.resources {
		s.evalResource(unit)
	} else {
		s.evalModule(unit - s.graph.resources)
	}
	s.tick++
	s.evaluated[unit] = s.tick
}

// settle evaluates a group of blocks reading each other until a pass changes
// nothing they publish. Each pass replaces the results of the last, and the
// module calls it recorded.
func (s *blockSchedule) settle(component []int) {
	instances, empty, live := len(s.e.instances), len(s.e.emptyBlocks), len(s.e.liveModules)
	for pass := 0; pass < len(component)+resourceRefPasses; pass++ {
		s.e.instances = s.e.instances[:instances]
		s.e.emptyBlocks = s.e.emptyBlocks[:empty]
		s.e.liveModules = s.e.liveModules[:live]
		before := s.published(component)
		for _, unit := range component {
			if s.ctx.Err() != nil {
				return
			}
			s.evalUnit(unit)
		}
		if pass > 0 && sameValues(before, s.published(component)) {
			return
		}
	}
}

// published is the values the units publish for references to read.
func (s *blockSchedule) published(component []int) []cty.Value {
	out := make([]cty.Value, 0, len(component))
	for _, unit := range component {
		if unit < s.graph.resources {
			out = append(out, s.refs.value(s.resourceBlocks[unit]))
			continue
		}
		out = append(out, s.moduleOutputs[blockLabel(s.moduleBlocks[unit-s.graph.resources])])
	}
	return out
}

func sameValues(a, b []cty.Value) bool {
	for i := range a {
		if !equalValues(a[i], b[i]) {
			return false
		}
	}
	return true
}

// sync refreshes what unit reads, when a block it reads was evaluated since it
// was last refreshed.
func (s *blockSchedule) sync(unit int) {
	if s.refsStale && s.readsEvaluatedResource(s.graph.edges[unit], s.refsAt) {
		s.publishRefs()
	}
	if s.readsEvaluatedResource(s.graph.viaLocals[unit], s.localsAt) {
		s.refreshLocals()
	}
	if s.graph.readsData[unit] && s.data.readsOwnResources() &&
		s.readsEvaluatedResource(s.graph.dataUnits, s.dataAt) {
		// Data may read resources through locals the unit itself does not, so
		// viaLocals above would not refresh them.
		if s.data.readsLocals && s.readsEvaluatedResource(s.graph.dataUnits, s.localsAt) {
			s.refreshLocals()
		}
		s.data.refresh(s.evalCtx)
		s.dataAt = s.refsAt
	}
}

// readsEvaluatedResource reports whether one of units is a resource evaluated
// after tick. Module outputs refresh what reads them when they are published.
func (s *blockSchedule) readsEvaluatedResource(units []int, tick int) bool {
	for _, w := range units {
		if w < s.graph.resources && s.evaluated[w] > tick {
			return true
		}
	}
	return false
}

func (s *blockSchedule) publishRefs() {
	s.refs.publish(s.evalCtx)
	s.refsStale = false
	s.refsAt = s.tick
}

func (s *blockSchedule) refreshLocals() {
	if s.siblings != nil && s.scope.localGraph.readsModules {
		s.siblings.publish()
	}
	s.evalCtx.Variables["local"] = s.e.resolveLocalsIncremental(s.scope, s.evalCtx, true, false)
	s.localsAt = s.refsAt
}

// callContext is the context a unit is evaluated in.
func (s *blockSchedule) callContext(unit int) *hcl.EvalContext {
	if s.siblings == nil {
		return s.evalCtx
	}
	return s.siblings.contextFor(&s.reads[unit])
}

func (s *blockSchedule) evalResource(unit int) {
	rb := s.resourceBlocks[unit]
	resources, isEmpty := s.e.expandBlock(s.ctx, rb, s.callContext(unit), s.addr, s.chain, false)
	if s.ctx.Err() != nil {
		return
	}
	s.resources[unit], s.empty[unit] = resources, isEmpty
	s.refs.set(unit, rb, resources, isEmpty)
	s.refsStale = true
}

func (s *blockSchedule) evalModule(index int) {
	mb := s.moduleBlocks[index]
	callCtx := s.callContext(s.graph.resources + index)
	plan := moduleInstances(s.ctx, mb, callCtx)
	if s.ctx.Err() != nil {
		return
	}
	s.children[index] = nil
	if s.e.publishEmptyModuleCall(mb, plan, s.siblings, s.evalCtx, s.scope, s.data, s.moduleOutputs) {
		return
	}
	call, ok := s.e.resolveModuleCall(s.ctx, mb, callCtx, s.dir, s.packageRoot)
	if !ok {
		return
	}
	s.children[index] = s.e.expandModuleCallInstances(
		s.ctx, mb, &call, plan, s.evalCtx, s.scope, s.data,
		s.rootDir, s.addr, s.chain, s.depth, s.visiting, s.allVisited,
		s.siblings, s.moduleOutputs,
	)
}

// finish publishes what the last blocks evaluated: the module outputs, then
// the locals and data blocks reading the resources.
func (s *blockSchedule) finish() {
	if s.refsStale {
		s.publishRefs()
	}
	s.e.installModuleOutputs(s.evalCtx, s.scope, s.data, s.moduleOutputs)
	if s.readsEvaluatedResource(allUnits(s.graph.resources), s.localsAt) && s.scope.localGraph.readsResources {
		s.refreshLocals()
	}
	if s.data.readsOwnResources() {
		s.data.refresh(s.evalCtx)
	}
}

func allUnits(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func (s *blockSchedule) collect() scheduledBlocks {
	var out scheduledBlocks
	for unit, resources := range s.resources {
		out.resources = append(out.resources, resources...)
		if s.empty[unit] {
			out.empty = append(out.empty, emptyBlockOf(s.resourceBlocks[unit], false))
		}
	}
	for _, children := range s.children {
		out.childResources = append(out.childResources, children...)
	}
	return out
}
