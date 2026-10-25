/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// unreadModuleAttrs are the module call arguments evaluation never reads.
var unreadModuleAttrs = map[string]bool{
	argDependsOn: true,
	argProviders: true,
}

// labelSet is the module calls an expression reads by label. all marks a read
// that does not name one call, such as a bare module or a computed index.
type labelSet struct {
	names map[string]bool
	all   bool
}

func (s *labelSet) add(name string) {
	if s.names == nil {
		s.names = map[string]bool{}
	}
	s.names[name] = true
}

// union adds the labels of other to s. A set reading every call drops its
// names.
func (s *labelSet) union(other labelSet) {
	if s.all {
		return
	}
	if other.all {
		*s = labelSet{all: true}
		return
	}
	for name := range other.names {
		s.add(name)
	}
}

// readsAny reports whether s reads one of the labels in changed.
func (s labelSet) readsAny(changed map[string]bool) bool {
	if len(changed) == 0 {
		return false
	}
	if s.all {
		return true
	}
	for name := range s.names {
		if changed[name] {
			return true
		}
	}
	return false
}

// blockReads is what an expression or body reads of a module's module calls,
// locals and data blocks.
type blockReads struct {
	modules            labelSet
	locals, data       map[string]bool
	allLocals, allData bool
}

func (r *blockReads) note(traversal hcl.Traversal) {
	switch traversal.RootName() {
	case blockTypeModule:
		if len(traversal) < 2 {
			r.modules.all = true
		} else if name, ok := refStepName(traversal[1]); ok {
			r.modules.add(name)
		} else {
			r.modules.all = true
		}
	case rootLocal:
		if name, ok := terraform.LocalTraversalName(traversal); ok {
			r.locals = addName(r.locals, name)
		} else {
			r.allLocals = true
		}
	case blockTypeData:
		if len(traversal) < 3 {
			r.allData = true
			return
		}
		typ, okType := refStepName(traversal[1])
		name, okName := refStepName(traversal[2])
		if !okType || !okName {
			r.allData = true
			return
		}
		r.data = addName(r.data, typ+"."+name)
	}
}

func (r *blockReads) expr(expr hclsyntax.Expression) {
	for _, traversal := range expr.Variables() {
		r.note(traversal)
	}
}

func (r *blockReads) body(body *hclsyntax.Body, skip map[string]bool) {
	for name, attr := range body.Attributes {
		if !skip[name] {
			r.expr(attr.Expr)
		}
	}
	for _, block := range body.Blocks {
		r.body(block.Body, nil)
	}
}

func addName(set map[string]bool, name string) map[string]bool {
	if set == nil {
		set = map[string]bool{}
	}
	set[name] = true
	return set
}

// siblingReads is what each module call of a module reads of its sibling
// calls' outputs, by position in the module's call order.
type siblingReads struct {
	// direct is what a call's arguments read of module.* themselves.
	direct []labelSet
	// resolved adds what they read through locals and data blocks.
	resolved []labelSet
	// throughLocals is set when the locals and data blocks a call's arguments
	// read reach a module call, so the call is evaluated against the shared
	// context those are refreshed in.
	throughLocals []bool
	// prepass marks the calls the sibling prepass evaluates; anyPrepass is
	// set when there is one.
	prepass    []bool
	anyPrepass bool
}

// computeSiblingReads returns what a module's calls read of one another. It
// depends on the module's HCL alone, so it is computed once per parse.
func computeSiblingReads(
	moduleBlocks []*hclsyntax.Block,
	locals *localGraph,
	dataBlocks []*hclsyntax.Block,
) *siblingReads {
	out := &siblingReads{
		direct:        make([]labelSet, len(moduleBlocks)),
		resolved:      make([]labelSet, len(moduleBlocks)),
		throughLocals: make([]bool, len(moduleBlocks)),
	}
	if len(moduleBlocks) == 0 {
		return out
	}
	closure := newModuleReadClosure(locals, dataBlocks)
	for i, mb := range moduleBlocks {
		r := &blockReads{}
		r.body(mb.Body, unreadModuleAttrs)
		out.direct[i] = r.modules
		reached := closure.reached(r)
		out.throughLocals[i] = reached.all || len(reached.names) > 0
		reached.union(r.modules)
		out.resolved[i] = reached
	}
	out.prepass = prepassCalls(moduleBlocks, out)
	out.anyPrepass = slices.Contains(out.prepass, true)
	return out
}

// prepassCalls returns the calls the sibling prepass must evaluate.
//
// The main loop evaluates the calls in order and publishes each call's outputs
// before a later call reads them, so a call reading only earlier calls sees
// their final outputs without a prepass. Only a call reading itself or a later
// call needs that call's outputs ahead of time. The prepass evaluates those,
// plus every call their arguments read directly. Reads through locals and
// data need not be followed there: they are not refreshed between prepass
// calls.
func prepassCalls(moduleBlocks []*hclsyntax.Block, reads *siblingReads) []bool {
	members := make([]bool, len(moduleBlocks))
	if len(moduleBlocks) <= 1 {
		return members
	}
	positions := make(map[string][]int, len(moduleBlocks))
	for i, mb := range moduleBlocks {
		positions[blockLabel(mb)] = append(positions[blockLabel(mb)], i)
	}
	var pending []int
	include := func(i int) {
		if !members[i] {
			members[i] = true
			pending = append(pending, i)
		}
	}
	includeAll := func() {
		for i := range members {
			include(i)
		}
	}
	for i, r := range reads.resolved {
		if r.all {
			includeAll()
			break
		}
		for name := range r.names {
			for _, pos := range positions[name] {
				if pos >= i {
					include(pos)
				}
			}
		}
	}
	for len(pending) > 0 {
		m := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if reads.direct[m].all {
			includeAll()
			continue
		}
		for name := range reads.direct[m].names {
			for _, pos := range positions[name] {
				include(pos)
			}
		}
	}
	return members
}

// moduleReadClosure is the module calls each local and data block reads in
// the end, directly or through other locals and data blocks. Locals are the
// local graph's vertices by index; data blocks follow them.
type moduleReadClosure struct {
	locals    *localGraph
	dataIndex map[string]int
	reach     []labelSet
}

func newModuleReadClosure(locals *localGraph, dataBlocks []*hclsyntax.Block) *moduleReadClosure {
	c := &moduleReadClosure{locals: locals, dataIndex: map[string]int{}}
	nLocals := 0
	if locals != nil {
		nLocals = len(locals.names)
	}
	refs := make([]*blockReads, nLocals)
	for v := range refs {
		refs[v] = &blockReads{}
		refs[v].expr(locals.exprs[v])
	}
	for _, b := range dataBlocks {
		key := b.Labels[0] + "." + b.Labels[1]
		v, ok := c.dataIndex[key]
		if !ok {
			v = len(refs)
			c.dataIndex[key] = v
			refs = append(refs, &blockReads{})
		}
		refs[v].body(b.Body, nil)
	}
	edges := make([][]int, len(refs))
	for v, r := range refs {
		if v < nLocals {
			edges[v] = append(edges[v], locals.reads[v]...)
		} else {
			edges[v] = append(edges[v], c.localTargets(r)...)
		}
		edges[v] = append(edges[v], c.dataTargets(r, nLocals, len(refs))...)
	}
	c.reach = make([]labelSet, len(refs))
	for _, comp := range orderComponents(edges) {
		var reach labelSet
		for _, v := range comp.members {
			reach.union(refs[v].modules)
			for _, w := range edges[v] {
				reach.union(c.reach[w])
			}
		}
		for _, v := range comp.members {
			c.reach[v] = reach
		}
	}
	return c
}

// localTargets is the declared locals r reads, by graph index.
func (c *moduleReadClosure) localTargets(r *blockReads) []int {
	if c.locals == nil {
		return nil
	}
	if r.allLocals {
		all := make([]int, len(c.locals.names))
		for v := range all {
			all[v] = v
		}
		return all
	}
	var out []int
	for name := range r.locals {
		if v, ok := slices.BinarySearch(c.locals.names, name); ok {
			out = append(out, v)
		}
	}
	return out
}

// dataTargets is the data blocks r reads, by vertex.
func (c *moduleReadClosure) dataTargets(r *blockReads, first, end int) []int {
	if r.allData {
		all := make([]int, 0, end-first)
		for v := first; v < end; v++ {
			all = append(all, v)
		}
		return all
	}
	var out []int
	for key := range r.data {
		if v, ok := c.dataIndex[key]; ok {
			out = append(out, v)
		}
	}
	return out
}

// reached is the module calls r reads through the locals and data blocks it
// reads, leaving out the calls it reads directly.
func (c *moduleReadClosure) reached(r *blockReads) labelSet {
	var out labelSet
	for _, v := range c.localTargets(r) {
		out.union(c.reach[v])
	}
	for _, v := range c.dataTargets(r, len(c.reach)-len(c.dataIndex), len(c.reach)) {
		out.union(c.reach[v])
	}
	return out
}

// moduleOutputsPublisher publishes module.* to the calls that read it. The
// object is rebuilt only when the next call reads a call whose outputs changed
// since it was last built: rebuilding it after every call is quadratic in the
// number of calls.
type moduleOutputsPublisher struct {
	outputs map[string]cty.Value
	changed map[string]bool
}

// set records a call's outputs.
func (p *moduleOutputsPublisher) set(label string, value cty.Value) {
	if prev, ok := p.outputs[label]; ok && equalValues(prev, value) {
		return
	}
	p.outputs[label] = value
	p.changed = addName(p.changed, label)
}

// stale reports whether a call reading reads needs module.* rebuilt first,
// and forgets the changes when it does.
func (p *moduleOutputsPublisher) stale(reads labelSet) bool {
	if !reads.readsAny(p.changed) {
		return false
	}
	p.changed = nil
	return true
}

// moduleCallContext evaluates one call against a module.* object holding only
// the labels reads names. Rebuilding the object of every call is quadratic in
// the number of calls; a read that does not name its labels still needs that
// object, and reads.all leaves it to the caller.
func moduleCallContext(parent *hcl.EvalContext, outputs map[string]cty.Value, reads labelSet) *hcl.EvalContext {
	if reads.all || len(reads.names) == 0 {
		return parent
	}
	attrs := make(map[string]cty.Value, len(reads.names))
	for name := range reads.names {
		if value, ok := outputs[name]; ok {
			attrs[name] = value
		}
	}
	child := parent.NewChild()
	child.Variables = map[string]cty.Value{"module": cty.ObjectVal(attrs)}
	return child
}
