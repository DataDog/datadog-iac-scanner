/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
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
}

// siblingReadsOf returns the sibling reads of a module's calls.
func (e *Evaluator) siblingReadsOf(moduleBlocks []*hclsyntax.Block, scope *ModuleScope) *siblingReads {
	if len(moduleBlocks) == 0 {
		return &siblingReads{}
	}
	key := moduleBlocks[0]
	if reads, ok := e.siblingReads[key]; ok {
		return reads
	}
	reads := computeSiblingReads(moduleBlocks, scope.Locals, collectDataBlocks(scope.Bodies))
	if e.siblingReads == nil {
		e.siblingReads = make(map[*hclsyntax.Block]*siblingReads)
	}
	e.siblingReads[key] = reads
	return reads
}

func computeSiblingReads(
	moduleBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	dataBlocks []*hclsyntax.Block,
) *siblingReads {
	locals := make(map[string]*blockReads, len(localExprs))
	for name, expr := range localExprs {
		r := &blockReads{}
		r.expr(expr)
		locals[name] = r
	}
	data := make(map[string]*blockReads, len(dataBlocks))
	for _, b := range dataBlocks {
		key := b.Labels[0] + "." + b.Labels[1]
		r := data[key]
		if r == nil {
			r = &blockReads{}
			data[key] = r
		}
		r.body(b.Body, nil)
	}
	out := &siblingReads{
		direct:   make([]labelSet, len(moduleBlocks)),
		resolved: make([]labelSet, len(moduleBlocks)),
	}
	for i, mb := range moduleBlocks {
		r := &blockReads{}
		r.body(mb.Body, unreadModuleAttrs)
		out.direct[i] = r.modules
		out.resolved[i] = resolveModuleReads(r, locals, data)
	}
	return out
}

// resolveModuleReads follows refs through the locals and data blocks it reads
// to the module calls it reads in the end.
func resolveModuleReads(refs *blockReads, locals, data map[string]*blockReads) labelSet {
	var out labelSet
	visited := map[*blockReads]bool{}
	var walk func(r *blockReads)
	walk = func(r *blockReads) {
		if r == nil || visited[r] || out.all {
			return
		}
		visited[r] = true
		if r.modules.all {
			out.all = true
			return
		}
		for name := range r.modules.names {
			out.add(name)
		}
		if r.allLocals {
			for _, next := range locals {
				walk(next)
			}
		}
		for name := range r.locals {
			walk(locals[name])
		}
		if r.allData {
			for _, next := range data {
				walk(next)
			}
		}
		for key := range r.data {
			walk(data[key])
		}
	}
	walk(refs)
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
