/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// unevaluatedModuleAttrs are the module arguments evaluation never reads, so
// a sibling they name does not feed the call.
var unevaluatedModuleAttrs = map[string]bool{
	"depends_on": true,
	"providers":  true,
}

// siblingPrepass lists the module calls the sibling prepass evaluates, by
// position in the module's call order.
//
// The main loop evaluates calls in order and publishes each call's outputs,
// refreshing the locals and data reading them, before the next call. A call
// reading only earlier siblings therefore sees their real outputs without any
// prepass. Only a call reading a sibling at or after its own position (a
// forward reference) needs speculative outputs, and only that sibling and
// what its own arguments read must be evaluated to produce them. Every other
// speculative evaluation is a whole subtree evaluated and retained for
// nothing, and with count and for_each each such subtree is up to
// maxCountExpansion instances per level.
type siblingPrepass struct {
	members []bool
	any     bool
}

// prepassPlanKey identifies a parsed module directory, like the parse cache.
func prepassPlanKey(dir, packageRoot string) string {
	return filepath.Clean(dir) + "\x00" + filepath.Clean(packageRoot)
}

// siblingPrepassPlan returns the prepass plan of the module at dir, computed
// once per parse: it only depends on the module's HCL.
func (e *Evaluator) siblingPrepassPlan(
	dir, packageRoot string,
	bodies []*hclsyntax.Body,
	moduleBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
) siblingPrepass {
	if len(moduleBlocks) <= 1 {
		return siblingPrepass{}
	}
	key := prepassPlanKey(dir, packageRoot)
	e.parseMu.Lock()
	plan, ok := e.prepassPlans[key]
	e.parseMu.Unlock()
	if ok && len(plan.members) == len(moduleBlocks) {
		return plan
	}
	plan = planSiblingPrepass(moduleBlocks, localExprs, collectDataBlocks(bodies))
	e.parseMu.Lock()
	e.prepassPlans[key] = plan
	e.parseMu.Unlock()
	return plan
}

// blockRefs is what an expression or body names of a module's locals, data
// blocks and module calls. The all* flags mark a reference that does not name
// one in particular, such as a bare root or a computed index.
type blockRefs struct {
	modules, locals, data             map[string]bool
	allModules, allLocals, allDataRef bool
}

func (r *blockRefs) note(traversal hcl.Traversal) {
	switch traversal.RootName() {
	case blockTypeModule:
		if name, ok := traversalStep(traversal, 1); ok {
			r.modules = setAdd(r.modules, name)
		} else {
			r.allModules = true
		}
	case "local":
		if name, ok := terraform.LocalTraversalName(traversal); ok {
			r.locals = setAdd(r.locals, name)
		} else {
			r.allLocals = true
		}
	case blockTypeData:
		typ, okType := traversalStep(traversal, 1)
		name, okName := traversalStep(traversal, 2)
		if okType && okName {
			r.data = setAdd(r.data, typ+"."+name)
		} else {
			r.allDataRef = true
		}
	}
}

func (r *blockRefs) expr(expr hclsyntax.Expression) {
	for _, traversal := range expr.Variables() {
		r.note(traversal)
	}
}

func (r *blockRefs) body(body *hclsyntax.Body, skip map[string]bool) {
	for name, attr := range body.Attributes {
		if !skip[name] {
			r.expr(attr.Expr)
		}
	}
	for _, block := range body.Blocks {
		r.body(block.Body, nil)
	}
}

func traversalStep(traversal hcl.Traversal, i int) (string, bool) {
	if len(traversal) <= i {
		return "", false
	}
	return refStepName(traversal[i])
}

func setAdd(set map[string]bool, key string) map[string]bool {
	if set == nil {
		set = map[string]bool{}
	}
	set[key] = true
	return set
}

// moduleReads resolves, per local and data block, the module calls read
// directly or through other locals and data blocks.
type moduleReads struct {
	locals, data map[string]*blockRefs
	// closed holds the resolved module reads of each node, keyed "local.<name>"
	// or "data.<type>.<name>".
	closed map[string]*blockRefs
}

func newModuleReads(localExprs map[string]hclsyntax.Expression, dataBlocks []*hclsyntax.Block) *moduleReads {
	m := &moduleReads{
		locals: make(map[string]*blockRefs, len(localExprs)),
		data:   make(map[string]*blockRefs, len(dataBlocks)),
		closed: map[string]*blockRefs{},
	}
	for name, expr := range localExprs {
		r := &blockRefs{}
		r.expr(expr)
		m.locals[name] = r
	}
	for _, b := range dataBlocks {
		key := b.Labels[0] + "." + b.Labels[1]
		r, ok := m.data[key]
		if !ok {
			r = &blockRefs{}
			m.data[key] = r
		}
		r.body(b.Body, nil)
	}
	return m
}

// resolve returns the module calls refs reads, following locals and data
// blocks transitively. Cycles between locals resolve to what the cycle reads.
func (m *moduleReads) resolve(refs *blockRefs) (modules map[string]bool, all bool) {
	modules = map[string]bool{}
	visited := map[string]bool{}
	var walk func(r *blockRefs)
	walk = func(r *blockRefs) {
		if r.allModules {
			all = true
		}
		for name := range r.modules {
			modules[name] = true
		}
		visit := func(key string, next *blockRefs) {
			if next == nil || visited[key] {
				return
			}
			visited[key] = true
			walk(next)
		}
		if r.allLocals {
			for name, next := range m.locals {
				visit("local."+name, next)
			}
		}
		for name := range r.locals {
			visit("local."+name, m.locals[name])
		}
		if r.allDataRef {
			for key, next := range m.data {
				visit("data."+key, next)
			}
		}
		for key := range r.data {
			visit("data."+key, m.data[key])
		}
	}
	walk(refs)
	return modules, all
}

// planSiblingPrepass decides which module calls the prepass must evaluate:
// every call some call reads at or after its own position, plus the calls
// their arguments read directly, which the prepass publishes to them as it
// goes. Reads through locals and data are not followed for the latter: the
// prepass does not refresh locals or data between calls, so a speculative
// call only ever sees its siblings' prepass outputs through module.* itself.
func planSiblingPrepass(
	moduleBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	dataBlocks []*hclsyntax.Block,
) siblingPrepass {
	reads := newModuleReads(localExprs, dataBlocks)
	lastPos := make(map[string]int, len(moduleBlocks))
	direct := make([]*blockRefs, len(moduleBlocks))
	for i, mb := range moduleBlocks {
		lastPos[blockLabel(mb)] = i
		r := &blockRefs{}
		r.body(mb.Body, unevaluatedModuleAttrs)
		direct[i] = r
	}

	plan := siblingPrepass{members: make([]bool, len(moduleBlocks))}
	needed, all := forwardReads(reads, direct, lastPos)
	if all {
		// A read naming no call in particular may read any of them.
		for i := range plan.members {
			plan.members[i] = true
		}
		plan.any = true
		return plan
	}
	if len(needed) == 0 {
		return plan
	}
	closeOverDirectReads(moduleBlocks, direct, lastPos, needed)
	for i, mb := range moduleBlocks {
		if needed[blockLabel(mb)] {
			plan.members[i] = true
			plan.any = true
		}
	}
	return plan
}

// forwardReads returns the calls some call reads at or after its own
// position, or all when a call reads module.* without naming a call.
func forwardReads(reads *moduleReads, direct []*blockRefs, lastPos map[string]int) (needed map[string]bool, all bool) {
	needed = map[string]bool{}
	for i := range direct {
		modules, readsAll := reads.resolve(direct[i])
		if readsAll {
			return nil, true
		}
		for name := range modules {
			if pos, ok := lastPos[name]; ok && pos >= i {
				needed[name] = true
			}
		}
	}
	return needed, false
}

// closeOverDirectReads adds to needed the calls the needed calls' arguments
// read directly: the prepass publishes each member's outputs to the members
// after it through module.*.
func closeOverDirectReads(
	moduleBlocks []*hclsyntax.Block, direct []*blockRefs, lastPos map[string]int, needed map[string]bool,
) {
	for changed := true; changed; {
		changed = false
		for i, mb := range moduleBlocks {
			if !needed[blockLabel(mb)] {
				continue
			}
			for name := range lastPos {
				if needed[name] || (!direct[i].allModules && !direct[i].modules[name]) {
					continue
				}
				needed[name] = true
				changed = true
			}
		}
	}
}
