/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// exposureSkip are the arguments of a module call that carry no value of the
// caller: where the module comes from, which providers it uses, and ordering.
var exposureSkip = map[string]bool{"source": true, "version": true, "providers": true, "depends_on": true}

func unresolvedCalls(root *Root) map[string]bool {
	out := make(map[string]bool, len(root.Unresolved))
	for _, inst := range root.Unresolved {
		out[unresolvedKey(inst.Block.Module.Address, inst.Block.Name)] = true
	}
	return out
}

func unresolvedKey(moduleAddress, label string) string {
	return moduleAddress + "\x00" + label
}

// exposeUnresolved limits what the unresolved module calls make incomplete.
// A call that did not resolve may create blocks of its own, and may read a
// block of its caller only through its arguments, so only the instances
// those arguments reach, and the blocks that hold one of the strings they
// carry, can have a relation the model does not see. The arguments are traced
// through locals, variables and module outputs like any other expression.
// An argument that cannot be traced to blocks leaves the whole root
// incomplete.
func (t *tracer) exposeUnresolved() {
	root := t.root
	if len(root.Unresolved) == 0 {
		return
	}
	x := &tracer{root: root, blocks: t.blocks, modules: t.modules, unresolved: unresolvedCalls(root), outside: true}
	root.Exposed = map[*Instance]bool{}
	root.ExposedStrings = map[string]bool{}
	for _, inst := range root.Unresolved {
		root.Exposed[inst] = true
		collectStrings(inst, root.ExposedStrings)
		b := inst.Block
		walkExprs(b.Syntax.Body, nil, exposureSkip, nil, func(expr hcl.Expression, _ []string, shadowed []string) {
			targets, untraced := x.trace(b.Module, inst, expr, true, shadowed, 0)
			for _, tg := range targets {
				root.Exposed[tg.inst] = true
			}
			if untraced {
				root.Unscoped = true
			}
		})
	}
}

// collectStrings adds the known strings of the arguments of inst to out.
func collectStrings(inst *Instance, out map[string]bool) {
	for name, v := range inst.Attrs {
		if !exposureSkip[name] {
			addStrings(v, out)
		}
	}
}

func addStrings(v cty.Value, out map[string]bool) {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		out[v.AsString()] = true
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			addStrings(e, out)
		}
	case ty.IsMapType() || ty.IsObjectType():
		for it := v.ElementIterator(); it.Next(); {
			k, e := it.Element()
			addStrings(k, out)
			addStrings(e, out)
		}
	}
}
