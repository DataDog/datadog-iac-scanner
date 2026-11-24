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
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// fileInputView holds the changed bindings and local-data instances of one
// selection. It is computed from the dependencies visible to the current
// block, and is read-only after evaluation.
type fileInputView struct {
	bindings   map[string]cty.Value
	data       map[documentDataKey]documentDataSource
	recomputed map[documentDataKey]bool
	rendered   sync.Map
}

// fileViews memoizes the selected inputs within one evaluation of a block.
// A prepass, a scheduled evaluation and a rule projection use separate views.
type fileViews struct {
	ctx     context.Context
	e       *Evaluator
	base    *hcl.EvalContext
	inputs  *overrideInputs
	views   map[string]*fileInputView
	derived bool
}

func (e *Evaluator) fileViews(ctx context.Context, base *hcl.EvalContext, body *hclsyntax.Body, inputs *overrideInputs) *fileViews {
	if inputs == nil {
		return nil
	}
	derived := slices.ContainsFunc(terraform.BodyTraversals(body), func(t hcl.Traversal) bool {
		return t.RootName() == rootLocal || t.RootName() == blockTypeData
	})
	return &fileViews{ctx: ctx, e: e, base: base, inputs: inputs, views: make(map[string]*fileInputView), derived: derived}
}

func (v *fileViews) view(file string) *fileInputView {
	if v == nil {
		return nil
	}
	if view, ok := v.views[file]; ok {
		return view
	}
	vars, selected := v.inputs.files[file]
	if !selected || vars.RawEquals(v.base.Variables[rootVar]) || v.ctx.Err() != nil {
		return nil
	}
	view := &fileInputView{bindings: map[string]cty.Value{rootVar: vars}}
	if v.derived {
		v.e.deriveFileInputs(v.ctx, v.base, v.inputs, view)
	}
	v.views[file] = view
	return view
}

func (v *fileViews) context(base *hcl.EvalContext, file string) *hcl.EvalContext {
	if view := v.view(file); view != nil {
		return partial.Scope(base, view.bindings)
	}
	return base
}

func (e *Evaluator) deriveFileInputs(
	ctx context.Context, base *hcl.EvalContext, inputs *overrideInputs, view *fileInputView,
) {
	g := inputs.scope.static.resources
	n := len(g.blocks)
	s := &resourceSchedule{
		e: e, ctx: ctx, graph: g, scope: inputs.scope, base: base,
		globals: maps.Clone(base.Variables), references: make(map[int]cty.Value, n),
		exposed: make([][]ResolvedResource, n), cyclic: make([]bool, n),
		localValues: make(map[string]cty.Value), data: newModuleData(e, inputs.parsed, "", nil, nil),
	}
	s.globals[rootVar] = view.bindings[rootVar]
	// Module outputs, managed resources and existing data instances belong to
	// the live evaluation. Replay only local computations fed by the new vars.
	if locals := base.Variables[rootLocal]; slicableObject(locals) {
		for name, value := range locals.AsValueMap() {
			if i, ok := s.scope.localGraph.index[name]; ok {
				deps := s.scope.localGraph.deps[i]
				if !deps.vars && !deps.data {
					s.localValues[name] = value
				}
			}
		}
	}
	available := s.seedFileReferences(base)
	s.replayFileData(base, inputs.directedData, view)
	resolved := s.context(available, s.scope.localGraph.order)
	for _, name := range []string{rootLocal, blockTypeData} {
		if value := resolved.Variables[name]; !value.RawEquals(base.Variables[name]) {
			view.bindings[name] = value
		}
	}
	if len(view.recomputed) != 0 {
		scope := &ModuleScope{}
		s.data.resolved(scope)
		view.data = scope.dataSources
	}
}

func (s *resourceSchedule) seedFileReferences(base *hcl.EvalContext) []int {
	available := make([]int, 0, len(s.graph.blocks))
	for i, b := range s.graph.blocks {
		root, path := b.Labels[0], []string{b.Labels[1]}
		if b.Type == blockTypeData {
			root, path = blockTypeData, b.Labels
		}
		value := rootSliceValue(base.Variables[root], path)
		if value.IsNull() && base == s.scope.evalCtx && b.Type == blockTypeData {
			// A standalone refresh omits empty data expansions. A selection
			// can make their count or keys nonempty.
			switch {
			case b.Body.Attributes[metaArgCount] != nil:
				value = cty.EmptyTupleVal
			case b.Body.Attributes[metaArgForEach] != nil:
				value = cty.EmptyObjectVal
			}
		}
		s.references[i] = cty.NilVal
		if value != cty.NilVal && !value.IsNull() {
			s.references[i] = value
			available = append(available, i)
		}
	}
	return available
}

func (s *resourceSchedule) replayFileData(base *hcl.EvalContext, directed map[*hclsyntax.Body]bool, view *fileInputView) {
	g := s.graph
	for i, component := range g.components {
		if s.ctx.Err() != nil {
			break
		}
		unit := component[0]
		if g.cyclic[i] || unit < g.resources || s.references[unit] == cty.NilVal {
			continue
		}
		b := g.blocks[unit]
		if _, local := localdata.Lookup(b.Labels[0]); !local || directed[b.Body] || !s.dataReadsFileVars(unit, view) {
			continue
		}
		scope := s.context(g.edges[unit], g.locals[unit])
		values := blockEvalInputs(b, scope)
		if sameCtyValues(blockEvalInputs(b, base), values) {
			continue
		}
		cached := s.data.evalBlock(s.ctx, b, scope, values)
		delete(s.references, unit)
		s.exposed[unit] = cached.exposed
		s.reference(unit)
		if view.recomputed == nil {
			view.recomputed = make(map[documentDataKey]bool)
		}
		view.recomputed[documentDataKey{typ: b.Labels[0], name: b.Labels[1]}] = true
	}
}

func (s *resourceSchedule) dataReadsFileVars(unit int, view *fileInputView) bool {
	if slices.ContainsFunc(s.graph.locals[unit], func(local int) bool {
		return s.scope.localGraph.deps[local].vars
	}) {
		return true
	}
	for _, dep := range s.graph.edges[unit] {
		if dep >= s.graph.resources {
			block := s.graph.blocks[dep]
			if view.recomputed[documentDataKey{typ: block.Labels[0], name: block.Labels[1]}] {
				return true
			}
		}
	}
	return slices.ContainsFunc(terraform.BodyTraversals(s.graph.blocks[unit].Body), func(t hcl.Traversal) bool {
		return t.RootName() == rootVar
	})
}
