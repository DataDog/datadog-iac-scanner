/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Hooks let a caller observe and adjust an evaluation without changing its
// results for other callers. Every field is optional.
type Hooks struct {
	// Bodies rewrites the parsed files of a module directory before their
	// blocks are collected, for example to merge override files.
	Bodies func(dir string, bodies []*hclsyntax.Body) []*hclsyntax.Body
	// Scope is called once per completed evaluation of a module directory,
	// cached replays excluded, with its final scope. A speculative evaluation
	// reports too: a call whose inputs it computed correctly is a cached
	// replay of it, so the speculative scope is the only one it has. A later
	// evaluation of the same address with other inputs reports again.
	Scope func(dir, address string, scope *ModuleScope, outputs map[string]cty.Value)
	// Instance is called for every module call instance the evaluation keeps,
	// cached replays included, with the inputs and outputs it was evaluated
	// with.
	Instance func(dir, address string, chain []CallSite, inputs, outputs map[string]cty.Value)
}

// DynamicCounts values that are not a number of generated blocks.
const (
	// DynamicKeptAsWritten is a dynamic block that was not expanded: its body
	// is in the attributes under "dynamic", as written.
	DynamicKeptAsWritten = keptAsWritten
	// DynamicCountVaries is a dynamic block that generated a different number
	// of blocks under each element of its parent.
	DynamicCountVaries = unknownDynamicCount
)

// SetHooks installs hooks on e. Forks inherit them.
func (e *Evaluator) SetHooks(h *Hooks) { e.hooks = h }

// EvalContext returns the context the module's blocks were evaluated in. It is
// final once evaluation completes and must not be modified.
func (s *ModuleScope) EvalContext() *hcl.EvalContext { return s.evalCtx }

// Sources returns the module's file contents by the filename their ranges carry.
func (s *ModuleScope) Sources() map[string][]byte { return s.sources }

// ReleaseEvalState drops the evaluation context and local caches once the
// model is built. Locals, Bodies, Var, Local and the sources stay: module
// argument attribution and unknown-attribute text still read them.
func (s *ModuleScope) ReleaseEvalState() {
	if s == nil {
		return
	}
	s.evalCtx = nil
	s.localCache = nil
	s.localGraph = nil
}

func (e *Evaluator) hookBodies(dir string, bodies []*hclsyntax.Body) []*hclsyntax.Body {
	if e.hooks == nil || e.hooks.Bodies == nil {
		return bodies
	}
	return e.hooks.Bodies(dir, bodies)
}

func (e *Evaluator) hookScope(dir, address string, scope *ModuleScope, outputs map[string]cty.Value) {
	if e.hooks == nil || e.hooks.Scope == nil {
		return
	}
	e.hooks.Scope(dir, address, scope, outputs)
}

func (e *Evaluator) hookInstance(dir, address string, chain []CallSite, inputs, outputs map[string]cty.Value) {
	if e.hooks == nil || e.hooks.Instance == nil || e.prepassDepth > 0 {
		return
	}
	e.hooks.Instance(dir, address, chain, inputs, outputs)
}
