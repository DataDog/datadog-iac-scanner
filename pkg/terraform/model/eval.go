/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Options configure loading.
type Options struct {
	// FS serves every read; nil is the real disk.
	FS vfs.FS
	// Resolver resolves module sources that are not local; nil leaves them
	// unresolved, which makes their root incomplete.
	Resolver tfeval.RemoteResolver
	// Plans are Terraform plan JSON files to model, each as its own root
	// after the source roots.
	Plans []string
	// PlansOnly skips the source roots.
	PlansOnly bool
	// Files, when not nil, is the set of scanned configuration files. The
	// roots are found among their directories instead of by walking the base,
	// and the other configuration files of those directories are never read.
	Files map[string]bool
	// VarsPath is an explicit selected .tfvars file (CLI). Empty discovers
	// a // kics_terraform_vars: directive in the root configs.
	VarsPath string
}

// evaluation is what evaluating one root returned, before modeling.
type evaluation struct {
	resources []tfeval.ResolvedResource
	outputs   map[string]cty.Value
	scopes    map[string]scopeRecord
	instances map[string]instanceRecord
	kept      []tfeval.ModuleInstance
	// evaluated lists, per directory, the module instances that were really
	// evaluated rather than replayed from the cache.
	evaluated map[string][]string
	// scopeByInput maps directory + input identity to the scope of the first
	// real evaluation, so cache replays skip repeated input-map compares.
	scopeByInput map[scopeInputKey]*tfeval.ModuleScope
	inputMemo    tfeval.InputMemo
	skipped      []string
	degraded     bool
	err          error
}

type scopeInputKey struct {
	dir string
	key tfeval.InputKey
}

type scopeRecord struct {
	dir     string
	scope   *tfeval.ModuleScope
	outputs map[string]cty.Value
}

type instanceRecord struct {
	dir     string
	chain   []tfeval.CallSite
	inputs  map[string]cty.Value
	outputs map[string]cty.Value
	// scope is set when the Instance hook can resolve it (real evaluation or
	// indexed replay).
	scope *tfeval.ModuleScope
}

// evaluate runs tfeval on a root with its autoloaded variables. When that
// fails, and ctx is not done, it evaluates the root again with every root
// variable unknown (the degraded mode). Evaluation is unbounded: no instantiation budget. eval may
// be nil; a non-nil evaluator is reused across roots so the parse cache is
// shared, and its evaluation cache is released after each root.
func evaluate(
	ctx context.Context, fsys vfs.FS, resolver tfeval.RemoteResolver, dir string, varNames []string, eval *tfeval.Evaluator, varsPath string,
) *evaluation {
	e := eval
	if e == nil {
		e = tfeval.NewWithFS(fsys)
		e.SetOpaquePartialData(true)
		e.SetTrackModuleInstances(true)
	}
	if resolver != nil {
		e.SetRemoteResolver(resolver)
	}
	ev := runEvaluation(ctx, fsys, e, dir, nil, varsPath)
	if ctxErr := ctx.Err(); ctxErr != nil && ev.err == nil {
		ev.err = ctxErr
	}
	if ev.err == nil || ctx.Err() != nil {
		e.ReleaseEvalCache()
		e.ForgetRootParse(dir)
		return ev
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Err(ev.err).Str("root", dir).Msg("terraform model: evaluating the root with every variable unknown")
	if len(varNames) == 0 {
		varNames = e.DeclaredVariables(ctx, dir)
	}
	inputs := make(map[string]cty.Value, len(varNames))
	for _, name := range varNames {
		inputs[name] = cty.DynamicVal
	}
	degraded := runEvaluation(ctx, fsys, e, dir, inputs, varsPath)
	degraded.degraded = true
	e.ReleaseEvalCache()
	e.ForgetRootParse(dir)
	return degraded
}

var runEvaluation = run

func run(
	ctx context.Context, fsys vfs.FS, e *tfeval.Evaluator, dir string, inputs map[string]cty.Value, varsPath string,
) *evaluation {
	out := &evaluation{
		scopes:       map[string]scopeRecord{},
		instances:    map[string]instanceRecord{},
		scopeByInput: map[scopeInputKey]*tfeval.ModuleScope{},
	}
	e.SetHooks(&tfeval.Hooks{
		Bodies: func(_ string, bodies []*hclsyntax.Body) []*hclsyntax.Body { return MergeOverrides(bodies) },
		Scope: func(dir, address string, scope *tfeval.ModuleScope, outputs map[string]cty.Value) {
			out.scopes[address] = scopeRecord{dir: dir, scope: scope, outputs: outputs}
		},
		Instance: func(dir, address string, chain []tfeval.CallSite, inputs, outputs map[string]cty.Value) {
			rec := instanceRecord{dir: dir, chain: chain, inputs: inputs, outputs: outputs}
			key := scopeInputKey{dir: dir, key: out.inputMemo.Key(inputs)}
			if s, ok := out.scopes[address]; ok {
				rec.scope = s.scope
				out.scopeByInput[key] = s.scope
			} else {
				rec.scope = out.scopeByInput[key]
			}
			out.instances[address] = rec
		},
	})
	if inputs == nil {
		inputs = e.LoadRootInputs(ctx, dir, varsPath)
	}
	out.resources, out.outputs, _, out.err = e.EvaluateModule(ctx, dir, inputs)
	out.kept = e.TakeModuleInstances()
	out.skipped = e.TakeNotEvaluatedDirs()
	sort.Strings(out.skipped)
	return out
}

// modules returns the root module and the module instances evaluation kept,
// in address order, each with its scope. A cached replay of a module
// evaluation has no scope of its own: it takes the scope of the evaluation
// of the same directory with equal inputs.
func (ev *evaluation) modules(root *Root, dir string) []*Module {
	rootScope := ev.scopes[""]
	mods := []*Module{{Root: root, Dir: dir, Scope: rootScope.scope, Outputs: ev.outputs}}
	if mods[0].Outputs == nil {
		mods[0].Outputs = rootScope.outputs
	}
	ev.evaluated = map[string][]string{}
	for _, addr := range slices.Sorted(maps.Keys(ev.scopes)) {
		if _, ok := ev.instances[addr]; ok {
			ev.evaluated[ev.scopes[addr].dir] = append(ev.evaluated[ev.scopes[addr].dir], addr)
		}
	}
	kept := map[string]tfeval.ModuleInstance{}
	for _, k := range ev.kept {
		kept[k.ModuleAddress] = k
	}
	addrs := slices.Sorted(maps.Keys(kept))
	sort.SliceStable(addrs, func(i, j int) bool { return len(addrs[i]) < len(addrs[j]) })
	byAddr := map[string]*Module{"": mods[0]}
	for _, addr := range addrs {
		k := kept[addr]
		rec, ok := ev.instances[addr]
		if !ok {
			rec, ok = ev.rebased(addr, byAddr)
		}
		if !ok {
			continue
		}
		ev.instances[addr] = rec
		m := &Module{
			Root: root, Address: addr, Dir: k.Dir, Chain: k.CallChain,
			Inputs: rec.inputs, Outputs: rec.outputs,
		}
		switch {
		case rec.scope != nil:
			m.Scope = rec.scope
		case ev.scopes[addr].dir == k.Dir:
			m.Scope = ev.scopes[addr].scope
		default:
			m.Scope = ev.replayedScope(instanceRecord{dir: k.Dir, inputs: rec.inputs})
		}
		if i := strings.LastIndex(addr, ".module."); i > 0 {
			m.parent = byAddr[addr[:i]]
		} else {
			m.parent = mods[0]
		}
		byAddr[addr] = m
	}
	sort.Strings(addrs)
	for _, addr := range addrs {
		if m, ok := byAddr[addr]; ok {
			mods = append(mods, m)
		}
	}
	seen := map[string]bool{}
	for _, m := range mods {
		if !seen[m.Dir] {
			seen[m.Dir] = true
			m.Static = true
		}
	}
	return mods
}

// rebased finds the record of a module instance whose ancestor was a cached
// replay: tfeval replays the descendants of the original evaluation under
// the new address without evaluating them again. The original is the
// instance of the same directory with equal inputs as the closest modeled
// ancestor.
func (ev *evaluation) rebased(addr string, byAddr map[string]*Module) (instanceRecord, bool) {
	for i := strings.LastIndex(addr, ".module."); i > 0; i = strings.LastIndex(addr[:i], ".module.") {
		ancestor, rest := addr[:i], addr[i:]
		anc, ok := byAddr[ancestor]
		if !ok {
			continue
		}
		for _, orig := range ev.evaluated[anc.Dir] {
			if orig == ancestor || !sameInputs(ev.instances[orig].inputs, anc.Inputs) {
				continue
			}
			if child, ok := ev.instances[orig+rest]; ok {
				return child, true
			}
		}
		return instanceRecord{}, false
	}
	return instanceRecord{}, false
}

func (ev *evaluation) replayedScope(rec instanceRecord) *tfeval.ModuleScope {
	for _, addr := range ev.evaluated[rec.dir] {
		if sameInputs(ev.instances[addr].inputs, rec.inputs) {
			return ev.scopes[addr].scope
		}
	}
	return nil
}

func sameInputs(a, b map[string]cty.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !v.RawEquals(w) {
			return false
		}
	}
	return true
}

func (ev *evaluation) notes(base string) []string {
	var notes []string
	if ev.err != nil {
		notes = append(notes, fmt.Sprintf("evaluation failed: %v", ev.err))
	}
	for _, dir := range ev.skipped {
		if rel, err := filepath.Rel(base, dir); err == nil {
			dir = rel
		}
		notes = append(notes, "module directory not evaluated: "+filepath.ToSlash(dir))
	}
	return notes
}
