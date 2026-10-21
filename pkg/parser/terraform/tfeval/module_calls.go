/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	tfinstances "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// moduleCall is a module block whose source resolved to a directory.
type moduleCall struct {
	block                  *hclsyntax.Block
	label, source, version string
	dir, packageRoot       string
}

func (e *Evaluator) resolveModuleCall(
	ctx context.Context, mb *hclsyntax.Block, evalCtx *hcl.EvalContext, callerDir, packageRoot string,
) (moduleCall, bool) {
	label := blockLabel(mb)
	if label == "" {
		return moduleCall{}, false
	}
	source := ctyutil.StringFromAttribute(mb.Body.Attributes["source"], evalCtx)
	if source == "" {
		return moduleCall{}, false
	}
	version := ctyutil.StringFromAttribute(mb.Body.Attributes["version"], evalCtx)
	dir, childPackageRoot, ok := e.resolveModuleDir(
		ctx, callerDir, packageRoot, source, version, mb.TypeRange.Filename, label,
	)
	if !ok {
		return moduleCall{}, false
	}
	return moduleCall{
		block: mb, label: label, source: source, version: version, dir: dir, packageRoot: childPackageRoot,
	}, true
}

func (c *moduleCall) site(scope *ModuleScope) CallSite {
	return CallSite{
		ModuleName:      c.label,
		Source:          c.source,
		Version:         c.version,
		CalledFrom:      c.block.TypeRange.Filename,
		CalledLine:      c.block.TypeRange.Start.Line,
		CalledEndLine:   c.block.Range().End.Line,
		CalledColumn:    c.block.TypeRange.Start.Column,
		CalledEndColumn: c.block.Range().End.Column,
		Body:            c.block.Body,
		Caller:          scope,
	}
}

// moduleExpansion is how a module call's count or for_each expanded.
type moduleExpansion int

const (
	expansionNone moduleExpansion = iota
	expansionCount
	expansionForEach
	// expansionUnknown is a count or for_each that could not be resolved; the
	// call is evaluated once with an unknown count.index or each.
	expansionUnknown
)

// moduleInstance is one instance of a module call: the key Terraform addresses
// it by and the context its arguments are evaluated in.
type moduleInstance struct {
	key cty.Value
	ctx *hcl.EvalContext
}

func (i moduleInstance) address(parent, label string) string {
	seg := "module." + label
	if i.key != cty.NilVal {
		if formatted, ok := ctyutil.FormatIndexKey(i.key); ok {
			seg += formatted
		}
	}
	return joinAddr(parent, seg)
}

// moduleExpansionPlan is the result of expanding a module call's count/for_each.
type moduleExpansionPlan struct {
	instances []moduleInstance
	mode      moduleExpansion
	// requested is the full instance count when known (before the per-block cap).
	requested int
	// forEachKeys is every for_each key when mode is for_each and the collection
	// is within maxExpansionShape (including keys beyond the expansion cap).
	forEachKeys []cty.Value
}

func (p moduleExpansionPlan) truncated() bool {
	return p.requested > maxCountExpansion && (p.mode == expansionCount || p.mode == expansionForEach)
}

// moduleInstances expands a module call's count or for_each under ctx.
func moduleInstances(mb *hclsyntax.Block, ctx *hcl.EvalContext) moduleExpansionPlan {
	count, forEach := tfinstances.Attributes(mb.Body)
	plan := tfinstances.Resolve(count, forEach, ctx, maxExpansionShape)
	return modulePlan(&plan, ctx)
}

// modulePlan adds caller contexts and the module-specific unresolved fallback.
// Expansion decisions and iteration bindings come from the shared resolver;
// output padding and instantiation budgets remain owned by the evaluator.
func modulePlan(plan *tfinstances.Plan, ctx *hcl.EvalContext) moduleExpansionPlan {
	if plan.Kind == "" {
		return moduleExpansionPlan{
			instances: []moduleInstance{{ctx: ctx}},
			mode:      expansionNone,
			requested: 1,
		}
	}
	if plan.Unresolved {
		return moduleExpansionPlan{
			instances: []moduleInstance{{ctx: instanceContext(ctx, plan, tfinstances.Item{})}},
			mode:      expansionUnknown,
		}
	}
	mode := expansionForEach
	if plan.Kind == tfinstances.KindCount {
		mode = expansionCount
	}
	expanded := make([]moduleInstance, len(plan.Items))
	for i, item := range plan.Items {
		expanded[i] = moduleInstance{key: item.Key, ctx: instanceContext(ctx, plan, item)}
	}
	return moduleExpansionPlan{
		instances:   expanded,
		mode:        mode,
		requested:   plan.Requested,
		forEachKeys: plan.ForEachKeys,
	}
}

func instanceContext(ctx *hcl.EvalContext, plan *tfinstances.Plan, item tfinstances.Item) *hcl.EvalContext {
	name, value := plan.Variable(item)
	child := ctx.NewChild()
	child.Variables = map[string]cty.Value{name: value}
	return child
}

func isForEachCollection(v cty.Value) bool { return tfinstances.ForEachCollection(v) }

// moduleOutputsValue is what module.<label> evaluates to in the caller: the
// outputs object of a single call, a tuple of them for count and an object of
// them keyed like for_each. outs holds cty.NilVal for instances that failed.
// When the expansion was truncated, the returned collection keeps the full
// requested shape with unknown values for instances that were not evaluated,
// unless the shape would exceed maxExpansionShape (then the whole value is unknown).
func moduleOutputsValue(plan moduleExpansionPlan, outs []cty.Value) (cty.Value, bool) {
	switch plan.mode {
	case expansionUnknown:
		return cty.DynamicVal, true
	case expansionCount:
		return truncatedCountOutputs(plan.requested, outs), true
	case expansionForEach:
		return truncatedForEachOutputs(plan, outs), true
	}
	if len(outs) == 1 && outs[0] != cty.NilVal {
		return outs[0], true
	}
	return cty.NilVal, false
}

func truncatedCountOutputs(requested int, outs []cty.Value) cty.Value {
	if requested == 0 {
		return cty.EmptyTupleVal
	}
	if requested > maxExpansionShape {
		return cty.DynamicVal
	}
	elems := make([]cty.Value, requested)
	for i := range elems {
		if i < len(outs) {
			elems[i] = orUnknown(outs[i])
		} else {
			elems[i] = cty.DynamicVal
		}
	}
	return cty.TupleVal(elems)
}

func truncatedForEachOutputs(plan moduleExpansionPlan, outs []cty.Value) cty.Value {
	if plan.requested == 0 {
		return cty.EmptyObjectVal
	}
	if plan.requested > maxExpansionShape {
		return cty.DynamicVal
	}
	byKey := make(map[string]cty.Value, plan.requested)
	switch {
	case len(plan.forEachKeys) == plan.requested:
		// Truncated (or fully keyed) shape: start with unknown for every key.
		for _, key := range plan.forEachKeys {
			s, _ := ctyutil.ConcreteString(key)
			byKey[s] = cty.DynamicVal
		}
	case plan.truncated():
		// Truncated but keys were not kept — do not publish a short object.
		return cty.DynamicVal
	}
	for i, out := range outs {
		if i >= len(plan.instances) {
			break
		}
		key, _ := ctyutil.ConcreteString(plan.instances[i].key)
		byKey[key] = orUnknown(out)
	}
	return objectOrEmpty(byKey)
}

func orUnknown(v cty.Value) cty.Value {
	if v == cty.NilVal {
		return cty.DynamicVal
	}
	return v
}
