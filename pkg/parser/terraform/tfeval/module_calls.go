/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
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

// moduleExpansionPlan is how a module call's count/for_each expanded. Its
// instances are generated one at a time by all, so nothing is allocated for
// instances before they are evaluated, and a known expansion yields every
// instance it declares.
type moduleExpansionPlan struct {
	mode    moduleExpansion
	ctx     *hcl.EvalContext
	count   int
	forEach cty.Value
	// unknown is the iteration variable bound when the expansion is unknown.
	unknown string
}

// moduleInstances plans the expansion of a module call's count or for_each under ctx.
func moduleInstances(mb *hclsyntax.Block, ctx *hcl.EvalContext) moduleExpansionPlan {
	if attr, ok := mb.Body.Attributes[iterCount]; ok {
		n, state := countValue(attr.Expr, ctx)
		if state != expansionKnown {
			return moduleExpansionPlan{mode: expansionUnknown, ctx: ctx, unknown: iterCount}
		}
		return moduleExpansionPlan{mode: expansionCount, ctx: ctx, count: n}
	}
	if attr, ok := mb.Body.Attributes[forEachArg]; ok {
		v, state := forEachValue(attr.Expr, ctx)
		if state != expansionKnown {
			return moduleExpansionPlan{mode: expansionUnknown, ctx: ctx, unknown: iterEach}
		}
		return moduleExpansionPlan{mode: expansionForEach, ctx: ctx, forEach: v}
	}
	return moduleExpansionPlan{mode: expansionNone, ctx: ctx}
}

// all yields every instance of the plan in Terraform's order: count by index,
// for_each by key.
func (p *moduleExpansionPlan) all(yield func(moduleInstance) bool) {
	switch p.mode {
	case expansionNone:
		yield(moduleInstance{ctx: p.ctx})
	case expansionUnknown:
		yield(moduleInstance{ctx: unknownIterationContext(p.ctx, p.unknown)})
	case expansionCount:
		for i := range p.count {
			index := cty.NumberIntVal(int64(i))
			if !yield(moduleInstance{key: index, ctx: iterationContext(p.ctx, iterCount, map[string]cty.Value{"index": index})}) {
				return
			}
		}
	case expansionForEach:
		for it := p.forEach.ElementIterator(); it.Next(); {
			key, value := it.Element()
			ctx := iterationContext(p.ctx, iterEach, map[string]cty.Value{"key": key, "value": value})
			if !yield(moduleInstance{key: key, ctx: ctx}) {
				return
			}
		}
	}
}

// unknownIterationContext binds count.index or each to unknown values.
func unknownIterationContext(ctx *hcl.EvalContext, name string) *hcl.EvalContext {
	if name == iterCount {
		return iterationContext(ctx, iterCount, map[string]cty.Value{"index": cty.UnknownVal(cty.Number)})
	}
	return iterationContext(ctx, iterEach, map[string]cty.Value{"key": cty.UnknownVal(cty.String), "value": cty.DynamicVal})
}

func iterationContext(ctx *hcl.EvalContext, name string, attrs map[string]cty.Value) *hcl.EvalContext {
	child := ctx.NewChild()
	child.Variables = map[string]cty.Value{name: cty.ObjectVal(attrs)}
	return child
}

// moduleOutputsValue is what module.<label> evaluates to in the caller: the
// outputs object of a single call, a tuple of them for count and an object of
// them keyed like for_each. outs holds the outputs of every instance in plan
// order, cty.NilVal for one that failed, which reads as unknown, and keys the
// for_each key of each.
func moduleOutputsValue(plan *moduleExpansionPlan, keys, outs []cty.Value) (cty.Value, bool) {
	switch plan.mode {
	case expansionUnknown:
		return cty.DynamicVal, true
	case expansionCount:
		if len(outs) == 0 {
			return cty.EmptyTupleVal, true
		}
		elems := make([]cty.Value, len(outs))
		for i, out := range outs {
			elems[i] = orUnknown(out)
		}
		return cty.TupleVal(elems), true
	case expansionForEach:
		if len(outs) == 0 {
			return cty.EmptyObjectVal, true
		}
		byKey := make(map[string]cty.Value, len(outs))
		for i, out := range outs {
			key, _ := ctyutil.ConcreteString(keys[i])
			byKey[key] = orUnknown(out)
		}
		return cty.ObjectVal(byKey), true
	}
	if len(outs) == 1 && outs[0] != cty.NilVal {
		return outs[0], true
	}
	return cty.NilVal, false
}

func orUnknown(v cty.Value) cty.Value {
	if v == cty.NilVal {
		return cty.DynamicVal
	}
	return v
}
