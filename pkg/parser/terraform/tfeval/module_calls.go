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

// moduleInstances expands a module call's count or for_each under ctx. It
// reports truncated when instances beyond maxCountExpansion were left out.
func moduleInstances(mb *hclsyntax.Block, ctx *hcl.EvalContext) (
	instances []moduleInstance, mode moduleExpansion, truncated bool,
) {
	if attr, ok := mb.Body.Attributes["count"]; ok {
		return countInstances(attr, ctx)
	}
	if attr, ok := mb.Body.Attributes["for_each"]; ok {
		return forEachInstances(attr, ctx)
	}
	return []moduleInstance{{ctx: ctx}}, expansionNone, false
}

func countInstances(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) ([]moduleInstance, moduleExpansion, bool) {
	v, diags := attr.Expr.Value(ctx)
	n, ok := 0, false
	if !diags.HasErrors() {
		n, ok = ctyutil.LiteralInt(v)
	}
	if !ok {
		return []moduleInstance{{ctx: iterationContext(ctx, "count", map[string]cty.Value{
			"index": cty.UnknownVal(cty.Number),
		})}}, expansionUnknown, false
	}
	expand := min(max(n, 0), maxCountExpansion)
	instances := make([]moduleInstance, expand)
	for i := range instances {
		index := cty.NumberIntVal(int64(i))
		instances[i] = moduleInstance{
			key: index,
			ctx: iterationContext(ctx, "count", map[string]cty.Value{"index": index}),
		}
	}
	return instances, expansionCount, n > maxCountExpansion
}

func forEachInstances(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) ([]moduleInstance, moduleExpansion, bool) {
	unknown := []moduleInstance{{ctx: iterationContext(ctx, "each", map[string]cty.Value{
		"key":   cty.UnknownVal(cty.String),
		"value": cty.DynamicVal,
	})}}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !ctyutil.Materialized(v) || !v.CanIterateElements() || !v.Length().IsKnown() {
		return unknown, expansionUnknown, false
	}
	if v.LengthInt() == 0 {
		return nil, expansionForEach, false
	}
	t := v.Type()
	if !t.IsObjectType() && !t.IsMapType() && !t.IsSetType() {
		return unknown, expansionUnknown, false
	}
	instances := make([]moduleInstance, 0, min(v.LengthInt(), maxCountExpansion))
	for it := v.ElementIterator(); it.Next() && len(instances) < maxCountExpansion; {
		key, value := it.Element()
		if _, ok := ctyutil.ConcreteString(key); !ok {
			return unknown, expansionUnknown, false
		}
		instances = append(instances, moduleInstance{
			key: key,
			ctx: iterationContext(ctx, "each", map[string]cty.Value{"key": key, "value": value}),
		})
	}
	return instances, expansionForEach, v.LengthInt() > maxCountExpansion
}

func iterationContext(ctx *hcl.EvalContext, name string, attrs map[string]cty.Value) *hcl.EvalContext {
	child := ctx.NewChild()
	child.Variables = map[string]cty.Value{name: cty.ObjectVal(attrs)}
	return child
}

// moduleOutputsValue is what module.<label> evaluates to in the caller: the
// outputs object of a single call, a tuple of them for count and an object of
// them keyed like for_each. outs holds cty.NilVal for instances that failed.
func moduleOutputsValue(mode moduleExpansion, instances []moduleInstance, outs []cty.Value) (cty.Value, bool) {
	switch mode {
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
		byKey := make(map[string]cty.Value, len(outs))
		for i, out := range outs {
			key, _ := ctyutil.ConcreteString(instances[i].key)
			byKey[key] = orUnknown(out)
		}
		return objectOrEmpty(byKey), true
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
