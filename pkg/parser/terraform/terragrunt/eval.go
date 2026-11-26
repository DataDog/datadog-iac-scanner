/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// varLocal is the root of local references.
const varLocal = "local"

// evalExpr evaluates expr; what cannot be evaluated is unknown. A failing
// object or tuple constructor, or merge call, is rebuilt item by item so one
// failing item does not hide the others.
func (t *translator) evalExpr(expr hcl.Expression, ctx *hcl.EvalContext) cty.Value {
	value, diags := expr.Value(ctx)
	if !diags.HasErrors() {
		return value
	}
	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return t.evalExpr(e.Expression, ctx)
	case *hclsyntax.ObjectConsExpr:
		items := make(map[string]cty.Value, len(e.Items))
		for _, item := range e.Items {
			k, kd := item.KeyExpr.Value(ctx)
			name, ok := stringKey(k, kd)
			if !ok {
				t.debugf("%s: an object key is not known, item dropped", item.KeyExpr.Range())
				continue
			}
			items[name] = t.evalExpr(item.ValueExpr, ctx)
		}
		return cty.ObjectVal(items)
	case *hclsyntax.TupleConsExpr:
		elems := make([]cty.Value, len(e.Exprs))
		for i, sub := range e.Exprs {
			elems[i] = t.evalExpr(sub, ctx)
		}
		return cty.TupleVal(elems)
	case *hclsyntax.FunctionCallExpr:
		if e.Name == funcMerge && !e.ExpandFinal {
			args := make([]cty.Value, len(e.Args))
			for i, a := range e.Args {
				args[i] = t.evalExpr(a, ctx)
			}
			if merged, err := functions.TerraformFuncs[funcMerge].Call(args); err == nil {
				return merged
			}
		}
	}
	t.debugf("%s: %s", expr.Range(), diags.Error())
	return cty.DynamicVal
}

func (t *translator) debugf(format string, args ...any) {
	log := logger.FromContext(t.ctx)
	log.Debug().Msgf("terragrunt: "+format, args...)
}

// attr evaluates a block attribute, cty.NilVal when it is absent.
func (t *translator) attr(body *hclsyntax.Body, name string, ctx *hcl.EvalContext) cty.Value {
	a, ok := body.Attributes[name]
	if !ok {
		return cty.NilVal
	}
	return t.evalExpr(a.Expr, ctx)
}

// knownString returns v when it is a known string.
func knownString(v cty.Value) (string, bool) {
	if v == cty.NilVal {
		return "", false
	}
	v, _ = v.UnmarkDeep()
	return ctyutil.ConcreteString(v)
}

// knownBool returns v when it is a known bool.
func knownBool(v cty.Value) (value, ok bool) {
	if v == cty.NilVal {
		return false, false
	}
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() || v.Type() != cty.Bool {
		return false, false
	}
	return v.True(), true
}

func blocksOfType(body *hclsyntax.Body, typ string) []*hclsyntax.Block {
	var out []*hclsyntax.Block
	for _, block := range body.Blocks {
		if block.Type == typ {
			out = append(out, block)
		}
	}
	return out
}

// features is the feature variable: each flag's default as feature.<name>.value.
func (t *translator) features(body *hclsyntax.Body, ctx *hcl.EvalContext) cty.Value {
	out := map[string]cty.Value{}
	for _, block := range blocksOfType(body, "feature") {
		if len(block.Labels) == 0 {
			continue
		}
		value := t.attr(block.Body, "default", ctx)
		if value == cty.NilVal {
			value = cty.NullVal(cty.DynamicPseudoType)
		}
		out[block.Labels[0]] = cty.ObjectVal(map[string]cty.Value{"value": value})
	}
	return cty.ObjectVal(out)
}

// evalLocals evaluates the locals blocks in dependency order. A local in a
// cycle, or reading a local that does not exist, is unknown.
func (t *translator) evalLocals(body *hclsyntax.Body, ctx *hcl.EvalContext) map[string]cty.Value {
	exprs := map[string]hclsyntax.Expression{}
	for _, block := range blocksOfType(body, "locals") {
		for name, a := range block.Body.Attributes {
			exprs[name] = a.Expr
		}
	}
	values := make(map[string]cty.Value, len(exprs))
	state := make(map[string]int, len(exprs)) // 1: evaluating, 2: done
	var visit func(name string) cty.Value
	visit = func(name string) cty.Value {
		switch state[name] {
		case 1:
			t.debugf("cycle through local.%s, read as unknown", name)
			return cty.DynamicVal
		case 2:
			return values[name]
		}
		expr, ok := exprs[name]
		if !ok {
			return cty.DynamicVal
		}
		state[name] = 1
		deps := map[string]cty.Value{}
		for _, dep := range localReferences(expr) {
			deps[dep] = visit(dep)
		}
		child := ctx.NewChild()
		child.Variables = map[string]cty.Value{varLocal: cty.ObjectVal(deps)}
		value := t.evalExpr(expr, child)
		state[name] = 2
		values[name] = value
		return value
	}
	names := make([]string, 0, len(exprs))
	for name := range exprs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		visit(name)
	}
	return values
}

// localReferences lists the locals expr reads.
func localReferences(expr hclsyntax.Expression) []string {
	var names []string
	seen := map[string]bool{}
	for _, traversal := range expr.Variables() {
		if traversal.RootName() != varLocal || len(traversal) < 2 {
			continue
		}
		name, ok := localName(traversal[1])
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// localName is the local a traversal step reads: local.x or local["x"].
func localName(step hcl.Traverser) (string, bool) {
	switch s := step.(type) {
	case hcl.TraverseAttr:
		return s.Name, true
	case hcl.TraverseIndex:
		return ctyutil.ConcreteString(s.Key)
	}
	return "", false
}

// inputsOf splits the value of an inputs attribute by key, each key with the
// item that sets it in the file, or the attribute itself when no literal item
// does (computed keys). unknown is true when the keys are not known.
func inputsOf(a *hclsyntax.Attribute, value cty.Value) (inputs map[string]item, unknown bool) {
	value, _ = value.UnmarkDeep()
	if !value.IsKnown() {
		return nil, true
	}
	if value.IsNull() {
		return map[string]item{}, false
	}
	if ty := value.Type(); !ty.IsObjectType() && !ty.IsMapType() {
		return nil, true
	}
	inputs = map[string]item{}
	for name, v := range value.AsValueMap() {
		rng, found := itemRange(a.Expr, name)
		if !found {
			rng = toRange(a.SrcRange)
		}
		inputs[name] = item{value: v, rng: rng}
	}
	return inputs, false
}

// itemRange finds the item setting key in an object constructor, or in the
// object constructors merge() combines, the last literal setting winning.
func itemRange(expr hclsyntax.Expression, key string) (model.SourceLocation, bool) {
	switch e := hclexpr.Unwrap(expr).(type) {
	case *hclsyntax.ObjectConsExpr:
		var rng model.SourceLocation
		found := false
		for _, it := range e.Items {
			if k, ok := literalKey(it.KeyExpr); ok && k == key {
				rng = toRange(hcl.RangeBetween(it.KeyExpr.Range(), it.ValueExpr.Range()))
				found = true
			}
		}
		return rng, found
	case *hclsyntax.FunctionCallExpr:
		if e.Name != funcMerge {
			return model.SourceLocation{}, false
		}
		for i := len(e.Args) - 1; i >= 0; i-- {
			if rng, ok := itemRange(e.Args[i], key); ok {
				return rng, true
			}
		}
	}
	return model.SourceLocation{}, false
}

// literalKey is an object item's key when it does not depend on variables.
func literalKey(expr hclsyntax.Expression) (string, bool) {
	if wrapped, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		if name := hcl.ExprAsKeyword(wrapped.Wrapped); name != "" && !wrapped.ForceNonLiteral {
			return name, true
		}
		expr = wrapped.Wrapped
	}
	v, diags := expr.Value(nil)
	return stringKey(v, diags)
}
