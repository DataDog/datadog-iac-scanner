/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// The roots a shareable local may read.
const (
	rootVar       = "var"
	rootLocal     = "local"
	rootPath      = "path"
	rootTerraform = "terraform"
)

// localMemoKey identifies a local's value by its expression and the values it
// reads. The expression pins the module directory its functions resolve files
// against, and the values read include path.*, which pins the root.
type localMemoKey struct {
	expr   hclsyntax.Expression
	inputs inputsDigest
}

// localReads is what a local expression reads. It is shareable when it reads
// nothing but var.*, local.*, path.* and terraform.*, so that its value is a
// function of those alone.
type localReads struct {
	shareable bool
	refs      []hcl.Traversal
}

// localValue evaluates a local, sharing the value with every evaluation of the
// same expression that reads the same values.
//
// A module loop hands every instance the same configuration, and a local
// derived from it alone is the same in each instance. Evaluating it once per
// instance repeats the work, and every instance's scope keeps its own copy
// until the root is merged: memory grows with the instances times the size of
// what the configuration is reshaped into.
func (e *Evaluator) localValue(expr hclsyntax.Expression, ctx *hcl.EvalContext) cty.Value {
	reads := e.localReadsOf(expr)
	if !reads.shareable {
		return evalLocal(expr, ctx)
	}
	inputs, ok := localInputs(reads.refs, ctx)
	if !ok {
		return evalLocal(expr, ctx)
	}
	key := localMemoKey{expr: expr, inputs: e.keyMemo.inputsKey(inputs)}
	if v, hit := e.localMemo[key]; hit {
		return v
	}
	v := evalLocal(expr, ctx)
	if e.localMemo == nil {
		e.localMemo = make(map[localMemoKey]cty.Value)
	}
	e.localMemo[key] = v
	return v
}

func evalLocal(expr hclsyntax.Expression, ctx *hcl.EvalContext) cty.Value {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		v = partial.WithUnknownRefs(expr, ctx)
	}
	return v
}

func (e *Evaluator) localReadsOf(expr hclsyntax.Expression) localReads {
	if reads, ok := e.localReads[expr]; ok {
		return reads
	}
	reads := localReads{shareable: true}
	for _, t := range expr.Variables() {
		switch t.RootName() {
		case rootVar, rootLocal:
			reads.refs = append(reads.refs, t)
		case rootPath, rootTerraform:
		default:
			reads = localReads{}
		}
		if !reads.shareable {
			break
		}
	}
	if e.localReads == nil {
		e.localReads = make(map[hclsyntax.Expression]localReads)
	}
	e.localReads[expr] = reads
	return reads
}

// localInputs returns the values refs read, each taken at the deepest static
// step of its traversal, so a local reading one attribute of a configuration
// is keyed by that attribute rather than the whole configuration.
func localInputs(refs []hcl.Traversal, ctx *hcl.EvalContext) (map[string]cty.Value, bool) {
	path, ok := contextVariable(ctx, rootPath)
	if !ok || path.IsMarked() || !path.IsWhollyKnown() || !path.Type().IsObjectType() {
		return nil, false
	}
	// path.* is rebuilt for every module evaluation, so its attributes are
	// keyed as strings: digesting the object would memoize one per evaluation.
	inputs := make(map[string]cty.Value, len(refs)+len(path.Type().AttributeTypes()))
	for name := range path.Type().AttributeTypes() {
		inputs[rootPath+"\x00"+name] = path.GetAttr(name)
	}
	for _, t := range refs {
		root := t.RootName()
		v, ok := contextVariable(ctx, root)
		if !ok {
			inputs[root+"\x00!"] = cty.True
			continue
		}
		name := root
		for _, step := range t[1:] {
			next, label, found := traverseStatic(v, step)
			if found == stepAbsent {
				// A step known to be absent fails the same whatever else v holds, so
				// key the read by the absence rather than by v.
				v, name = cty.True, name+"\x00"+label+"\x00!"
				break
			}
			if found != stepFound {
				break
			}
			v, name = next, name+"\x00"+label
		}
		if v.IsMarked() {
			return nil, false
		}
		inputs[name] = v
	}
	return inputs, true
}

type stepResult int

const (
	stepUnresolved stepResult = iota
	stepFound
	// stepAbsent is a step v is known to lack, which fails the same whatever
	// else v holds.
	stepAbsent
)

// traverseStatic applies an attribute or literal index step to v, when v is a
// known value the step resolves in.
func traverseStatic(v cty.Value, step hcl.Traverser) (cty.Value, string, stepResult) {
	key, ok := stepKey(step)
	if !ok || v.IsMarked() || !v.IsKnown() || v.IsNull() {
		return cty.NilVal, "", stepUnresolved
	}
	t := v.Type()
	switch {
	case key.Type() == cty.String && t.IsObjectType():
		name := key.AsString()
		if !t.HasAttribute(name) {
			return cty.NilVal, strconv.Quote(name), stepAbsent
		}
		return v.GetAttr(name), strconv.Quote(name), stepFound
	case key.Type() == cty.String && t.IsMapType(),
		key.Type() == cty.Number && (t.IsListType() || t.IsTupleType()):
		if !v.HasIndex(key).True() {
			return cty.NilVal, stepLabel(key), stepAbsent
		}
		return v.Index(key), stepLabel(key), stepFound
	}
	return cty.NilVal, "", stepUnresolved
}

// stepKey is the key an attribute or literal index step reads.
func stepKey(step hcl.Traverser) (cty.Value, bool) {
	var key cty.Value
	switch s := step.(type) {
	case hcl.TraverseAttr:
		key = cty.StringVal(s.Name)
	case hcl.TraverseIndex:
		key = s.Key
	default:
		return cty.NilVal, false
	}
	return key, !key.IsMarked() && key.IsKnown() && !key.IsNull()
}

func stepLabel(key cty.Value) string {
	if key.Type() == cty.String {
		return strconv.Quote(key.AsString())
	}
	return "[" + key.AsBigFloat().Text('f', -1) + "]"
}

// contextVariable looks name up through ctx and its parents.
func contextVariable(ctx *hcl.EvalContext, name string) (cty.Value, bool) {
	for c := ctx; c != nil; c = c.Parent() {
		if v, ok := c.Variables[name]; ok {
			return v, true
		}
	}
	return cty.NilVal, false
}
