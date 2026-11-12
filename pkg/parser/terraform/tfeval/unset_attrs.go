/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/customdecode"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// instanceRegistry holds the objects references to resource instances read, so
// that try and can tell an attribute a block leaves to its provider from a key
// that is missing, whatever alias the object is reached through.
//
// A block's configuration does not say which of the attributes it leaves out
// the provider computes. Terraform reads such an attribute as unknown until
// apply, and rejects the configuration for one the resource does not have, so
// an attribute missing from a resource instance is taken to be unknown: try
// and can return unknown for it rather than step past it. A missing key of any
// other object still falls through. referencedAttrs adds the attributes read
// directly by name to the instances; this covers the rest.
//
// It follows the evaluation cache's lifetime: a cached module's resources can
// be read through its outputs by a later evaluation.
type instanceRegistry struct {
	at map[instanceAt]registeredInstance
	// byShape indexes the instances by the hash of their attribute names, so
	// a lookup compares only objects of the same shape.
	byShape map[uint64]map[instanceAt]struct{}
}

// instanceAt identifies a resource instance across the module evaluations of
// one evaluation cache.
type instanceAt struct {
	dir, addr      string
	kind           refKind
	typ, name, key string
}

type registeredInstance struct {
	shape uint64
	value cty.Value
}

func newInstanceRegistry() *instanceRegistry {
	return &instanceRegistry{
		at:      map[instanceAt]registeredInstance{},
		byShape: map[uint64]map[instanceAt]struct{}{},
	}
}

// shapeOf hashes the attribute names of a known object, in any order.
func shapeOf(v cty.Value) (uint64, bool) {
	if !v.IsKnown() || v.IsNull() || !v.Type().IsObjectType() {
		return 0, false
	}
	attrs := v.Type().AttributeTypes()
	shape := uint64(len(attrs))
	for name := range attrs {
		h := fnv.New64a()
		_, _ = h.Write([]byte(name))
		shape += h.Sum64()
	}
	return shape, true
}

func (r *instanceRegistry) register(at *instanceAt, v cty.Value) {
	v, _ = v.Unmark()
	shape, ok := shapeOf(v)
	if old, seen := r.at[*at]; seen && (!ok || old.shape != shape) {
		delete(r.byShape[old.shape], *at)
		delete(r.at, *at)
	}
	if !ok {
		return
	}
	r.at[*at] = registeredInstance{shape: shape, value: v}
	if r.byShape[shape] == nil {
		r.byShape[shape] = map[instanceAt]struct{}{}
	}
	r.byShape[shape][*at] = struct{}{}
}

// holds reports whether v is the object of a resource instance.
func (r *instanceRegistry) holds(v cty.Value) bool {
	v, _ = v.Unmark()
	shape, ok := shapeOf(v)
	if !ok {
		return false
	}
	for at := range r.byShape[shape] {
		if r.at[at].value.RawEquals(v) {
			return true
		}
	}
	return false
}

// lacks reports whether step reads an attribute that container, a resource
// instance, does not set.
func (r *instanceRegistry) lacks(container cty.Value, step hcl.Traverser) bool {
	var name string
	switch s := step.(type) {
	case hcl.TraverseAttr:
		name = s.Name
	case hcl.TraverseIndex:
		if !s.Key.IsKnown() || s.Key.IsNull() || s.Key.Type() != cty.String {
			return false
		}
		name = s.Key.AsString()
	default:
		return false
	}
	return r.lacksName(container, name)
}

func (r *instanceRegistry) lacksName(container cty.Value, name string) bool {
	unmarked, _ := container.Unmark()
	if !unmarked.IsKnown() || unmarked.IsNull() || !unmarked.Type().IsObjectType() ||
		unmarked.Type().HasAttribute(name) {
		return false
	}
	return r.holds(unmarked)
}

// readsUnsetAttributes reports whether every error evaluating expr reports an
// attribute a resource instance does not set.
func (r *instanceRegistry) readsUnsetAttributes(expr hcl.Expression, diags hcl.Diagnostics) bool {
	if r == nil || len(r.at) == 0 {
		return false
	}
	found := false
	for _, d := range diags {
		if d.Severity != hcl.DiagError {
			continue
		}
		if !r.readsUnsetAttribute(expr, d) {
			return false
		}
		found = true
	}
	return found
}

func (r *instanceRegistry) readsUnsetAttribute(root hcl.Expression, d *hcl.Diagnostic) bool {
	if d.Subject == nil || d.EvalContext == nil {
		return false
	}
	switch x := d.Expression.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		return r.scopeTraversalReadsUnset(x, *d.Subject, d.EvalContext)
	case *hclsyntax.RelativeTraversalExpr:
		return r.relativeTraversalReadsUnset(root, x, *d.Subject, d.EvalContext)
	case *hclsyntax.IndexExpr:
		return r.indexReadsUnset(root, x, d.EvalContext)
	}
	return false
}

func (r *instanceRegistry) scopeTraversalReadsUnset(
	x *hclsyntax.ScopeTraversalExpr, subject hcl.Range, ctx *hcl.EvalContext,
) bool {
	i := failingStep(x.Traversal, subject)
	if i < 1 {
		return false
	}
	container, diags := x.Traversal[:i].TraverseAbs(ctx)
	return !diags.HasErrors() && r.lacks(container, x.Traversal[i])
}

func (r *instanceRegistry) relativeTraversalReadsUnset(
	root hcl.Expression, x *hclsyntax.RelativeTraversalExpr, subject hcl.Range, ctx *hcl.EvalContext,
) bool {
	i := failingStep(x.Traversal, subject)
	if i < 0 {
		return false
	}
	for _, source := range sourceValues(root, x.Source, ctx) {
		container, diags := x.Traversal[:i].TraverseRel(source)
		if !diags.HasErrors() && r.lacks(container, x.Traversal[i]) {
			return true
		}
	}
	return false
}

func (r *instanceRegistry) indexReadsUnset(root hcl.Expression, x *hclsyntax.IndexExpr, ctx *hcl.EvalContext) bool {
	key, diags := x.Key.Value(ctx)
	if diags.HasErrors() || !key.IsKnown() || key.IsNull() || key.Type() != cty.String {
		return false
	}
	for _, container := range sourceValues(root, x.Collection, ctx) {
		if r.lacksName(container, key.AsString()) {
			return true
		}
	}
	return false
}

// failingStep is the index of the traversal step a diagnostic reports.
func failingStep(t hcl.Traversal, subject hcl.Range) int {
	for i, step := range t {
		if step.SourceRange() == subject {
			return i
		}
	}
	return -1
}

// sourceValues is what expr evaluated to in ctx. The item of a splat holds
// each element of the splat's source in turn, and nothing once it is done.
func sourceValues(root hcl.Expression, expr hclsyntax.Expression, ctx *hcl.EvalContext) []cty.Value {
	item, ok := expr.(*hclsyntax.AnonSymbolExpr)
	if !ok {
		v, diags := expr.Value(ctx)
		if diags.HasErrors() {
			return nil
		}
		return []cty.Value{v}
	}
	splat := splatOf(root, item)
	if splat == nil {
		return nil
	}
	source, diags := splat.Source.Value(ctx)
	if diags.HasErrors() || !source.IsKnown() || source.IsNull() {
		return nil
	}
	source, _ = source.Unmark()
	ty := source.Type()
	if !ty.IsTupleType() && !ty.IsListType() && !ty.IsSetType() {
		return []cty.Value{source}
	}
	out := make([]cty.Value, 0, source.LengthInt())
	for it := source.ElementIterator(); it.Next(); {
		_, v := it.Element()
		out = append(out, v)
	}
	return out
}

func splatOf(root hcl.Expression, item *hclsyntax.AnonSymbolExpr) *hclsyntax.SplatExpr {
	node, ok := root.(hclsyntax.Node)
	if !ok {
		return nil
	}
	var found *hclsyntax.SplatExpr
	_ = hclsyntax.VisitAll(node, func(n hclsyntax.Node) hcl.Diagnostics {
		if s, ok := n.(*hclsyntax.SplatExpr); ok && s.Item == item {
			found = s
		}
		return nil
	})
	return found
}

// withUnsetAttrFunctions returns funcs with try and can reading an attribute a
// resource instance does not set as unknown.
func (e *Evaluator) withUnsetAttrFunctions(funcs map[string]function.Function) map[string]function.Function {
	funcs["try"] = function.New(&function.Spec{
		VarParam: &function.Parameter{Name: "expressions", Type: customdecode.ExpressionClosureType},
		Type: func(args []cty.Value) (cty.Type, error) {
			v, err := e.try(args)
			if err != nil {
				return cty.NilType, err
			}
			return v.Type(), nil
		},
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			return e.try(args)
		},
	})
	funcs["can"] = function.New(&function.Spec{
		Params: []function.Parameter{{Name: "expression", Type: customdecode.ExpressionClosureType}},
		Type:   function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			return e.can(args[0]), nil
		},
	})
	return funcs
}

// try is HCL's try, except that an argument failing only for reading an
// attribute a resource instance does not set is unknown.
func (e *Evaluator) try(args []cty.Value) (cty.Value, error) {
	if len(args) == 0 {
		return cty.NilVal, errors.New("at least one argument is required")
	}
	var diags hcl.Diagnostics
	for _, arg := range args {
		closure := customdecode.ExpressionClosureFromVal(arg)
		v, argDiags := closure.Value()
		if argDiags.HasErrors() {
			if e.registry.readsUnsetAttributes(closure.Expression, argDiags) {
				return cty.DynamicVal, nil
			}
			diags = append(diags, argDiags...)
			continue
		}
		if !v.IsWhollyKnown() {
			return cty.DynamicVal, nil
		}
		return v, nil
	}
	var buf strings.Builder
	buf.WriteString("no expression succeeded:\n")
	for _, d := range diags {
		if d.Subject != nil {
			fmt.Fprintf(&buf, "- %s (at %s)\n  %s\n", d.Summary, d.Subject, d.Detail)
		} else {
			fmt.Fprintf(&buf, "- %s\n  %s\n", d.Summary, d.Detail)
		}
	}
	buf.WriteString("\nAt least one expression must produce a successful result")
	return cty.NilVal, errors.New(buf.String())
}

func (e *Evaluator) can(arg cty.Value) cty.Value {
	closure := customdecode.ExpressionClosureFromVal(arg)
	v, diags := closure.Value()
	if diags.HasErrors() {
		if e.registry.readsUnsetAttributes(closure.Expression, diags) {
			return cty.UnknownVal(cty.Bool)
		}
		return cty.False
	}
	if !v.IsWhollyKnown() {
		return cty.UnknownVal(cty.Bool)
	}
	return cty.True
}
