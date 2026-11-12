/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/customdecode"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// resourceInstanceMark marks the object of a resource instance that identity
// cannot name: the empty object is a shared constant, and merge builds a new
// object. Non-empty instances are recognized by identity instead. Marking
// those would make a for expression that rebuilds the object look like an
// instance, because HCL copies the mark onto the result.
type resourceInstanceMark struct{}

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
// Non-empty instances are recognized by identity: reading an attribute or an
// element of a value returns the value stored in it, so an alias, a splat or
// a module variable or output still reaches the registered object. Empty
// instances and merge results carry resourceInstanceMark instead. An object a
// configuration builds with the same attributes is neither marked nor
// registered.
//
// It follows the evaluation cache's lifetime: a cached module's resources can
// be read through its outputs by a later evaluation.
type instanceRegistry struct {
	at map[instanceAt]registeredInstance
	// held counts the instances registered under each identity.
	held map[objectID]int
}

// instanceAt identifies a resource instance across the module evaluations of
// one evaluation cache.
type instanceAt struct {
	dir, addr      string
	kind           refKind
	typ, name, key string
}

type registeredInstance struct {
	id objectID
	// value keeps the object alive, so that its identity is not reused.
	value cty.Value
}

func newInstanceRegistry() *instanceRegistry {
	return &instanceRegistry{
		at:   map[instanceAt]registeredInstance{},
		held: map[objectID]int{},
	}
}

// objectID identifies the storage of a known object value. Copies of a value
// share it, and so do the values read from it.
type objectID uintptr

// objectIDOf returns the identity of v if it is a known, non-empty object. The
// empty object is a shared constant, not the object of an instance.
func objectIDOf(v cty.Value) (objectID, bool) {
	if !v.IsKnown() || v.IsNull() || !v.Type().IsObjectType() {
		return 0, false
	}
	raw := reflect.ValueOf(&v).Elem().FieldByName("v")
	if !raw.IsValid() || raw.Kind() != reflect.Interface || raw.IsNil() {
		return 0, false
	}
	storage := raw.Elem()
	if storage.Kind() != reflect.Map || storage.IsNil() || storage.Len() == 0 {
		return 0, false
	}
	return objectID(storage.Pointer()), true
}

func (r *instanceRegistry) register(at *instanceAt, v cty.Value) {
	v, _ = v.Unmark()
	id, ok := objectIDOf(v)
	if old, seen := r.at[*at]; seen {
		if ok && old.id == id {
			return
		}
		r.release(old.id)
		delete(r.at, *at)
	}
	if !ok {
		return
	}
	r.at[*at] = registeredInstance{id: id, value: v}
	r.held[id]++
}

func (r *instanceRegistry) release(id objectID) {
	if r.held[id] <= 1 {
		delete(r.held, id)
		return
	}
	r.held[id]--
}

// isResourceInstance reports whether v is the object of a resource instance.
func (r *instanceRegistry) isResourceInstance(v cty.Value) bool {
	if v.HasMark(resourceInstanceMark{}) {
		return true
	}
	if r == nil {
		return false
	}
	v, _ = v.Unmark()
	id, ok := objectIDOf(v)
	return ok && r.held[id] > 0
}

// markResourceInstance marks v when identity cannot name it: the empty object,
// or any object a caller such as merge has already decided is an instance.
func markResourceInstance(v cty.Value) cty.Value {
	if v.IsNull() || !v.IsKnown() || v.HasMark(resourceInstanceMark{}) {
		return v
	}
	return v.Mark(resourceInstanceMark{})
}

// markEmptyResourceInstance marks v only when it is the empty object.
func markEmptyResourceInstance(v cty.Value) cty.Value {
	u, _ := v.Unmark()
	if !u.IsKnown() || u.IsNull() || !u.Type().IsObjectType() || len(u.Type().AttributeTypes()) > 0 {
		return v
	}
	return markResourceInstance(v)
}

// markResourceInstances marks empty instance objects of a block's reference
// value. Non-empty instances are recorded in the registry by identity.
func markResourceInstances(v cty.Value, expanded bool) cty.Value {
	if !expanded {
		return markEmptyResourceInstance(v)
	}
	if v.IsNull() || !v.IsKnown() || !v.CanIterateElements() {
		return v
	}
	ty := v.Type()
	switch {
	case ty.IsTupleType() || ty.IsListType():
		elems := make([]cty.Value, 0, v.LengthInt())
		for it := v.ElementIterator(); it.Next(); {
			_, elem := it.Element()
			elems = append(elems, markEmptyResourceInstance(elem))
		}
		if ty.IsListType() {
			if len(elems) == 0 {
				return v
			}
			return cty.ListVal(elems)
		}
		return cty.TupleVal(elems)
	case ty.IsObjectType() || ty.IsMapType():
		kvs := make(map[string]cty.Value, v.LengthInt())
		for it := v.ElementIterator(); it.Next(); {
			k, elem := it.Element()
			kvs[k.AsString()] = markEmptyResourceInstance(elem)
		}
		if len(kvs) == 0 {
			return v
		}
		if ty.IsMapType() {
			return cty.MapVal(kvs)
		}
		return cty.ObjectVal(kvs)
	}
	return v
}

// isUserMarked reports whether v carries a mark other than the one this
// package puts on resource instances. Call sites that refuse marked values
// (memo keys, for_each narrowing) must still accept an instance mark alone.
func isUserMarked(v cty.Value) bool {
	if !v.IsMarked() {
		return false
	}
	marks := v.Marks()
	if len(marks) == 1 {
		if _, ok := marks[resourceInstanceMark{}]; ok {
			return false
		}
	}
	return true
}

// withoutResourceInstanceMarks returns v with this package's instance mark
// removed at every path, keeping any other marks. Resource attributes and
// module outputs that leave the evaluator must not carry it.
func withoutResourceInstanceMarks(v cty.Value) cty.Value {
	v, paths := v.UnmarkDeepWithPaths()
	if len(paths) == 0 {
		return v
	}
	kept := make([]cty.PathValueMarks, 0, len(paths))
	for _, pvm := range paths {
		if _, ok := pvm.Marks[resourceInstanceMark{}]; !ok {
			kept = append(kept, pvm)
			continue
		}
		if len(pvm.Marks) == 1 {
			continue
		}
		marks := make(cty.ValueMarks, len(pvm.Marks)-1)
		for m := range pvm.Marks {
			if _, ours := m.(resourceInstanceMark); ours {
				continue
			}
			marks[m] = struct{}{}
		}
		if len(marks) > 0 {
			kept = append(kept, cty.PathValueMarks{Path: pvm.Path, Marks: marks})
		}
	}
	return v.MarkWithPaths(kept)
}

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
	if !r.isResourceInstance(container) {
		return false
	}
	unmarked, _ := container.Unmark()
	return unmarked.IsKnown() && !unmarked.IsNull() && unmarked.Type().IsObjectType() &&
		!unmarked.Type().HasAttribute(name)
}

func (r *instanceRegistry) readsUnsetAttributes(expr hcl.Expression, diags hcl.Diagnostics) bool {
	if r == nil {
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

func failingStep(t hcl.Traversal, subject hcl.Range) int {
	for i, step := range t {
		if step.SourceRange() == subject {
			return i
		}
	}
	return -1
}

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
// resource instance does not set as unknown, and merge keeping that recognition
// on its result when an argument is an instance.
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
	funcs["merge"] = e.mergeFunc(funcs["merge"])
	return funcs
}

// mergeFunc wraps merge so a result that includes a resource instance is still
// recognized as one: merge builds a new object, so identity alone would not.
func (e *Evaluator) mergeFunc(base function.Function) function.Function {
	if base == (function.Function{}) {
		base = stdlib.MergeFunc
	}
	return function.New(&function.Spec{
		VarParam: &function.Parameter{
			Name:             "maps",
			Type:             cty.DynamicPseudoType,
			AllowDynamicType: true,
			AllowNull:        true,
			AllowUnknown:     true,
			AllowMarked:      true,
		},
		Type: base.ReturnTypeForValues,
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			v, err := base.Call(args)
			if err != nil {
				return cty.NilVal, err
			}
			for _, arg := range args {
				if e.registry.isResourceInstance(arg) {
					return markResourceInstance(v), nil
				}
			}
			return v, nil
		},
	})
}

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
		return withoutResourceInstanceMarks(v), nil
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
