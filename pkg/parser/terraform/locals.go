/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localorder"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// localDeclarations collects the locals assignments of a directory in the
// order Terraform applies them: those of ordinary files, then those of
// override files, each in file order. An override replaces a local of the
// same name, local by local, whatever the names of the files sort to.
type localDeclarations struct {
	ordinary, overrides []localAssignment
}

func (d *localDeclarations) add(file string, assignments []localAssignment) {
	if tfpath.IsOverride(file) {
		d.overrides = append(d.overrides, assignments...)
		return
	}
	d.ordinary = append(d.ordinary, assignments...)
}

// all returns every assignment in the order Terraform applies them, so the
// last one of each name is its declaration.
func (d *localDeclarations) all() []localAssignment {
	return append(slices.Clip(d.ordinary), d.overrides...)
}

// localEvalContext is what the locals of a directory are evaluated with
// besides each other: the functions and path the converter gives the resource
// attributes of the directory, so a local reads a file, an absolute path or
// path.module exactly as a resource attribute does. terraform is left out on
// purpose: the converter assumes the "default" workspace for a direct
// terraform.workspace, and a local reading it would carry that guess into
// conditions such as terraform.workspace == "production", hiding the value
// the other workspaces get.
type localEvalContext struct {
	funcs map[string]function.Function
	path  cty.Value
}

func newLocalEvalContext(fsys vfs.FS, dir string) localEvalContext {
	return localEvalContext{
		funcs: functions.EvalFuncsWithRoot(dir, "", fsys),
		path:  functions.ContextVariables(dir, "")[pathReference],
	}
}

// scope returns the namespaces a local reads besides local: var and path.
func (c localEvalContext) scope(vars cty.Value) map[string]cty.Value {
	scope := map[string]cty.Value{varReference: vars}
	if c.path != cty.NilVal {
		scope[pathReference] = c.path
	}
	return scope
}

// resolveRootLocals evaluates the effective assignments of a directory's
// locals once each, in dependency order, against scope and the locals they
// read. Evaluation is conservative: a local is evaluated only when it reads
// nothing but scope and declared locals, calls only functions the scanner
// implements (see localInputsOf), and every value it reads is already wholly
// known (see readsOnlyKnownValues). Any other local stays unknown, and so
// does every local reading it, as do a local in a cycle and one that does not
// evaluate to a wholly known value: where the scanner has no value, it cannot
// tell whether Terraform would fail, or what type it would give.
//
// Only the resolved locals are returned. An unresolved local is unknown while
// the others are evaluated, but missing from the result, as it is without
// this evaluation: an unknown local in the converter context would let go-cty
// fold it into a known value in resource attributes, such as
// length([local.x.missing]) == 1. try and can in resource attributes still
// take their fallback for a missing local, as they did before.
func resolveRootLocals(
	assignments []localAssignment, scope map[string]cty.Value, funcs map[string]function.Function,
) converter.VariableMap {
	n := len(assignments)
	index := make(map[string]int, n)
	for i, item := range assignments {
		index[item.name] = i
	}
	inputs := make([]localInputs, n)
	reads := make([][]int, n)
	whole := make([]bool, n)
	for i, item := range assignments {
		inputs[i] = localInputsOf(item.expr, index, scope, funcs)
		reads[i], whole[i] = inputs[i].locals, inputs[i].whole
	}
	edges := localorder.Edges(reads, whole)
	values := make(converter.VariableMap, n)
	for _, component := range localorder.StronglyConnected(edges) {
		if component[0] == n {
			continue // the barrier ordering whole-local reads
		}
		cyclic := localorder.Cyclic(edges, component)
		for _, v := range component {
			item := assignments[v]
			if cyclic || !inputs[v].evaluable {
				values[item.name] = cty.DynamicVal
				continue
			}
			variables := make(map[string]cty.Value, len(scope)+1)
			for name, value := range scope {
				variables[name] = value
			}
			// A whole read sees the locals evaluated before this one only.
			variables[blockTypeLocalReference] = readableLocals(assignments, reads[v], whole[v], values)
			values[item.name] = cty.DynamicVal
			if !readsOnlyKnownValues(item.expr, variables) {
				continue
			}
			val, diags := item.expr.Value(&hcl.EvalContext{Variables: variables, Functions: funcs})
			if !diags.HasErrors() && val.IsWhollyKnown() {
				values[item.name] = val
			}
		}
	}
	return resolvedLocals(values)
}

// resolvedLocals keeps the wholly known values of locals.
func resolvedLocals(locals converter.VariableMap) converter.VariableMap {
	resolved := make(converter.VariableMap, len(locals))
	for name, value := range locals {
		if value.IsWhollyKnown() {
			resolved[name] = value
		}
	}
	return resolved
}

// declaredLocals is the local object locals are evaluated against: the
// resolved values of current, and unknown for each other name of declared, so
// a read of an unresolved local, or of local as a whole, is never evaluated.
func declaredLocals(current converter.VariableMap, declared []localAssignment) converter.VariableMap {
	locals := make(converter.VariableMap, len(declared)+len(current))
	for _, item := range declared {
		locals[item.name] = cty.DynamicVal
	}
	for name, value := range current {
		locals[name] = value
	}
	return locals
}

// localInputs is what a local expression reads.
type localInputs struct {
	// locals are the declared locals it reads by name, by index; whole is set
	// when it reads local as a whole.
	locals []int
	whole  bool
	// evaluable is set when it reads nothing but declared locals and the
	// namespaces of scope, and calls only functions the scanner implements
	// other than templatestring and templatefile. A whole read under try or
	// can is not evaluated, as it would keep a fallback for a local absent
	// from the object it reads.
	evaluable bool
}

func localInputsOf(
	expr hcl.Expression, index map[string]int, scope map[string]cty.Value, funcs map[string]function.Function,
) localInputs {
	var in localInputs
	in.evaluable = callsOnlyImplemented(expr, funcs)
	for _, traversal := range expr.Variables() {
		root := traversal.RootName()
		if _, ok := scope[root]; ok {
			continue
		}
		if root != blockTypeLocalReference {
			in.evaluable = false
			continue
		}
		name, ok := LocalTraversalName(traversal)
		if !ok {
			in.whole = true
			continue
		}
		j, declared := index[name]
		if !declared {
			in.evaluable = false
			continue
		}
		in.locals = append(in.locals, j)
	}
	if in.whole && usesTryOrCan(expr) {
		in.evaluable = false
	}
	return in
}

// refreshableLocals keeps the assignments refreshLocals can evaluate against
// scope and the declared locals of current, under the rules of localInputsOf.
func refreshableLocals(
	assignments []localAssignment, current converter.VariableMap, scope map[string]cty.Value, funcs map[string]function.Function,
) []localAssignment {
	index := make(map[string]int, len(current))
	for name := range current {
		index[name] = len(index)
	}
	kept := make([]localAssignment, 0, len(assignments))
	for _, item := range assignments {
		if localInputsOf(item.expr, index, scope, funcs).evaluable {
			kept = append(kept, item)
		}
	}
	return kept
}

// readsOnlyKnownValues reports whether every value expr reads from
// variables, the namespaces it is evaluated against, exists and is wholly
// known: the variable, path attribute or local each traversal names, the
// rendered data document (data.<type>.<name>), or the whole namespace for a
// traversal that names none statically. An unknown read is never evaluated,
// even where it would not decide the result: go-cty skips a function called
// with an unknown argument and folds unknown values into known results, such
// as length([unknown]), hiding a failure or a type Terraform would give.
func readsOnlyKnownValues(expr hcl.Expression, variables map[string]cty.Value) bool {
	for _, traversal := range expr.Variables() {
		root, ok := variables[traversal.RootName()]
		if !ok {
			return false
		}
		depth := 1
		if traversal.RootName() == terraformDataIdentifier {
			depth = 2
		}
		if !readValueKnown(traversal, root, depth) {
			return false
		}
	}
	return true
}

// readValueKnown reports whether the value traversal reads from root, down
// to depth static steps, exists and is wholly known. A step that is not
// static reads the whole value at its level.
func readValueKnown(traversal hcl.Traversal, root cty.Value, depth int) bool {
	v := root
	for i := 1; i <= depth && i < len(traversal); i++ {
		name, ok := staticStepName(traversal[i])
		if !ok {
			break
		}
		if !v.IsKnown() || v.IsNull() {
			return false
		}
		key := cty.StringVal(name)
		switch ty := v.Type(); {
		case ty.IsObjectType():
			if !ty.HasAttribute(name) {
				return false
			}
			v = v.GetAttr(name)
		case ty.IsMapType():
			if !v.HasIndex(key).True() {
				return false
			}
			v = v.Index(key)
		default:
			return false
		}
	}
	return v.IsWhollyKnown()
}

// readableLocals is the local object a local is evaluated against: the locals
// it reads, or every local evaluated so far for a read of local as a whole.
func readableLocals(assignments []localAssignment, reads []int, whole bool, values converter.VariableMap) cty.Value {
	if whole {
		return cty.ObjectVal(values)
	}
	attrs := make(map[string]cty.Value, len(reads))
	for _, w := range reads {
		name := assignments[w].name
		attrs[name] = values[name]
	}
	return cty.ObjectVal(attrs)
}

// unsupportedLocalFunctions are implemented functions a local is not
// evaluated with: templatestring and templatefile render a template that may
// call any function, and the scanner's rendering differs from Terraform's
// (the result type, which template arguments are accepted).
var unsupportedLocalFunctions = map[string]bool{"templatestring": true, "templatefile": true}

// callsOnlyImplemented reports whether every function expr calls is in funcs
// and is not in unsupportedLocalFunctions. A function the scanner does not
// implement fails evaluation where Terraform may not, or returns where
// Terraform may fail, so no value of an expression calling one can be
// trusted.
func callsOnlyImplemented(expr hcl.Expression, funcs map[string]function.Function) bool {
	names, ok := calledFunctions(expr)
	if !ok {
		return false
	}
	for _, name := range names {
		if _, implemented := funcs[name]; !implemented || unsupportedLocalFunctions[name] {
			return false
		}
	}
	return true
}

// usesTryOrCan reports whether expr calls try or can, which turn a missing
// local into a value instead of an error. An expression whose function calls
// cannot be listed is treated as if it did.
func usesTryOrCan(expr hcl.Expression) bool {
	names, ok := calledFunctions(expr)
	return !ok || slices.Contains(names, "try") || slices.Contains(names, "can")
}

// calledFunctions lists the functions expr calls, including those of the
// templates JSON configuration writes as strings. It returns false when they
// cannot be listed.
func calledFunctions(expr hcl.Expression) ([]string, bool) {
	if syntax, native := expr.(hclsyntax.Expression); native {
		return nativeCalledFunctions(syntax), true
	}
	return jsonCalledFunctions(expr)
}

func nativeCalledFunctions(expr hclsyntax.Expression) []string {
	var names []string
	_ = hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
		if call, ok := node.(*hclsyntax.FunctionCallExpr); ok {
			names = append(names, call.Name)
		}
		return nil
	})
	return names
}

// jsonCalledFunctions is calledFunctions for a JSON expression: an array or
// object lists those of its elements, and a string, read verbatim without an
// evaluation context, those of the template it holds.
func jsonCalledFunctions(expr hcl.Expression) ([]string, bool) {
	var parts []hcl.Expression
	if items, diags := hcl.ExprList(expr); !diags.HasErrors() {
		parts = items
	} else if pairs, diags := hcl.ExprMap(expr); !diags.HasErrors() {
		for _, pair := range pairs {
			parts = append(parts, pair.Key, pair.Value)
		}
	} else {
		v, diags := expr.Value(nil)
		if diags.HasErrors() {
			return nil, false
		}
		if v.Type() != cty.String || !ctyutil.Materialized(v) {
			return nil, true
		}
		rng := expr.Range()
		template, diags := hclsyntax.ParseTemplate([]byte(v.AsString()), rng.Filename, rng.Start)
		if diags.HasErrors() {
			return nil, false
		}
		return calledFunctions(template)
	}
	var names []string
	for _, part := range parts {
		partNames, ok := calledFunctions(part)
		if !ok {
			return nil, false
		}
		names = append(names, partNames...)
	}
	return names, true
}
