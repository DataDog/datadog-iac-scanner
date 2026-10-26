/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"errors"
	"fmt"
	"hash/maphash"
	"maps"
	"sort"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

const templateMaxDepth = 8

func makeTemplateStringFunc(funcsCb func() map[string]function.Function) function.Function {
	return makeTemplateStringFuncDepth(funcsCb, 0)
}

func makeTemplateStringFuncDepth(funcsCb func() map[string]function.Function, depth int) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "str", Type: cty.String},
			{Name: "vars", Type: cty.DynamicPseudoType},
		},
		// Render only in Impl: go-cty always calls Type before Impl, so
		// rendering here as well would parse and evaluate every template twice.
		Type: func([]cty.Value) (cty.Type, error) {
			return cty.DynamicPseudoType, nil
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return renderTemplateString(args[0].AsString(), args[1], funcsCb, depth)
		},
	})
}

func makeTemplateFileFunc(baseDir, rootDir string, fsys vfs.FS, funcsCb func() map[string]function.Function) function.Function {
	return makeTemplateFileFuncDepth(baseDir, rootDir, fsys, funcsCb, 0)
}

func makeTemplateFileFuncDepth(
	baseDir, rootDir string,
	fsys vfs.FS,
	funcsCb func() map[string]function.Function,
	depth int,
) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "path", Type: cty.String},
			{Name: "vars", Type: cty.DynamicPseudoType},
		},
		// Render only in Impl: go-cty always calls Type before Impl, so
		// rendering here as well would read and parse every template twice.
		Type: func([]cty.Value) (cty.Type, error) {
			return cty.DynamicPseudoType, nil
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return renderTemplateFile(baseDir, rootDir, fsys, args[0].AsString(), args[1], funcsCb, depth)
		},
	})
}

func renderTemplateFile(
	baseDir, rootDir string,
	fsys vfs.FS,
	rel string,
	vars cty.Value,
	funcsCb func() map[string]function.Function,
	depth int,
) (cty.Value, error) {
	full, err := confinePath(baseDir, rootDir, fsys, rel)
	if err != nil {
		return cty.NilVal, err
	}
	got := readFileResult(fsys, "templatefile", full, parseTemplateFile)
	var diags hcl.Diagnostics
	switch {
	case errors.Is(got.err, errInvalidUTF8):
		return cty.NilVal, fmt.Errorf("contents of %s are not valid UTF-8", rel)
	case errors.As(got.err, &diags):
		// A parse error is reported after the recursion limit.
	case got.err != nil:
		return cty.NilVal, got.err
	}
	if depth > templateMaxDepth {
		return cty.NilVal, errTemplateDepth
	}
	if diags != nil {
		return cty.NilVal, got.err
	}
	if got.template == nil {
		if err := checkTemplateVars(vars); err != nil {
			return cty.NilVal, err
		}
		return got.value, nil
	}
	render := func() (cty.Value, error) {
		return evalTemplate(got.template.expr, vars, nestTemplateStringFuncs(func() map[string]function.Function {
			return nestTemplateFuncs(baseDir, rootDir, fsys, funcsCb, depth)
		}, depth))
	}
	if v, err, ok := cachedTemplateRender(fsys, full, got.template, vars, render); ok {
		return v, err
	}
	return render()
}

// cachedTemplateRender returns a remembered render of a pure template. ok is
// false when this call has to render, including after a first render under
// minMemoizedSize, whose key is dropped so it is not kept.
func cachedTemplateRender(
	fsys vfs.FS,
	full string,
	t *parsedTemplate,
	vars cty.Value,
	render func() (cty.Value, error),
) (cty.Value, error, bool) {
	s, ok := fsys.(*ScanFS)
	if !ok || !t.pure || t.smallOutput.Load() {
		return cty.NilVal, nil, false
	}
	key, ok := renderKeyOf(s.realPath(full), vars)
	if !ok {
		return cty.NilVal, nil, false
	}
	r := s.memo.renders.lookupOrCompute(key, func() valueResult {
		v, err := render()
		if out, ok := stringOutput(v, err); ok && len(out) < minMemoizedSize {
			t.smallOutput.Store(true)
		}
		return valueResult{value: v, err: err}
	})
	if t.smallOutput.Load() {
		s.memo.renders.mu.Lock()
		delete(s.memo.renders.seen, key)
		s.memo.renders.mu.Unlock()
	}
	return r.value, r.err, true
}

// renderKey names the text a template calling no function renders for one
// set of variables, by a digest of the variables and their type.
type renderKey struct {
	path string
	n    int
	a, b uint64
}

// maxRenderVars bounds the variables a render is remembered for. Keying walks
// them on every call, and a call passing a large value is rarely repeated
// with an equal one.
const maxRenderVars = 4 << 10

// renderKeyOf digests vars and their type, which decides how a template
// compares and converts them, or reports false once the walk passes
// maxRenderVars or meets a value it cannot digest.
func renderKeyOf(path string, vars cty.Value) (renderKey, bool) {
	d := varsDigest{left: maxRenderVars}
	d.a.SetSeed(decodeSeedA)
	d.b.SetSeed(decodeSeedB)
	if !d.typ(vars.Type()) || !d.value(vars) {
		return renderKey{}, false
	}
	return renderKey{path: path, n: maxRenderVars - d.left, a: d.a.Sum64(), b: d.b.Sum64()}, true
}

type varsDigest struct {
	a, b maphash.Hash
	left int
}

// varsNode is what the walk charges for each type or value node.
const varsNode = 8

func (d *varsDigest) spend(n int) bool {
	d.left -= n
	return d.left >= 0
}

func (d *varsDigest) write(s string) {
	_, _ = d.a.WriteString(s)
	_, _ = d.b.WriteString(s)
}

func (d *varsDigest) tag(c byte, n int) {
	var buf [24]byte
	b := strconv.AppendInt(append(buf[:0], c), int64(n), decimal)
	_, _ = d.a.Write(b)
	_, _ = d.b.Write(b)
}

const decimal = 10

func (d *varsDigest) typ(ty cty.Type) bool {
	if !d.spend(varsNode) {
		return false
	}
	if c, ok := primitiveTag(ty); ok {
		d.tag(c, 0)
		return true
	}
	switch {
	case ty.IsListType() || ty.IsSetType() || ty.IsMapType():
		d.tag(collectionTag(ty), 0)
		return d.typ(ty.ElementType())
	case ty.IsObjectType():
		return d.objectType(ty.AttributeTypes())
	case ty.IsTupleType():
		return d.tupleType(ty.TupleElementTypes())
	}
	return false
}

func primitiveTag(ty cty.Type) (byte, bool) {
	switch ty {
	case cty.String:
		return 's', true
	case cty.Number:
		return 'n', true
	case cty.Bool:
		return 'b', true
	case cty.DynamicPseudoType:
		return 'd', true
	}
	return 0, false
}

func collectionTag(ty cty.Type) byte {
	switch {
	case ty.IsListType():
		return 'L'
	case ty.IsSetType():
		return 'S'
	}
	return 'M'
}

func (d *varsDigest) objectType(attrs map[string]cty.Type) bool {
	if !d.spend(varsNode * len(attrs)) {
		return false
	}
	d.tag('O', len(attrs))
	for _, name := range sortedAttributes(attrs) {
		d.tag('a', len(name))
		if !d.spend(len(name)) {
			return false
		}
		d.write(name)
		if !d.typ(attrs[name]) {
			return false
		}
	}
	return true
}

func (d *varsDigest) tupleType(elems []cty.Type) bool {
	if !d.spend(varsNode * len(elems)) {
		return false
	}
	d.tag('T', len(elems))
	for _, e := range elems {
		if !d.typ(e) {
			return false
		}
	}
	return true
}

func (d *varsDigest) value(v cty.Value) bool {
	if !d.spend(varsNode) || v.IsMarked() || !v.IsKnown() {
		return false
	}
	if v.IsNull() {
		d.tag('z', 0)
		return true
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		return d.text('s', v.AsString())
	case ty == cty.Number:
		return d.text('n', v.AsBigFloat().Text('g', -1))
	case ty == cty.Bool:
		if v.True() {
			d.tag('t', 0)
		} else {
			d.tag('f', 0)
		}
		return true
	case ty.IsObjectType():
		for _, name := range sortedAttributes(ty.AttributeTypes()) {
			if !d.value(v.GetAttr(name)) {
				return false
			}
		}
		return true
	case ty.IsCollectionType() || ty.IsTupleType():
		return d.elements(v, ty.IsMapType())
	}
	return false
}

func (d *varsDigest) text(c byte, s string) bool {
	if !d.spend(len(s)) {
		return false
	}
	d.tag(c, len(s))
	d.write(s)
	return true
}

func (d *varsDigest) elements(v cty.Value, keyed bool) bool {
	n := v.LengthInt()
	if !d.spend(varsNode * n) {
		return false
	}
	d.tag('c', n)
	for it := v.ElementIterator(); it.Next(); {
		k, e := it.Element()
		if keyed && !d.value(k) {
			return false
		}
		if !d.value(e) {
			return false
		}
	}
	return true
}

func sortedAttributes(attrs map[string]cty.Type) []string {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func estimateRender(key renderKey, r valueResult) (int, bool) {
	s, ok := r.outputString()
	if !ok || len(s) < minMemoizedSize {
		return 0, false
	}
	return retainedEntry + len(key.path) + retainedString + len(s), true
}

func (r valueResult) outputString() (string, bool) {
	return stringOutput(r.value, r.err)
}

var errTemplateDepth = errors.New("template recursion limit reached")

func renderTemplateString(src string, vars cty.Value, funcsCb func() map[string]function.Function, depth int) (cty.Value, error) {
	if depth > templateMaxDepth {
		return cty.NilVal, errTemplateDepth
	}
	expr, diags := hclsyntax.ParseTemplate([]byte(src), "template", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return cty.NilVal, diags
	}
	return evalTemplate(expr, vars, nestTemplateStringFuncs(funcsCb, depth))
}

func nestTemplateFuncs(
	baseDir, rootDir string,
	fsys vfs.FS,
	funcsCb func() map[string]function.Function,
	depth int,
) map[string]function.Function {
	funcs := maps.Clone(funcsCb())
	funcs["templatefile"] = makeTemplateFileFuncDepth(baseDir, rootDir, fsys, funcsCb, depth+1)
	funcs["templatestring"] = makeTemplateStringFuncDepth(funcsCb, depth+1)
	return funcs
}

func nestTemplateStringFuncs(funcsCb func() map[string]function.Function, depth int) map[string]function.Function {
	funcs := maps.Clone(funcsCb())
	funcs["templatestring"] = makeTemplateStringFuncDepth(funcsCb, depth+1)
	return funcs
}

func evalTemplate(expr hcl.Expression, vars cty.Value, funcs map[string]function.Function) (cty.Value, error) {
	if err := checkTemplateVars(vars); err != nil {
		return cty.NilVal, err
	}
	val, diags := expr.Value(&hcl.EvalContext{
		Variables: vars.AsValueMap(),
		Functions: funcs,
	})
	if diags.HasErrors() {
		return cty.NilVal, diags
	}
	return val, nil
}

func checkTemplateVars(vars cty.Value) error {
	if ty := vars.Type(); !ty.IsObjectType() && !ty.IsMapType() {
		return fmt.Errorf("vars must be an object")
	}
	return nil
}
