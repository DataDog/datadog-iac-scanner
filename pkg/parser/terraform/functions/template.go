/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"fmt"
	"maps"
	"unicode/utf8"

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
		Type: func(args []cty.Value) (cty.Type, error) {
			if len(args) < 2 || !args[0].IsWhollyKnown() || !args[1].IsWhollyKnown() {
				return cty.DynamicPseudoType, nil
			}
			val, err := renderTemplateString(args[0].AsString(), args[1], funcsCb, depth)
			if err != nil {
				return cty.DynamicPseudoType, err
			}
			return val.Type(), nil
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return renderTemplateString(args[0].AsString(), args[1], funcsCb, depth)
		},
	})
}

func makeTemplateFileFunc(baseDir string, fsys vfs.FS, funcsCb func() map[string]function.Function) function.Function {
	return makeTemplateFileFuncDepth(baseDir, fsys, funcsCb, 0)
}

func makeTemplateFileFuncDepth(baseDir string, fsys vfs.FS, funcsCb func() map[string]function.Function, depth int) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "path", Type: cty.String},
			{Name: "vars", Type: cty.DynamicPseudoType},
		},
		Type: func(args []cty.Value) (cty.Type, error) {
			if len(args) < 2 || !args[0].IsWhollyKnown() || !args[1].IsWhollyKnown() {
				return cty.DynamicPseudoType, nil
			}
			val, err := renderTemplateFile(baseDir, fsys, args[0].AsString(), args[1], funcsCb, depth)
			if err != nil {
				return cty.DynamicPseudoType, err
			}
			return val.Type(), nil
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return renderTemplateFile(baseDir, fsys, args[0].AsString(), args[1], funcsCb, depth)
		},
	})
}

func renderTemplateFile(
	baseDir string,
	fsys vfs.FS,
	rel string,
	vars cty.Value,
	funcsCb func() map[string]function.Function,
	depth int,
) (cty.Value, error) {
	src, err := readConfinedFile(baseDir, fsys, rel)
	if err != nil {
		return cty.NilVal, err
	}
	if !utf8.Valid(src) {
		return cty.NilVal, fmt.Errorf("contents of %s are not valid UTF-8", rel)
	}
	return renderTemplateString(string(src), vars, func() map[string]function.Function {
		return nestTemplateFuncs(baseDir, fsys, funcsCb, depth)
	}, depth)
}

func renderTemplateString(src string, vars cty.Value, funcsCb func() map[string]function.Function, depth int) (cty.Value, error) {
	if depth > templateMaxDepth {
		return cty.NilVal, fmt.Errorf("template recursion limit reached")
	}
	expr, diags := hclsyntax.ParseTemplate([]byte(src), "template", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return cty.NilVal, diags
	}
	return evalTemplate(expr, vars, nestTemplateStringFuncs(funcsCb, depth))
}

func nestTemplateFuncs(baseDir string, fsys vfs.FS, funcsCb func() map[string]function.Function, depth int) map[string]function.Function {
	funcs := maps.Clone(funcsCb())
	funcs["templatefile"] = makeTemplateFileFuncDepth(baseDir, fsys, funcsCb, depth+1)
	funcs["templatestring"] = makeTemplateStringFuncDepth(funcsCb, depth+1)
	return funcs
}

func nestTemplateStringFuncs(funcsCb func() map[string]function.Function, depth int) map[string]function.Function {
	funcs := maps.Clone(funcsCb())
	funcs["templatestring"] = makeTemplateStringFuncDepth(funcsCb, depth+1)
	return funcs
}

func evalTemplate(expr hcl.Expression, vars cty.Value, funcs map[string]function.Function) (cty.Value, error) {
	ty := vars.Type()
	if !ty.IsObjectType() && !ty.IsMapType() {
		return cty.NilVal, fmt.Errorf("vars must be an object")
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
