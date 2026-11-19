/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"fmt"
	"maps"
	"sync"
	"unicode/utf8"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

const templateMaxDepth = 8

func makeTemplateStringFunc(funcsCb func() map[string]function.Function, memo *templateMemo) function.Function {
	return makeTemplateStringFuncDepth(funcsCb, 0, memo)
}

func makeTemplateStringFuncDepth(
	funcsCb func() map[string]function.Function,
	depth int,
	memo *templateMemo,
) function.Function {
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
			return renderTemplateString(args[0].AsString(), args[1], funcsCb, depth, memo)
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
	src, err := readConfinedFile(baseDir, rootDir, fsys, rel)
	if isNotExist(err) {
		return cty.DynamicVal, nil
	}
	if err != nil {
		return cty.NilVal, err
	}
	if !utf8.Valid(src) {
		return cty.NilVal, fmt.Errorf("contents of %s are not valid UTF-8", rel)
	}
	return renderTemplateString(string(src), vars, func() map[string]function.Function {
		return nestTemplateFuncs(baseDir, rootDir, fsys, funcsCb, depth)
	}, depth, templatesOf(fsys))
}

const (
	// templateMemoBudget bounds the bytes the parsed templates of one scan may
	// hold, estimated from the size of their sources. Past it, templates are
	// parsed and not remembered.
	templateMemoBudget = 16 << 20 // 16 MiB
	// templateBytesPerSourceByte estimates how much a parsed template holds
	// per byte of its source.
	templateBytesPerSourceByte = 8
)

// templateMemo remembers parsed templatefile and templatestring sources for
// the life of one scan: a block expanded for many instances renders the same
// template once per instance. Parsed expressions are only evaluated, never
// mutated, so concurrent evaluations share them.
type templateMemo struct {
	mu    sync.Mutex
	exprs map[decodeKey]hclsyntax.Expression
	bytes int
}

func templatesOf(fsys vfs.FS) *templateMemo {
	if s, ok := fsys.(*ScanFS); ok {
		return &s.templates
	}
	return nil
}

// parse returns the parsed template for src. A nil memo parses every call.
func (m *templateMemo) parse(src string) (hclsyntax.Expression, error) {
	if m == nil {
		return parseTemplate(src)
	}
	key := decodeKeyOf("template", src)
	m.mu.Lock()
	expr, ok := m.exprs[key]
	m.mu.Unlock()
	if ok {
		return expr, nil
	}
	expr, err := parseTemplate(src)
	if err != nil {
		return nil, err
	}
	cost := len(src) * templateBytesPerSourceByte
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.exprs[key]; !ok && m.bytes+cost <= templateMemoBudget {
		if m.exprs == nil {
			m.exprs = make(map[decodeKey]hclsyntax.Expression)
		}
		m.exprs[key] = expr
		m.bytes += cost
	}
	return expr, nil
}

func parseTemplate(src string) (hclsyntax.Expression, error) {
	expr, diags := hclsyntax.ParseTemplate([]byte(src), "template", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diags
	}
	return expr, nil
}

func renderTemplateString(
	src string,
	vars cty.Value,
	funcsCb func() map[string]function.Function,
	depth int,
	memo *templateMemo,
) (cty.Value, error) {
	if depth > templateMaxDepth {
		return cty.NilVal, fmt.Errorf("template recursion limit reached")
	}
	expr, err := memo.parse(src)
	if err != nil {
		return cty.NilVal, err
	}
	return evalTemplate(expr, vars, nestTemplateStringFuncs(funcsCb, depth, memo))
}

func nestTemplateFuncs(
	baseDir, rootDir string,
	fsys vfs.FS,
	funcsCb func() map[string]function.Function,
	depth int,
) map[string]function.Function {
	funcs := maps.Clone(funcsCb())
	funcs["templatefile"] = makeTemplateFileFuncDepth(baseDir, rootDir, fsys, funcsCb, depth+1)
	funcs["templatestring"] = makeTemplateStringFuncDepth(funcsCb, depth+1, templatesOf(fsys))
	return funcs
}

func nestTemplateStringFuncs(
	funcsCb func() map[string]function.Function,
	depth int,
	memo *templateMemo,
) map[string]function.Function {
	funcs := maps.Clone(funcsCb())
	funcs["templatestring"] = makeTemplateStringFuncDepth(funcsCb, depth+1, memo)
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
