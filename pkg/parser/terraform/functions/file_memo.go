/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"encoding/base64"
	"errors"
	"sync/atomic"
	"unicode/utf8"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// fileKey names what a file function made of the file at a confined path.
type fileKey struct {
	fn   string
	path string
}

type fileResult struct {
	value cty.Value
	// template is the parsed template of a templatefile call, unless it has
	// nothing to evaluate and value is its text.
	template *parsedTemplate
	err      error
	// size is the length of the file read.
	size int
}

// errInvalidUTF8 stands for content file and templatefile reject; the caller
// names the path as it was written in the call.
var errInvalidUTF8 = errors.New("invalid UTF-8")

// readFileResult returns what derive makes of the file at full, a path
// confinePath accepted. Through a ScanFS, calls reading the same file share
// one read and one result for the rest of the scan.
func readFileResult(fsys vfs.FS, fn, full string, derive func([]byte) fileResult) fileResult {
	read := func() fileResult {
		src, err := fsys.ReadFile(full)
		if err != nil {
			return fileResult{err: err}
		}
		r := derive(src)
		r.size = len(src)
		return r
	}
	s, ok := fsys.(*ScanFS)
	if !ok {
		return read()
	}
	return s.memo.files.lookupOrCompute(fileKey{fn: fn, path: s.realPath(full)}, read)
}

func estimateFile(key fileKey, r fileResult) (int, bool) {
	n := retainedEntry + len(key.path)
	switch {
	case r.err != nil:
		return n + estimateError(r.err), true
	case r.size < minMemoizedSize:
		return 0, false
	case r.template != nil:
		return n + estimateTemplate(r.template.expr), true
	}
	return n + estimateValue(r.value), true
}

// outputString is the string every call returning r passes on.
func (r fileResult) outputString() (string, bool) {
	if r.template != nil {
		return "", false
	}
	return stringOutput(r.value, r.err)
}

func stringOutput(v cty.Value, err error) (string, bool) {
	if err != nil || v == cty.NilVal || !v.Type().Equals(cty.String) || !v.IsKnown() || v.IsNull() {
		return "", false
	}
	return v.AsString(), true
}

func fileText(src []byte) fileResult {
	if !utf8.Valid(src) {
		return fileResult{err: errInvalidUTF8}
	}
	return fileResult{value: cty.StringVal(string(src))}
}

func fileBase64(src []byte) fileResult {
	return fileResult{value: cty.StringVal(base64.StdEncoding.EncodeToString(src))}
}

// parseTemplateFile parses a template once for every call rendering it. The
// parsed template is not changed by evaluation, so concurrent renders share it.
func parseTemplateFile(src []byte) fileResult {
	if !utf8.Valid(src) {
		return fileResult{err: errInvalidUTF8}
	}
	expr, diags := hclsyntax.ParseTemplate(src, "template", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fileResult{err: diags}
	}
	if text, ok := literalTemplate(expr); ok {
		return fileResult{value: text}
	}
	pure := true
	_ = hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
		if _, ok := node.(*hclsyntax.FunctionCallExpr); ok {
			pure = false
		}
		return nil
	})
	return fileResult{template: &parsedTemplate{expr: expr, pure: pure}}
}

type parsedTemplate struct {
	expr hclsyntax.Expression
	// pure is set for a template calling no function, which renders the same
	// text for the same variables.
	pure bool
	// smallOutput is set once a render came out too short to remember.
	smallOutput atomic.Bool
}

// literalTemplate returns the text of a template that renders its single
// string part as is, whatever the variables.
func literalTemplate(expr hclsyntax.Expression) (cty.Value, bool) {
	t, ok := expr.(*hclsyntax.TemplateExpr)
	if !ok || len(t.Parts) != 1 {
		return cty.NilVal, false
	}
	lit, ok := t.Parts[0].(*hclsyntax.LiteralValueExpr)
	if !ok || !lit.Val.Type().Equals(cty.String) || !lit.Val.IsKnown() || lit.Val.IsNull() {
		return cty.NilVal, false
	}
	return lit.Val, true
}

func estimateTemplate(expr hclsyntax.Expression) int {
	n := 0
	_ = hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
		n += retainedNode
		if lit, ok := node.(*hclsyntax.LiteralValueExpr); ok {
			n += estimateValue(lit.Val)
		}
		return nil
	})
	return n
}
