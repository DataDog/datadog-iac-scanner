/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"encoding/json"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/refs"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	maxTraceDepth  = 32
	jsonEncodeFunc = "jsonencode"
)

// derive records, for the attributes of inst holding a string with an
// unknown part, the template parts, a jsonencode argument, and JSON parsed
// from a template or heredoc that still looks like JSON after unknowns are
// marked. It covers the block's own attributes and those of its static nested
// blocks.
func derive(inst *Instance, m *Module, body *hclsyntax.Body) {
	var ctx *hcl.EvalContext
	context := func() *hcl.EvalContext {
		if ctx == nil {
			ctx = m.Scope.EvalContext()
			if inst.Iteration != nil {
				ctx = ctx.NewChild()
				ctx.Variables = inst.Iteration
			}
		}
		return ctx
	}
	deriveBody(inst, m, inst.Attrs, body, "", context)
}

func deriveBody(inst *Instance, m *Module, vals map[string]cty.Value, body *hclsyntax.Body, prefix string, ctx func() *hcl.EvalContext) {
	for name, attr := range body.Attributes {
		v, ok := vals[name]
		if !ok || v.IsWhollyKnown() || (v.Type() != cty.String && v.Type() != cty.DynamicPseudoType) {
			continue
		}
		deriveAttr(inst, m, attr.Expr, joinPath(prefix, name), ctx)
	}
	deriveNested(inst, m, vals, body, prefix, ctx)
}

// nolint:gocyclo
func deriveAttr(inst *Instance, m *Module, expr hclsyntax.Expression, path string, ctx func() *hcl.EvalContext) {
	switch e := expr.(type) {
	case *hclsyntax.TemplateExpr:
		parts := make([]cty.Value, 0, len(e.Parts))
		jsonParts := make([]cty.Value, 0, len(e.Parts))
		var unknownTexts []string
		known, unknown := false, false
		rd := jsonRenderer(m, ctx())
		for _, part := range e.Parts {
			pv := evalExpr(part, ctx())
			if s, err := stringOf(pv); err == nil {
				parts = append(parts, cty.StringVal(s))
				jsonParts = append(jsonParts, cty.StringVal(s))
				known = true
				continue
			}
			parts = append(parts, cty.UnknownVal(cty.String))
			// JSONUnknownMarker is valid JSON source (\u0000…); a raw NUL is not.
			jsonParts = append(jsonParts, cty.StringVal(value.JSONUnknownMarker))
			unknownTexts = append(unknownTexts, expandLocalText(rd.StringPart(part), rd, m))
			unknown = true
		}
		if known {
			if inst.Templates == nil {
				inst.Templates = map[string][]cty.Value{}
			}
			inst.Templates[path] = parts
		}
		if known && unknown {
			if doc, ok := jsonFromTemplate(jsonParts); ok {
				if inst.JSON == nil {
					inst.JSON = map[string]cty.Value{}
				}
				inst.JSON[path] = doc
				if leafExprs := assignJSONUnknownExprs(doc, "", unknownTexts, new(int)); len(leafExprs) > 0 {
					if inst.JSONExpr == nil {
						inst.JSONExpr = map[string]map[string]string{}
					}
					inst.JSONExpr[path] = leafExprs
				}
			}
		}
	case *hclsyntax.FunctionCallExpr:
		if e.Name == jsonEncodeFunc && len(e.Args) == 1 {
			doc, exprs := jsonEncodeArg(e.Args[0], ctx(), m)
			if inst.JSON == nil {
				inst.JSON = map[string]cty.Value{}
			}
			inst.JSON[path] = doc
			if len(exprs) > 0 {
				if inst.JSONExpr == nil {
					inst.JSONExpr = map[string]map[string]string{}
				}
				inst.JSONExpr[path] = exprs
			}
		}
	}
}

// jsonEncodeArg keeps known document fields concrete and unknown leaves as
// unknown values. Expression provenance for those leaves is returned separately
// as "${expr}" text, with local aliases rewritten to their underlying
// expression so policy rules can still match caller_identity account ids.
func jsonEncodeArg(expr hcl.Expression, ctx *hcl.EvalContext, m *Module) (doc cty.Value, exprs map[string]string) {
	rd := jsonRenderer(m, ctx)
	exprs = map[string]string{}
	doc = jsonEncodeValue(expr, ctx, rd, m, "", exprs)
	if len(exprs) == 0 {
		return doc, nil
	}
	return doc, exprs
}

func jsonRenderer(m *Module, ctx *hcl.EvalContext) *partial.Renderer {
	rd := &partial.Renderer{Ctx: ctx}
	if m != nil && m.Scope != nil {
		rd.Source = partial.FileSources(m.Scope.Sources())
	}
	return rd
}

// nolint:gocyclo
func jsonEncodeValue(
	expr hcl.Expression, ctx *hcl.EvalContext, rd *partial.Renderer, m *Module, path string, exprs map[string]string,
) cty.Value {
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsExpr:
		out := make(map[string]cty.Value, len(e.Items))
		for _, item := range e.Items {
			key, ok := objectKey(item.KeyExpr, ctx)
			if !ok {
				return cty.DynamicVal
			}
			child := path
			if child != "" {
				child += "."
			}
			child += key
			out[key] = jsonEncodeValue(item.ValueExpr, ctx, rd, m, child, exprs)
		}
		return cty.ObjectVal(out)
	case *hclsyntax.TupleConsExpr:
		elems := make([]cty.Value, len(e.Exprs))
		for i, elem := range e.Exprs {
			child := strconv.Itoa(i)
			if path != "" {
				child = path + "." + strconv.Itoa(i)
			}
			elems[i] = jsonEncodeValue(elem, ctx, rd, m, child, exprs)
		}
		return cty.TupleVal(elems)
	case *hclsyntax.TemplateExpr:
		return jsonEncodeTemplate(e, ctx, rd, m, path, exprs)
	case *hclsyntax.TemplateWrapExpr:
		return jsonEncodeValue(e.Wrapped, ctx, rd, m, path, exprs)
	}
	v := evalExpr(expr, ctx)
	if v.IsKnown() && !v.IsNull() {
		ty := v.Type()
		if ty.IsPrimitiveType() {
			return v
		}
		if ty.IsObjectType() || ty.IsMapType() || ty.IsTupleType() || ty.IsListType() || ty.IsSetType() {
			// A resolved collection still needs unknown leaves marked; fall
			// through to the renderer only when the expression is not a
			// constructor we walk above.
			if rendered, ok := rd.Render(expr); ok {
				return markRenderedJSON(rendered, rd, m, path, exprs)
			}
		}
		if ty != cty.DynamicPseudoType {
			return v
		}
	}
	syn, ok := expr.(hclsyntax.Expression)
	if !ok {
		exprs[path] = partial.UnknownPlaceholder
		return cty.UnknownVal(cty.String)
	}
	text, ok := rd.Text(syn)
	if !ok {
		text = partial.UnknownPlaceholder
	}
	text = expandLocalText(text, rd, m)
	exprs[path] = text
	return cty.UnknownVal(cty.String)
}

func jsonEncodeTemplate(
	e *hclsyntax.TemplateExpr, ctx *hcl.EvalContext, rd *partial.Renderer, m *Module, path string, exprs map[string]string,
) cty.Value {
	var b strings.Builder
	known, unknown := false, false
	var provenance strings.Builder
	for _, part := range e.Parts {
		pv := evalExpr(part, ctx)
		if s, err := stringOf(pv); err == nil {
			b.WriteString(s)
			provenance.WriteString(s)
			known = true
			continue
		}
		unknown = true
		b.WriteString(value.UnknownMarker)
		text := rd.StringPart(part)
		text = expandLocalText(text, rd, m)
		provenance.WriteString(text)
	}
	if !unknown {
		return cty.StringVal(b.String())
	}
	exprs[path] = provenance.String()
	if !known {
		return cty.UnknownVal(cty.String)
	}
	// Keep UnknownMarker inside the string so projection substitutes the
	// placeholder while preserving known ARN prefix/suffix text.
	return cty.StringVal(b.String())
}

// nolint:gocyclo
func markRenderedJSON(v cty.Value, rd *partial.Renderer, m *Module, path string, exprs map[string]string) cty.Value {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return v
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		s := v.AsString()
		if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
			return v
		}
		exprs[path] = expandLocalText(s, rd, m)
		return cty.UnknownVal(cty.String)
	case ty.IsObjectType() || ty.IsMapType():
		out := make(map[string]cty.Value, v.LengthInt())
		for k, ev := range v.AsValueMap() {
			child := k
			if path != "" {
				child = path + "." + k
			}
			out[k] = markRenderedJSON(ev, rd, m, child, exprs)
		}
		if ty.IsMapType() {
			return cty.MapVal(out)
		}
		return cty.ObjectVal(out)
	case ty.IsTupleType() || ty.IsListType() || ty.IsSetType():
		elems := v.AsValueSlice()
		out := make([]cty.Value, len(elems))
		for i, ev := range elems {
			child := strconv.Itoa(i)
			if path != "" {
				child = path + "." + strconv.Itoa(i)
			}
			out[i] = markRenderedJSON(ev, rd, m, child, exprs)
		}
		if ty.IsListType() {
			return cty.ListVal(out)
		}
		if ty.IsSetType() {
			return cty.SetVal(out)
		}
		return cty.TupleVal(out)
	}
	return v
}

func objectKey(expr hcl.Expression, ctx *hcl.EvalContext) (string, bool) {
	if k, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		expr = k.Wrapped
	}
	if trav, diags := hcl.AbsTraversalForExpr(expr); !diags.HasErrors() && len(trav) == 1 {
		if root, ok := trav[0].(hcl.TraverseRoot); ok {
			return root.Name, true
		}
	}
	v, diags := expr.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

func expandLocalText(s string, rd *partial.Renderer, m *Module) string {
	if m == nil || m.Scope == nil || len(m.Scope.Locals) == 0 {
		return s
	}
	for name, expr := range m.Scope.Locals {
		text, ok := rd.Text(expr)
		if !ok || text == "" {
			continue
		}
		s = strings.ReplaceAll(s, "${local."+name+"}", text)
	}
	return s
}

// assignJSONUnknownExprs walks doc and assigns unknownTexts, in order, to each
// unknown leaf (or string holding UnknownMarker).
// nolint:gocyclo
func assignJSONUnknownExprs(doc cty.Value, path string, texts []string, at *int) map[string]string {
	out := map[string]string{}
	doc, _ = doc.UnmarkDeep()
	if !doc.IsKnown() {
		if *at < len(texts) {
			out[path] = texts[*at]
			*at++
		}
		return out
	}
	if doc.IsNull() {
		return out
	}
	ty := doc.Type()
	switch {
	case ty == cty.String:
		if value.HasUnknownMarker(doc.AsString()) && *at < len(texts) {
			out[path] = texts[*at]
			*at++
		}
	case ty.IsObjectType() || ty.IsMapType():
		for k, ev := range doc.AsValueMap() {
			child := k
			if path != "" {
				child = path + "." + k
			}
			for p, t := range assignJSONUnknownExprs(ev, child, texts, at) {
				out[p] = t
			}
		}
	case ty.IsTupleType() || ty.IsListType() || ty.IsSetType():
		for i, ev := range doc.AsValueSlice() {
			child := strconv.Itoa(i)
			if path != "" {
				child = path + "." + strconv.Itoa(i)
			}
			for p, t := range assignJSONUnknownExprs(ev, child, texts, at) {
				out[p] = t
			}
		}
	}
	return out
}

// jsonFromTemplate parses parts as JSON when they form an object or array,
// with each unknown part replaced by a mark that stays in its surrounding
// known text after decode.
func jsonFromTemplate(parts []cty.Value) (cty.Value, bool) {
	if doc, ok := parseTemplateJSON(parts, false); ok {
		return doc, true
	}
	return parseTemplateJSON(parts, true)
}

func parseTemplateJSON(parts []cty.Value, quoted bool) (cty.Value, bool) {
	var b strings.Builder
	for _, part := range parts {
		if s, err := stringOf(part); err == nil {
			b.WriteString(s)
			continue
		}
		if quoted {
			b.WriteByte('"')
			b.WriteString(value.JSONUnknownMarker)
			b.WriteByte('"')
			continue
		}
		b.WriteString(value.JSONUnknownMarker)
	}
	raw := strings.TrimSpace(b.String())
	if raw == "" || (raw[0] != '{' && raw[0] != '[') {
		return cty.NilVal, false
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return cty.NilVal, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return cty.NilVal, false
	}
	return ctyFromMarkedJSON(decoded), true
}

func ctyFromMarkedJSON(v any) cty.Value {
	switch x := v.(type) {
	case nil:
		return cty.NullVal(cty.DynamicPseudoType)
	case bool:
		return cty.BoolVal(x)
	case string:
		if x == value.UnknownMarker {
			return cty.UnknownVal(cty.String)
		}
		return cty.StringVal(x)
	case json.Number:
		f, _, err := big.ParseFloat(string(x), numberBase, numberPrecision, big.ToNearestEven)
		if err != nil {
			return cty.StringVal(string(x))
		}
		return cty.NumberVal(f)
	case []any:
		if len(x) == 0 {
			return cty.EmptyTupleVal
		}
		elems := make([]cty.Value, len(x))
		for i, e := range x {
			elems[i] = ctyFromMarkedJSON(e)
		}
		return cty.TupleVal(elems)
	case map[string]any:
		if len(x) == 0 {
			return cty.EmptyObjectVal
		}
		attrs := make(map[string]cty.Value, len(x))
		for k, e := range x {
			if value.HasUnknownMarker(k) {
				return cty.DynamicVal
			}
			attrs[k] = ctyFromMarkedJSON(e)
		}
		return cty.ObjectVal(attrs)
	}
	return cty.DynamicVal
}

func deriveNested(inst *Instance, m *Module, vals map[string]cty.Value, body *hclsyntax.Body, prefix string, ctx func() *hcl.EvalContext) {
	index := map[string]int{}
	for _, nb := range body.Blocks {
		typ := nestedType(nb)
		i := index[typ]
		index[typ]++
		if dynamicblock.Is(nb) || hasDynamic(body, typ) {
			continue
		}
		list, ok := vals[typ]
		if !ok || !list.IsKnown() || list.IsNull() || !list.Type().IsTupleType() || i >= list.LengthInt() {
			continue
		}
		elem := list.Index(cty.NumberIntVal(int64(i)))
		if !elem.IsKnown() || elem.IsNull() || !elem.Type().IsObjectType() {
			continue
		}
		deriveBody(inst, m, elem.AsValueMap(), nb.Body, joinPath(joinPath(prefix, typ), strconv.Itoa(i)), ctx)
	}
}

func hasDynamic(body *hclsyntax.Body, typ string) bool {
	for _, nb := range body.Blocks {
		if dynamicblock.Is(nb) && dynamicblock.GeneratedType(nb) == typ {
			return true
		}
	}
	return false
}

func stringOf(v cty.Value) (string, error) {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return "", errUnknown
	}
	switch v.Type() {
	case cty.String:
		return v.AsString(), nil
	case cty.Number:
		return v.AsBigFloat().Text('f', -1), nil
	case cty.Bool:
		return strconv.FormatBool(v.True()), nil
	}
	return "", errUnknown
}

type unknownError struct{}

func (unknownError) Error() string { return "unknown" }

var errUnknown error = unknownError{}

// nonliteralPaths lists the attribute paths of body (names only) whose
// expression reads path.* or terraform.*, directly or through locals and
// module arguments.
func nonliteralPaths(m *Module, body *hclsyntax.Body) []string {
	var out []string
	var walkBody func(body *hclsyntax.Body, prefix string)
	walkBody = func(body *hclsyntax.Body, prefix string) {
		for name, attr := range body.Attributes {
			if readsContext(m, attr.Expr, 0) {
				out = append(out, joinPath(prefix, name))
			}
		}
		for _, nb := range body.Blocks {
			if dynamicblock.Is(nb) {
				if content := dynamicblock.Content(nb); content != nil {
					walkBody(content, joinPath(prefix, dynamicblock.GeneratedType(nb)))
				}
				continue
			}
			walkBody(nb.Body, joinPath(prefix, nb.Type))
		}
	}
	walkBody(body, "")
	return out
}

func readsContext(m *Module, expr hcl.Expression, depth int) bool {
	return reads(m, expr, depth, false)
}

// readsRootInput reports whether expr reads a value a plan can set: a root
// variable or terraform.workspace, directly or through locals and module
// arguments.
func readsRootInput(m *Module, expr hcl.Expression, depth int) bool {
	if expr == nil {
		return false
	}
	return reads(m, expr, depth, true)
}

// reads reports whether expr reads terraform.*, path.* (unless rootInput) or
// a root variable (if rootInput), following locals in m and variables to the
// argument of the call that set them.
func reads(m *Module, expr hcl.Expression, depth int, rootInput bool) bool {
	if depth > maxTraceDepth {
		// Too deep to follow: assume the value reads an input, so it never counts as a literal.
		return true
	}
	if m == nil || m.Scope == nil {
		return false
	}
	for _, r := range refs.Of(expr) {
		switch r.Kind {
		case refs.KindTerraform:
			return true
		case refs.KindPath:
			if !rootInput {
				return true
			}
		case refs.KindLocal:
			if e, ok := m.Scope.Locals[r.Name]; ok && reads(m, e, depth+1, rootInput) {
				return true
			}
		case refs.KindVar:
			if readsVar(m, r.Name, depth, rootInput) {
				return true
			}
		}
	}
	return false
}

func readsVar(m *Module, name string, depth int, rootInput bool) bool {
	if m.Address == "" {
		return rootInput
	}
	parent := parentOf(m)
	if parent == nil || len(m.Chain) == 0 || m.Chain[len(m.Chain)-1].Body == nil {
		return false
	}
	a, ok := m.Chain[len(m.Chain)-1].Body.Attributes[name]
	return ok && reads(parent, a.Expr, depth+1, rootInput)
}

// parentOf returns the module instance that calls m, nil for the root module.
func parentOf(m *Module) *Module {
	return m.parent
}
