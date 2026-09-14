/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

var jsonConfigSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: blockTypeLocals},
		{Type: "moved"},
		{Type: "import"},
		{Type: "removed"},
		{Type: blockTypeVariable, LabelNames: []string{"name"}},
		{Type: "output", LabelNames: []string{"name"}},
		{Type: "module", LabelNames: []string{"name"}},
		{Type: "provider", LabelNames: []string{"name"}},
		{Type: "check", LabelNames: []string{"name"}},
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "data", LabelNames: []string{"type", "name"}},
		{Type: "ephemeral", LabelNames: []string{"type", "name"}},
	},
}

func parseJSONConfig(src []byte, filename string, inputVars converter.VariableMap) (model.Document, error) {
	file, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}
	content, _, diags := file.Body.PartialContent(jsonConfigSchema)
	if diags.HasErrors() && content == nil {
		return nil, diags
	}

	evalCtx := &hcl.EvalContext{
		Variables: inputVars,
		Functions: functions.TerraformFuncs,
	}
	out := make(model.Document)
	ddLines := map[string]model.LineObject{
		"_dd__default": {Line: 1},
	}
	for _, block := range content.Blocks {
		body, skip := convertJSONBody(block.Body, evalCtx, src, block.DefRange.Start.Line)
		if skip {
			continue
		}
		ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
		nestJSONBlock(out, block, body)
	}
	out["_dd_lines"] = ddLines
	return out, nil
}

func convertJSONBody(body hcl.Body, evalCtx *hcl.EvalContext, src []byte, defLine int) (model.Document, bool) {
	attrs, _ := body.JustAttributes()
	if countZero(attrs, evalCtx) {
		return nil, true
	}

	out := make(model.Document)
	ddLines := map[string]model.LineObject{
		"_dd__default": {Line: defLine},
	}
	for name, attr := range attrs {
		ddLines["_dd_"+name] = model.LineObject{Line: attr.NameRange.Start.Line}
		out[name] = convertJSONExpr(attr.Expr, evalCtx, src, name)
	}
	out["_dd_lines"] = ddLines
	return out, false
}

func nestJSONBlock(out model.Document, block *hcl.Block, body model.Document) {
	cur := out
	key := block.Type
	for _, label := range block.Labels {
		if inner, exists := cur[key]; exists {
			next, ok := inner.(model.Document)
			if !ok {
				return
			}
			cur = next
		} else {
			next := make(model.Document)
			cur[key] = next
			cur = next
		}
		key = label
	}
	if current, exists := cur[key]; exists {
		if list, ok := current.([]interface{}); ok {
			cur[key] = append(list, body)
		} else {
			cur[key] = []interface{}{current, body}
		}
		return
	}
	cur[key] = body
}

func countZero(attrs hcl.Attributes, evalCtx *hcl.EvalContext) bool {
	attr, ok := attrs["count"]
	if !ok {
		return false
	}
	val, diags := attr.Expr.Value(evalCtx)
	if diags.HasErrors() || !val.IsKnown() || val.IsNull() {
		return false
	}
	switch val.Type() {
	case cty.Number:
		f, _ := val.AsBigFloat().Float64()
		return f == 0
	case cty.String:
		n, err := strconv.Atoi(val.AsString())
		return err == nil && n == 0
	default:
		return false
	}
}

func ctyToJSONDocument(v cty.Value) interface{} {
	if v.IsNull() {
		return nil
	}
	t := v.Type()
	switch {
	case t.IsPrimitiveType():
		return ctyjson.SimpleJSONValue{Value: v}
	case t.IsObjectType() || t.IsMapType():
		m := make(model.Document, v.LengthInt())
		for k, ev := range v.AsValueMap() {
			m[k] = ctyToJSONDocument(ev)
		}
		return m
	case t.IsListType() || t.IsTupleType() || t.IsSetType():
		list := make([]interface{}, 0, v.LengthInt())
		for _, ev := range v.AsValueSlice() {
			list = append(list, ctyToJSONDocument(ev))
		}
		return list
	default:
		return ctyjson.SimpleJSONValue{Value: v}
	}
}

func convertJSONExpr(expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte, fallback string) interface{} {
	val, diags := expr.Value(evalCtx)
	if !diags.HasErrors() && val.IsWhollyKnown() {
		return ctyToJSONDocument(val)
	}
	if obj, ok := convertJSONObjectExpr(expr, evalCtx, src); ok {
		return obj
	}
	if list, ok := convertJSONListExpr(expr, evalCtx, src, fallback); ok {
		return list
	}
	return wrapJSONRange(expr.Range(), fallback, src)
}

func convertJSONObjectExpr(expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte) (model.Document, bool) {
	pairs, diags := hcl.ExprMap(expr)
	if diags.HasErrors() || len(pairs) == 0 {
		return nil, false
	}
	out := make(model.Document, len(pairs))
	for _, pair := range pairs {
		keyVal, keyDiags := pair.Key.Value(evalCtx)
		if keyDiags.HasErrors() || !keyVal.IsKnown() || keyVal.Type() != cty.String {
			continue
		}
		key := keyVal.AsString()
		out[key] = convertJSONExpr(pair.Value, evalCtx, src, key)
	}
	return out, true
}

func convertJSONListExpr(
	expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte, fallback string,
) ([]interface{}, bool) {
	items, diags := hcl.ExprList(expr)
	if diags.HasErrors() || len(items) == 0 {
		return nil, false
	}
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		out = append(out, convertJSONExpr(item, evalCtx, src, fallback))
	}
	return out, true
}

func wrapJSONRange(r hcl.Range, fallback string, src []byte) string {
	if r.Start.Byte < 0 || r.End.Byte > len(src) || r.Start.Byte >= r.End.Byte {
		return "${" + fallback + "}"
	}
	raw := strings.TrimSpace(string(src[r.Start.Byte:r.End.Byte]))
	if unquoted, err := strconv.Unquote(raw); err == nil {
		if strings.Contains(unquoted, "${") {
			return unquoted
		}
		return "${" + unquoted + "}"
	}
	return "${" + raw + "}"
}
