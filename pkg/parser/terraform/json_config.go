/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
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

// parseJSONConfigLayers converts a JSON configuration into its documents the
// way converter.ConvertAll does for native syntax: resources and data whose
// count or for_each expand into instances that differ from one another have
// their first instance in the first document (see converter.BuildLayers for
// the others).
func parseJSONConfigLayers(src []byte, filename string, inputVars converter.VariableMap) ([]model.Document, error) {
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
	var expanded []converter.Expanded
	instancesLeft := instances.MaxPerFile
	for _, block := range content.Blocks {
		if values, ok := expandJSONInstances(block, evalCtx, src, &instancesLeft); ok {
			ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
			if len(values) == 0 {
				continue
			}
			nestJSONBlock(out, block, values[0])
			if len(values) > 1 {
				expanded = append(expanded, converter.Expanded{
					Path:   append([]string{block.Type}, block.Labels...),
					Values: values,
				})
			}
			continue
		}
		body, skip := convertJSONBody(block.Body, evalCtx, src, block.DefRange.Start.Line)
		if skip {
			continue
		}
		ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
		nestJSONBlock(out, block, body)
	}
	out["_dd_lines"] = ddLines
	return converter.BuildLayers(out, expanded), nil
}

// expandJSONInstances converts a resource or data block whose count or
// for_each yields instances that differ from one another, one result per
// distinct instance. ok is false for every other block, which is converted as
// written.
func expandJSONInstances(
	block *hcl.Block, evalCtx *hcl.EvalContext, src []byte, instancesLeft *int,
) (values []model.Document, ok bool) {
	if (block.Type != "resource" && block.Type != terraformDataIdentifier) || len(block.Labels) < 2 {
		return nil, false
	}
	attrs, _ := block.Body.JustAttributes()
	var count, forEach hcl.Expression
	if attr, has := attrs[instances.KindCount]; has {
		count = attr.Expr
	}
	if attr, has := attrs[instances.KindForEach]; has {
		forEach = attr.Expr
	}
	plan := instances.Resolve(count, forEach, evalCtx)
	if !plan.Expands() {
		return nil, false
	}
	if len(plan.Items) == 0 {
		return nil, true
	}
	exprs := make([]hcl.Expression, 0, len(attrs))
	for _, attr := range attrs {
		exprs = append(exprs, attr.Expr)
	}
	extra := len(plan.Items) - 1
	if plan.Truncated() {
		extra++
	}
	if !instances.ReadsInstanceExpr(exprs...) || extra > *instancesLeft {
		return nil, false
	}
	values = distinctJSONInstances(block, plan, evalCtx, src)
	*instancesLeft -= len(values) - 1
	return values, true
}

// distinctJSONInstances converts each instance of a plan, plus the block as
// written when the plan was cut short, and drops the ones equal to an earlier
// one.
func distinctJSONInstances(block *hcl.Block, plan instances.Plan, evalCtx *hcl.EvalContext, src []byte) []model.Document {
	var values []model.Document
	add := func(ctx *hcl.EvalContext) {
		value, skip := convertJSONBody(block.Body, ctx, src, block.DefRange.Start.Line)
		if skip {
			return
		}
		for _, seen := range values {
			if reflect.DeepEqual(seen, value) {
				return
			}
		}
		values = append(values, value)
	}
	for _, item := range plan.Items {
		name, iteration := plan.Variable(item)
		child := evalCtx.NewChild()
		child.Variables = map[string]cty.Value{name: iteration}
		add(child)
	}
	if plan.Truncated() {
		add(evalCtx)
	}
	return values
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
	if diags.HasErrors() {
		return false
	}
	n, ok := ctyutil.LiteralInt(val)
	return ok && n == 0
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
		key, ok := ctyutil.ConcreteString(keyVal)
		if keyDiags.HasErrors() || !ok {
			continue
		}
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
