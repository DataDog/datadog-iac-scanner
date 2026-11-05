/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/blockmeta"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/metaargs"
	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

var jsonConfigSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "locals"},
		{Type: "moved"},
		{Type: "import"},
		{Type: "removed"},
		{Type: "variable", LabelNames: []string{"name"}},
		{Type: "output", LabelNames: []string{"name"}},
		{Type: moduleBlock, LabelNames: []string{"name"}},
		{Type: providerBlock, LabelNames: []string{"name"}},
		{Type: "check", LabelNames: []string{"name"}},
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "data", LabelNames: []string{"type", "name"}},
		{Type: "ephemeral", LabelNames: []string{"type", "name"}},
	},
}

// parseJSONConfig converts a .tf.json file. Without a provider schema, JSON
// cannot tell a nested block from an object attribute, so nested blocks keep
// the shape written: an object stays an object rather than a one-element list.
func parseJSONConfig(src []byte, filename string) (model.Document, error) {
	file, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}
	content, _, diags := file.Body.PartialContent(jsonConfigSchema)
	if diags.HasErrors() && content == nil {
		return nil, diags
	}

	evalCtx := &hcl.EvalContext{Functions: functions.TerraformFuncs}
	out := make(model.Document)
	ddLines := map[string]model.LineObject{
		"_dd__default": {Line: 1},
	}
	for _, block := range content.Blocks {
		body, ok := convertJSONBlock(block, evalCtx, src)
		if !ok {
			continue
		}
		ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
		nestJSONBlock(out, block, body)
	}
	out["_dd_lines"] = ddLines
	return out, nil
}

// convertJSONBlock converts a top-level block with its _dd_meta, reporting
// false for one whose count or for_each creates no instance.
func convertJSONBlock(block *hcl.Block, evalCtx *hcl.EvalContext, src []byte) (model.Document, bool) {
	resource := metaSections[block.Type] && len(block.Labels) == 2
	called := (block.Type == moduleBlock || block.Type == outputBlock) && len(block.Labels) == 1
	configures := block.Type == providerBlock && len(block.Labels) == 1
	rules := jsonRules(block.Type, resource)
	attrs, _ := block.Body.JustAttributes()
	if (resource || (called && block.Type == moduleBlock)) && jsonExpandsToNothing(attrs, evalCtx) {
		return nil, false
	}
	body, unknown := convertJSONBody(attrs, evalCtx, src, block.DefRange.Start.Line, rules)
	if !resource && !called && !configures {
		return body, true
	}
	var provider string
	var configured map[string]interface{}
	if resource {
		var providerExpr hcl.Expression
		if attr, ok := attrs["provider"]; ok {
			providerExpr = attr.Expr
		}
		provider = blockmeta.Provider(providerExpr, block.Labels[0])
		configured = jsonConfigured(body)
	}
	if meta := blockmeta.Meta(provider, configured, unknown); meta != nil {
		body["_dd_meta"] = meta
	}
	return body, true
}

const (
	moduleBlock   = "module"
	outputBlock   = "output"
	providerBlock = "provider"
)

// jsonRules is what the document of a block of type typ leaves out, as for
// HCL blocks.
func jsonRules(typ string, resource bool) jsonBodyRules {
	switch {
	case resource:
		return jsonBodyRules{hide: metaargs.Hidden, dropNulls: true}
	case typ == moduleBlock:
		return jsonBodyRules{hide: metaargs.IsModule}
	case typ == outputBlock:
		return jsonBodyRules{hide: metaargs.IsOutput}
	case typ == providerBlock:
		return jsonBodyRules{dropNulls: true}
	}
	return jsonBodyRules{}
}

// metaSections are the top-level sections whose blocks carry _dd_meta.
var metaSections = map[string]bool{"resource": true, "data": true, "ephemeral": true}

// jsonBodyRules says what a block's document leaves out: hide names its
// meta-arguments, and dropNulls drops attributes set to null.
type jsonBodyRules struct {
	hide      func(name string) bool
	dropNulls bool
}

// jsonExpandsToNothing reports whether a block's count or for_each is known
// to create no instance.
func jsonExpandsToNothing(attrs hcl.Attributes, evalCtx *hcl.EvalContext) bool {
	if attr, ok := attrs["count"]; ok {
		v, diags := attr.Expr.Value(evalCtx)
		return !diags.HasErrors() && v.IsKnown() && !v.IsNull() && v.Type() == cty.Number && v.Equals(cty.Zero).True()
	}
	if attr, ok := attrs["for_each"]; ok {
		v, diags := attr.Expr.Value(evalCtx)
		return !diags.HasErrors() && v.IsKnown() && !v.IsNull() && v.CanIterateElements() &&
			v.Length().IsKnown() && v.LengthInt() == 0
	}
	return false
}

// jsonConfigured is the _dd_meta.configured of a converted body: every
// attribute it holds, nested blocks included, since JSON writes them as
// attributes.
func jsonConfigured(body model.Document) map[string]interface{} {
	out := map[string]interface{}{}
	for k := range body {
		if !strings.HasPrefix(k, "_dd_") {
			out[k] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// convertJSONBody converts a block's attributes and returns, beside them, the
// unknown shape of their values (see convertJSONExpr). An unknown count or
// for_each is count: true in the shape.
func convertJSONBody(
	attrs hcl.Attributes, evalCtx *hcl.EvalContext, src []byte, defLine int, rules jsonBodyRules,
) (out model.Document, unknown map[string]interface{}) {
	out = make(model.Document)
	unknown = make(map[string]interface{})
	ddLines := map[string]model.LineObject{
		"_dd__default": {Line: defLine},
	}
	for name, attr := range attrs {
		ddLines["_dd_"+name] = model.LineObject{Line: attr.NameRange.Start.Line}
		value, u := convertJSONExpr(attr.Expr, evalCtx, src, name)
		if rules.hide != nil && rules.hide(name) {
			if u != nil && (name == "count" || name == "for_each") {
				unknown["count"] = true
			}
			continue
		}
		if rules.dropNulls && value == nil {
			continue
		}
		out[name] = value
		if u != nil {
			unknown[name] = u
		}
	}
	out["_dd_lines"] = ddLines
	return out, unknown
}

// listLabeled are the labeled blocks whose label may repeat, so their bodies
// are a list even when written once.
var listLabeled = map[string]bool{"provider": true}

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
	if listLabeled[block.Type] {
		cur[key] = []interface{}{body}
		return
	}
	cur[key] = body
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

// convertJSONExpr converts expr and returns, beside it, its unknown shape: nil
// when it evaluates, an object of its unknown entries, a list keeping its
// length with {} or false for a known element, and true otherwise.
func convertJSONExpr(
	expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte, fallback string,
) (value, unknown interface{}) {
	val, diags := expr.Value(evalCtx)
	if !diags.HasErrors() && val.IsWhollyKnown() {
		return ctyToJSONDocument(val), nil
	}
	if obj, u, ok := convertJSONObjectExpr(expr, evalCtx, src); ok {
		return obj, u
	}
	if list, u, ok := convertJSONListExpr(expr, evalCtx, src, fallback); ok {
		return list, u
	}
	return wrapJSONRange(expr.Range(), fallback, src), true
}

func convertJSONObjectExpr(
	expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte,
) (model.Document, interface{}, bool) {
	pairs, diags := hcl.ExprMap(expr)
	if diags.HasErrors() || len(pairs) == 0 {
		return nil, nil, false
	}
	out := make(model.Document, len(pairs))
	unknown := make(map[string]interface{})
	for _, pair := range pairs {
		keyVal, keyDiags := pair.Key.Value(evalCtx)
		key, ok := ctyutil.ConcreteString(keyVal)
		if keyDiags.HasErrors() || !ok {
			continue
		}
		var u interface{}
		out[key], u = convertJSONExpr(pair.Value, evalCtx, src, key)
		if u != nil {
			unknown[key] = u
		}
	}
	if len(unknown) == 0 {
		return out, nil, true
	}
	return out, unknown, true
}

func convertJSONListExpr(
	expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte, fallback string,
) (list []interface{}, unknown interface{}, ok bool) {
	items, diags := hcl.ExprList(expr)
	if diags.HasErrors() || len(items) == 0 {
		return nil, nil, false
	}
	out := make([]interface{}, 0, len(items))
	shape := make([]interface{}, len(items))
	found := false
	for i, item := range items {
		value, u := convertJSONExpr(item, evalCtx, src, fallback)
		out = append(out, value)
		switch {
		case u != nil:
			shape[i], found = u, true
		case isDocument(value):
			shape[i] = map[string]interface{}{}
		default:
			shape[i] = false
		}
	}
	if !found {
		return out, nil, true
	}
	return out, shape, true
}

func isDocument(v interface{}) bool {
	_, ok := v.(model.Document)
	return ok
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
