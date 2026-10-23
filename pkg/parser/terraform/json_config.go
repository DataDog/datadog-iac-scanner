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
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
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
	instancesLeft := converter.MaxExtraInstances
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
		body := convertJSONBody(block.Body, evalCtx, src, block.DefRange.Start.Line)
		ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
		nestJSONBlock(out, block, body)
	}
	out["_dd_lines"] = ddLines
	return converter.BuildLayers(out, expanded), nil
}

// expandJSONInstances converts a resource, data or module block whose count or
// for_each yields instances that differ from one another, one result per
// distinct instance. ok is false for every other block, which is converted as
// written.
func expandJSONInstances(
	block *hcl.Block, evalCtx *hcl.EvalContext, src []byte, instancesLeft *int,
) (values []model.Document, ok bool) {
	switch block.Type {
	case "resource", terraformDataIdentifier:
		if len(block.Labels) < 2 {
			return nil, false
		}
	case "module":
		if len(block.Labels) < 1 {
			return nil, false
		}
	default:
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
	plan := instances.Resolve(count, forEach, evalCtx, 0)
	if plan.Kind == "" || plan.Unresolved {
		return nil, false
	}
	if len(plan.Items) == 0 {
		return nil, true
	}
	extra := len(plan.Items) - 1
	if plan.Truncated() {
		extra++
	}
	if extra > *instancesLeft {
		return nil, false
	}
	values = distinctJSONInstances(block, &plan, evalCtx, src)
	*instancesLeft -= extra
	return values, true
}

// distinctJSONInstances converts each instance of a plan, plus the block as
// written when the plan was cut short, and drops the ones equal to an earlier
// one.
func distinctJSONInstances(block *hcl.Block, plan *instances.Plan, evalCtx *hcl.EvalContext, src []byte) []model.Document {
	var values []model.Document
	add := func(ctx *hcl.EvalContext) {
		value := convertJSONBody(block.Body, ctx, src, block.DefRange.Start.Line)
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

func convertJSONBody(body hcl.Body, evalCtx *hcl.EvalContext, src []byte, defLine int) model.Document {
	attrs, _ := body.JustAttributes()
	budget := dynamicblock.MaxGeneratedPerResource
	return convertJSONAttrs(attrs, evalCtx, src, defLine, &budget)
}

func convertJSONAttrs(
	attrs hcl.Attributes, evalCtx *hcl.EvalContext, src []byte, defLine int, budget *int,
) model.Document {
	out := make(model.Document)
	ddLines := map[string]model.LineObject{
		"_dd__default": {Line: defLine},
	}
	for name, attr := range attrs {
		ddLines["_dd_"+name] = model.LineObject{Line: attr.NameRange.Start.Line}
		out[name] = convertJSONExpr(attr.Expr, evalCtx, src, name)
	}
	if attr, ok := attrs[jsonDynamicKey]; ok {
		expandJSONDynamic(attr, out, ddLines, evalCtx, src, budget)
	}
	out["_dd_lines"] = ddLines
	return out
}

const jsonDynamicKey = "dynamic"

// expandJSONDynamic replaces the dynamic attribute of a JSON body with the
// blocks it generates, each converted with its iterator bound to its element,
// as the native syntax does. The attribute is kept as written unless every
// block type in it resolves.
func expandJSONDynamic(
	attr *hcl.Attribute, out model.Document, ddLines map[string]model.LineObject,
	evalCtx *hcl.EvalContext, src []byte, budget *int,
) {
	types, diags := hcl.ExprMap(attr.Expr)
	if diags.HasErrors() || len(types) == 0 {
		return
	}
	generated := make(map[string][]interface{}, len(types))
	remaining := *budget
	for _, pair := range types {
		keyVal, keyDiags := pair.Key.Value(evalCtx)
		blockType, ok := ctyutil.ConcreteString(keyVal)
		if keyDiags.HasErrors() || !ok {
			return
		}
		blocks, ok := generateJSONDynamic(blockType, pair.Value, evalCtx, src, &remaining)
		if !ok {
			return
		}
		generated[blockType] = append(generated[blockType], blocks...)
	}
	*budget = remaining
	delete(out, jsonDynamicKey)
	delete(ddLines, "_dd_"+jsonDynamicKey)
	for blockType, blocks := range generated {
		ddLines["_dd_"+blockType] = model.LineObject{Line: attr.NameRange.Start.Line}
		if len(blocks) == 0 {
			continue
		}
		switch existing := out[blockType].(type) {
		case nil:
			out[blockType] = blocks
		case []interface{}:
			out[blockType] = append(existing, blocks...)
		default:
			out[blockType] = append([]interface{}{existing}, blocks...)
		}
	}
}

// jsonFields maps the keys of a JSON object expression to their values.
func jsonFields(expr hcl.Expression, evalCtx *hcl.EvalContext) (map[string]hcl.Expression, bool) {
	fields, diags := hcl.ExprMap(expr)
	if diags.HasErrors() {
		return nil, false
	}
	byName := make(map[string]hcl.Expression, len(fields))
	for _, field := range fields {
		keyVal, keyDiags := field.Key.Value(evalCtx)
		name, concrete := ctyutil.ConcreteString(keyVal)
		if keyDiags.HasErrors() || !concrete {
			return nil, false
		}
		byName[name] = field.Value
	}
	return byName, true
}

// jsonAttributes retains the key ranges for generated content's line lookup.
func jsonAttributes(expr hcl.Expression, ctx *hcl.EvalContext) (hcl.Attributes, bool) {
	pairs, diags := hcl.ExprMap(expr)
	if diags.HasErrors() {
		return nil, false
	}
	attrs := make(hcl.Attributes, len(pairs))
	for _, pair := range pairs {
		key, diags := pair.Key.Value(ctx)
		name, ok := ctyutil.ConcreteString(key)
		if diags.HasErrors() || !ok {
			return nil, false
		}
		attrs[name] = &hcl.Attribute{Name: name, Expr: pair.Value, NameRange: pair.Key.Range(), Range: pair.Value.Range()}
	}
	return attrs, true
}

// jsonIteratorName is the variable a dynamic block's content reads its element
// through: the iterator argument when it is a string, else the block type.
func jsonIteratorName(blockType string, expr hcl.Expression, evalCtx *hcl.EvalContext) string {
	if expr == nil {
		return blockType
	}
	v, diags := expr.Value(evalCtx)
	if name, ok := ctyutil.ConcreteString(v); !diags.HasErrors() && ok {
		return name
	}
	return blockType
}

// generateJSONDynamic converts the content of one dynamic block per element of
// its for_each. ok is false when the block cannot be expanded: its for_each
// does not resolve or asks for too many blocks, it sets labels, or it has no
// content.
func generateJSONDynamic(
	blockType string, expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte, budget *int,
) (blocks []interface{}, ok bool) {
	items, diags := hcl.ExprList(expr)
	if diags.HasErrors() {
		items = []hcl.Expression{expr}
	}
	for _, item := range items {
		generated, ok := generateJSONDynamicBlock(blockType, item, evalCtx, src, budget)
		if !ok {
			return nil, false
		}
		blocks = append(blocks, generated...)
	}
	return blocks, true
}

func generateJSONDynamicBlock(
	blockType string, expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte, budget *int,
) (blocks []interface{}, ok bool) {
	byName, ok := jsonFields(expr, evalCtx)
	if !ok {
		return nil, false
	}
	forEach, content := byName["for_each"], byName["content"]
	if _, labeled := byName["labels"]; labeled || forEach == nil || content == nil {
		return nil, false
	}
	collection, diags := forEach.Value(evalCtx)
	if diags.HasErrors() || !collection.IsKnown() || collection.IsNull() ||
		!collection.CanIterateElements() || !collection.Length().IsKnown() {
		return nil, false
	}
	requested := collection.LengthInt()
	if requested > dynamicblock.MaxExpansion || requested > *budget {
		return nil, false
	}
	*budget -= requested
	iterator := jsonIteratorName(blockType, byName["iterator"], evalCtx)
	blocks = make([]interface{}, 0, requested)
	for it := collection.ElementIterator(); it.Next(); {
		key, value := it.Element()
		child := evalCtx.NewChild()
		child.Variables = map[string]cty.Value{iterator: cty.ObjectVal(map[string]cty.Value{"key": key, "value": value})}
		attrs, ok := jsonAttributes(content, child)
		if !ok {
			return nil, false
		}
		blocks = append(blocks, convertJSONAttrs(attrs, child, src, content.Range().Start.Line, budget))
	}
	return blocks, true
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
	if obj, ok := convertJSONObjectExpr(expr, evalCtx, src); ok {
		return obj
	}
	if list, ok := convertJSONListExpr(expr, evalCtx, src, fallback); ok {
		return list
	}
	val, diags := expr.Value(evalCtx)
	if !diags.HasErrors() && val.IsWhollyKnown() {
		return ctyToJSONDocument(val)
	}
	return wrapJSONRange(expr.Range(), fallback, src)
}

func convertJSONObjectExpr(expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte) (model.Document, bool) {
	pairs, diags := hcl.ExprMap(expr)
	if diags.HasErrors() || len(pairs) == 0 {
		return nil, false
	}
	out := make(model.Document, len(pairs)+1)
	lines := map[string]model.LineObject{"_dd__default": {Line: expr.Range().Start.Line}}
	for _, pair := range pairs {
		keyVal, keyDiags := pair.Key.Value(evalCtx)
		key, ok := ctyutil.ConcreteString(keyVal)
		if keyDiags.HasErrors() || !ok {
			continue
		}
		out[key] = convertJSONExpr(pair.Value, evalCtx, src, key)
		lines["_dd_"+key] = model.LineObject{Line: pair.Key.Range().Start.Line}
	}
	out["_dd_lines"] = lines
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
