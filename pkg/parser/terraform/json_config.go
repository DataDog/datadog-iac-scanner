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
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
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
		{Type: blockTypeModule, LabelNames: []string{"name"}},
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
	var expansions []model.ResourceExpansion
	instancesLeft := instances.MaxPerFile
	for _, block := range content.Blocks {
		values, plan, positions, recordable, ok := expandJSONInstances(block, evalCtx, src, &instancesLeft)
		if recordable {
			path := append([]string{block.Type}, block.Labels...)
			expansions = append(expansions, jsonExpansionFor(block, path, plan, positions))
		}
		if !ok {
			body, skip := convertJSONBody(block.Body, evalCtx, src, block.DefRange.Start.Line)
			if skip {
				continue
			}
			ddLines["_dd_"+block.Type] = model.LineObject{Line: block.TypeRange.Start.Line}
			nestJSONBlock(out, block, body)
			continue
		}
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
	}
	out["_dd_lines"] = ddLines
	layers := converter.BuildLayers(out, expanded)
	if len(expansions) > 0 {
		// Carried on the first document for the engine to report findings per
		// instance address; stripped into the file metadata before rules run.
		layers[0]["_dd_expansions"] = converter.EncodeExpansions(expansions)
	}
	return layers, nil
}

// jsonExpansionFor builds the expansion record of one JSON block the way the
// converter does for native syntax: every instance address its plan produces,
// and which addresses each distinct converted instance covers. A nil
// positions list means every planned instance converts identically, so the
// single conversion covers them all.
func jsonExpansionFor(block *hcl.Block, path []string, plan instances.Plan, positions [][]int) model.ResourceExpansion {
	mode := address.Mode(block.Type)
	typ, name := "", ""
	switch block.Type {
	case blockTypeModule:
		name = block.Labels[0]
		mode = ""
		// A module call address has no resource mode: module.<name>[key].
		typ = blockTypeModule
	default:
		typ, name = block.Labels[0], block.Labels[1]
	}

	prefix := ""
	if block.Type == blockTypeModule {
		prefix = "module." + name
	} else {
		prefix = typ + "." + name
		if mode == address.ModeData {
			prefix = "data." + prefix
		}
	}

	addresses := make([]string, 0, len(plan.Items))
	known := make([]int, 0, len(plan.Items))
	for i, item := range plan.Items {
		key := ""
		if plan.Kind == instances.KindCount {
			key = "[" + strconv.Itoa(i) + "]"
		} else if formatted, ok := address.FormatKey(item.Key); ok {
			key = formatted
		} else {
			continue
		}
		addresses = append(addresses, prefix+key)
		known = append(known, i)
	}

	if positions == nil {
		positions = make([][]int, 1)
		positions[0] = known
	}
	renumber := make([]int, len(plan.Items))
	for i := range renumber {
		renumber[i] = -1
	}
	for out, in := range known {
		renumber[in] = out
	}
	mapped := make([][]int, len(positions))
	for vi, idx := range positions {
		mapped[vi] = make([]int, 0, len(idx))
		for _, i := range idx {
			if i >= 0 && renumber[i] >= 0 {
				mapped[vi] = append(mapped[vi], renumber[i])
			}
		}
	}
	return model.ResourceExpansion{
		Path:      strings.Join(path, "."),
		Type:      typ,
		Name:      name,
		Data:      mode == address.ModeData,
		Truncated: plan.Truncated(),
		Addresses: addresses,
		Positions: mapped,
	}
}

// expandJSONInstances converts a resource or data block whose count or
// for_each yields instances that differ from one another, one result per
// distinct instance, with the planned instances that produced each. recordable
// reports whether the block produced an expansion plan to record (a block that
// does not read its instance context records one covering every planned
// address, and is still converted as written: ok is false then). ok is false
// for every other block, which is converted as written without a record.
func expandJSONInstances(
	block *hcl.Block, evalCtx *hcl.EvalContext, src []byte, instancesLeft *int,
) (values []model.Document, plan instances.Plan, positions [][]int, recordable, ok bool) {
	switch block.Type {
	case "resource", terraformDataIdentifier:
		if len(block.Labels) < 2 {
			return nil, instances.Plan{}, nil, false, false
		}
	case blockTypeModule:
		if len(block.Labels) < 1 {
			return nil, instances.Plan{}, nil, false, false
		}
	default:
		return nil, instances.Plan{}, nil, false, false
	}
	attrs, _ := block.Body.JustAttributes()
	var count, forEach hcl.Expression
	if attr, has := attrs[instances.KindCount]; has {
		count = attr.Expr
	}
	if attr, has := attrs[instances.KindForEach]; has {
		forEach = attr.Expr
	}
	plan = instances.Resolve(count, forEach, evalCtx)
	if !plan.Expands() {
		return nil, plan, nil, false, false
	}
	if len(plan.Items) == 0 {
		// No instance: the block declares nothing and has no address, matching
		// a plan with no resource_changes entry for it.
		return nil, plan, nil, true, true
	}
	exprs := make([]hcl.Expression, 0, len(attrs))
	for _, attr := range attrs {
		exprs = append(exprs, attr.Expr)
	}
	extra := len(plan.Items) - 1
	if plan.Truncated() {
		extra++
	}
	reads := instances.ReadsInstanceExpr(exprs...)
	if !reads || extra > *instancesLeft {
		if reads {
			// The block reads its instance context but does not fit the
			// file's instance budget: it is converted as written and carries
			// no expansion record.
			return nil, plan, nil, false, false
		}
		// The block does not read its instance context, so every planned
		// instance converts identically: the file keeps the block as
		// written and findings on it fan out to every planned address.
		return nil, plan, nil, true, false
	}
	values, positions = distinctJSONInstances(block, plan, evalCtx, src)
	*instancesLeft -= len(values) - 1
	return values, plan, positions, true, true
}

// distinctJSONInstances converts each instance of a plan, plus the block as
// written when the plan was cut short, and drops the ones equal to an earlier
// one, recording the planned instances that produced each.
func distinctJSONInstances(
	block *hcl.Block, plan instances.Plan, evalCtx *hcl.EvalContext, src []byte,
) (docs []model.Document, positions [][]int) {
	add := func(ctx *hcl.EvalContext, itemIndex int) {
		value, skip := convertJSONBody(block.Body, ctx, src, block.DefRange.Start.Line)
		if skip {
			return
		}
		for vi, seen := range docs {
			if converter.SameInstance(seen, value) {
				positions[vi] = append(positions[vi], itemIndex)
				return
			}
		}
		docs = append(docs, value)
		positions = append(positions, []int{itemIndex})
	}
	for itemIndex, item := range plan.Items {
		name, iteration := plan.Variable(item)
		child := evalCtx.NewChild()
		child.Variables = map[string]cty.Value{name: iteration}
		add(child, itemIndex)
	}
	if plan.Truncated() {
		// The as-written conversion stands for the block itself, not for any
		// one planned instance; its item index is unknown, so it maps to no
		// address.
		add(evalCtx, -1)
	}
	return docs, positions
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
	if attr, ok := attrs[jsonDynamicKey]; ok {
		expandJSONDynamic(attr, out, ddLines, evalCtx, src)
	}
	out["_dd_lines"] = ddLines
	return out, false
}

const jsonDynamicKey = "dynamic"

// expandJSONDynamic replaces the dynamic attribute of a JSON body with the
// blocks it generates, each converted with its iterator bound to its element,
// as the native syntax does. The attribute is kept as written unless every
// block type in it resolves.
func expandJSONDynamic(
	attr *hcl.Attribute, out model.Document, ddLines map[string]model.LineObject,
	evalCtx *hcl.EvalContext, src []byte,
) {
	types, diags := hcl.ExprMap(attr.Expr)
	if diags.HasErrors() || len(types) == 0 {
		return
	}
	generated := make(map[string][]interface{}, len(types))
	budget := dynamicblock.MaxGeneratedPerResource
	for _, pair := range types {
		keyVal, keyDiags := pair.Key.Value(evalCtx)
		blockType, ok := ctyutil.ConcreteString(keyVal)
		if keyDiags.HasErrors() || !ok {
			return
		}
		blocks, ok := generateJSONDynamic(blockType, pair.Value, evalCtx, src, &budget)
		if !ok {
			return
		}
		generated[blockType] = append(generated[blockType], blocks...)
	}
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
		blocks = append(blocks, convertJSONExpr(content, child, src, blockType))
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
