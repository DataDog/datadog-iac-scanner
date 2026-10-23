/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

const jsonDynamicBlockType = "dynamic"

var jsonConfigSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "terraform"},
		{Type: "locals"},
		{Type: "variable", LabelNames: []string{"name"}},
		{Type: "output", LabelNames: []string{"name"}},
		{Type: blockTypeModule, LabelNames: []string{"name"}},
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "data", LabelNames: []string{"type", "name"}},
	},
}

func parseJSONAsHCLBody(src []byte, filename string) (*hclsyntax.Body, bool) {
	file, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil, false
	}
	content, _, _ := file.Body.PartialContent(jsonConfigSchema)
	if content == nil {
		return nil, false
	}
	body := &hclsyntax.Body{
		Attributes: make(hclsyntax.Attributes),
		SrcRange:   hcl.Range{Filename: filename, Start: hcl.Pos{Line: 1, Column: 1, Byte: 0}},
	}
	for _, block := range content.Blocks {
		body.Blocks = append(body.Blocks, jsonBlockToHCL(block, src))
	}
	return body, true
}

func jsonBlockToHCL(block *hcl.Block, src []byte) *hclsyntax.Block {
	header := block.TypeRange
	if len(block.LabelRanges) > 0 {
		header = block.LabelRanges[len(block.LabelRanges)-1]
	}
	body := jsonBodyToHCL(block.Body, src, block.DefRange)
	return &hclsyntax.Block{
		Type:            block.Type,
		Labels:          block.Labels,
		Body:            body,
		TypeRange:       header,
		LabelRanges:     block.LabelRanges,
		OpenBraceRange:  header,
		CloseBraceRange: body.SrcRange,
	}
}

func jsonBodyToHCL(body hcl.Body, src []byte, defRange hcl.Range) *hclsyntax.Body {
	attrs, _ := body.JustAttributes()
	return jsonAttrsToHCL(attrs, src, defRange)
}

func jsonAttrsToHCL(attrs hcl.Attributes, src []byte, defRange hcl.Range) *hclsyntax.Body {
	out := &hclsyntax.Body{
		Attributes: make(hclsyntax.Attributes, len(attrs)),
		SrcRange:   defRange,
	}
	for name, attr := range attrs {
		if attr.Range.End.Byte > out.SrcRange.End.Byte {
			out.SrcRange.End = attr.Range.End
		}
		if name == jsonDynamicBlockType {
			if blocks, ok := jsonDynamicBlocks(attr.Expr, src); ok {
				out.Blocks = append(out.Blocks, blocks...)
				continue
			}
		}
		out.Attributes[name] = &hclsyntax.Attribute{
			Name:      name,
			Expr:      jsonExprToHCL(attr.Expr, src),
			NameRange: attr.NameRange,
			SrcRange:  attr.Range,
		}
	}
	return out
}

// JSON resource bodies otherwise retain nested objects as attributes. Dynamic
// blocks need their syntax represented as blocks so the existing evaluator can
// expand them in each resource instance's count/each scope and enforce its caps.
func jsonDynamicBlocks(expr hcl.Expression, src []byte) ([]*hclsyntax.Block, bool) {
	types, diags := hcl.ExprMap(expr)
	if diags.HasErrors() {
		return nil, false
	}
	var blocks []*hclsyntax.Block
	for _, pair := range types {
		key, diags := pair.Key.Value(nil)
		if diags.HasErrors() || !key.IsKnown() || key.IsNull() || key.Type() != cty.String {
			return nil, false
		}
		items, diags := hcl.ExprList(pair.Value)
		if diags.HasErrors() {
			items = []hcl.Expression{pair.Value}
		}
		for _, item := range items {
			body, ok := jsonDynamicBody(item, src)
			if !ok {
				return nil, false
			}
			blocks = append(blocks, &hclsyntax.Block{
				Type: jsonDynamicBlockType, Labels: []string{key.AsString()}, Body: body,
				TypeRange: pair.Key.Range(), OpenBraceRange: item.Range(), CloseBraceRange: item.Range(),
			})
		}
	}
	return blocks, true
}

func jsonDynamicBody(expr hcl.Expression, src []byte) (*hclsyntax.Body, bool) {
	attrs, ok := jsonExprAttributes(expr)
	if !ok {
		return nil, false
	}
	content, hasContent := attrs["content"]
	if !hasContent {
		return nil, false
	}
	contentAttrs, ok := jsonExprAttributes(content.Expr)
	if !ok {
		return nil, false
	}
	delete(attrs, "content")
	body := jsonAttrsToHCL(attrs, src, expr.Range())
	if iterator := attrs["iterator"]; iterator != nil {
		value, diags := iterator.Expr.Value(nil)
		if !diags.HasErrors() && value.IsKnown() && !value.IsNull() && value.Type() == cty.String {
			body.Attributes["iterator"].Expr = &hclsyntax.ScopeTraversalExpr{
				Traversal: hcl.Traversal{hcl.TraverseRoot{Name: value.AsString(), SrcRange: iterator.Range}},
				SrcRange:  iterator.Range,
			}
		}
	}
	body.Blocks = append(body.Blocks, &hclsyntax.Block{
		Type: "content", Body: jsonAttrsToHCL(contentAttrs, src, content.Range),
		TypeRange: content.NameRange, OpenBraceRange: content.Range, CloseBraceRange: content.Range,
	})
	return body, true
}

func jsonExprAttributes(expr hcl.Expression) (hcl.Attributes, bool) {
	pairs, diags := hcl.ExprMap(expr)
	if diags.HasErrors() {
		return nil, false
	}
	attrs := make(hcl.Attributes, len(pairs))
	for _, pair := range pairs {
		key, diags := pair.Key.Value(nil)
		if diags.HasErrors() || !key.IsKnown() || key.IsNull() || key.Type() != cty.String {
			return nil, false
		}
		name := key.AsString()
		attrs[name] = &hcl.Attribute{Name: name, Expr: pair.Value, NameRange: pair.Key.Range(), Range: pair.Value.Range()}
	}
	return attrs, true
}

func jsonExprToHCL(expr hcl.Expression, src []byte) hclsyntax.Expression {
	if obj, ok := jsonObjectExprToHCL(expr, src); ok {
		return obj
	}
	if list, ok := jsonListExprToHCL(expr, src); ok {
		return list
	}
	val, diags := expr.Value(&hcl.EvalContext{})
	if !diags.HasErrors() && val.IsWhollyKnown() {
		return &hclsyntax.LiteralValueExpr{Val: val, SrcRange: expr.Range()}
	}
	if parsed := parseJSONInterpolation(expr, src); parsed != nil {
		return parsed
	}
	return &hclsyntax.LiteralValueExpr{Val: cty.UnknownVal(cty.DynamicPseudoType), SrcRange: expr.Range()}
}

func jsonObjectExprToHCL(expr hcl.Expression, src []byte) (hclsyntax.Expression, bool) {
	pairs, diags := hcl.ExprMap(expr)
	if diags.HasErrors() || len(pairs) == 0 {
		return nil, false
	}
	items := make([]hclsyntax.ObjectConsItem, 0, len(pairs))
	for _, pair := range pairs {
		items = append(items, hclsyntax.ObjectConsItem{
			KeyExpr:   jsonExprToHCL(pair.Key, src),
			ValueExpr: jsonExprToHCL(pair.Value, src),
		})
	}
	return &hclsyntax.ObjectConsExpr{Items: items, SrcRange: expr.Range()}, true
}

func jsonListExprToHCL(expr hcl.Expression, src []byte) (hclsyntax.Expression, bool) {
	items, diags := hcl.ExprList(expr)
	if diags.HasErrors() || len(items) == 0 {
		return nil, false
	}
	exprs := make([]hclsyntax.Expression, 0, len(items))
	for _, item := range items {
		exprs = append(exprs, jsonExprToHCL(item, src))
	}
	return &hclsyntax.TupleConsExpr{Exprs: exprs, SrcRange: expr.Range()}, true
}

func parseJSONInterpolation(expr hcl.Expression, src []byte) hclsyntax.Expression {
	raw := jsonExprSource(expr, src)
	if raw == "" {
		return nil
	}
	if raw == "null" {
		return &hclsyntax.LiteralValueExpr{Val: cty.NullVal(cty.DynamicPseudoType), SrcRange: expr.Range()}
	}
	unquoted, err := strconv.Unquote(raw)
	if err != nil {
		unquoted = strings.TrimSpace(raw)
	}
	// JSON has already unescaped the string. Parse it as template content:
	// re-quoting would escape quotes inside count/each expressions a second
	// time and make valid JSON interpolations fail in module instances.
	parsed, diags := hclsyntax.ParseTemplate([]byte(unquoted), expr.Range().Filename, expr.Range().Start)
	if diags.HasErrors() {
		return nil
	}
	return parsed
}

func jsonExprSource(expr hcl.Expression, src []byte) string {
	r := expr.Range()
	if r.Start.Byte < 0 || r.End.Byte > len(src) || r.Start.Byte >= r.End.Byte {
		return ""
	}
	return strings.TrimSpace(string(src[r.Start.Byte:r.End.Byte]))
}
