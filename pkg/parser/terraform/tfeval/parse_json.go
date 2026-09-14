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
	return &hclsyntax.Block{
		Type:            block.Type,
		Labels:          block.Labels,
		Body:            jsonBodyToHCL(block.Body, src, block.DefRange),
		TypeRange:       block.TypeRange,
		LabelRanges:     block.LabelRanges,
		OpenBraceRange:  block.DefRange,
		CloseBraceRange: block.DefRange,
	}
}

func jsonBodyToHCL(body hcl.Body, src []byte, defRange hcl.Range) *hclsyntax.Body {
	attrs, _ := body.JustAttributes()
	out := &hclsyntax.Body{
		Attributes: make(hclsyntax.Attributes, len(attrs)),
		SrcRange:   defRange,
	}
	for name, attr := range attrs {
		out.Attributes[name] = &hclsyntax.Attribute{
			Name:      name,
			Expr:      jsonExprToHCL(attr.Expr, src),
			NameRange: attr.NameRange,
			SrcRange:  attr.Range,
		}
	}
	return out
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
	parsed, diags := hclsyntax.ParseExpression([]byte(strconv.Quote(unquoted)), "", expr.Range().Start)
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
