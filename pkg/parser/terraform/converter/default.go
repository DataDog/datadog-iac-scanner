/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package converter

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// VariableMap represents a set of terraform input variables
type VariableMap map[string]cty.Value

// This file is attributed to https://github.com/tmccombs/hcl2json.
// convertBlock() is manipulated for combining the both blocks and labels for one given resource.

// Options controls filesystem-backed function evaluation during conversion.
type Options struct {
	BaseDir string
	RootDir string
	FS      vfs.FS
}

// Convert an hcl File to a toJson serializable object.
// This assumes that the body is a hclsyntax.Body.
func Convert(ctx context.Context, file *hcl.File, inputVariables VariableMap, opts Options) (model.Document, error) {
	layers, err := ConvertAll(ctx, file, inputVariables, opts)
	if err != nil || len(layers) == 0 {
		return nil, err
	}
	return layers[0], nil
}

// ConvertAll converts an hcl File into its documents. The first holds every
// block of the file. Resources, data and modules whose count or for_each expand into
// instances that differ from one another have their first instance there; see
// BuildLayers for the documents of the others.
func ConvertAll(ctx context.Context, file *hcl.File, inputVariables VariableMap, opts Options) ([]model.Document, error) {
	variables := make(VariableMap, len(inputVariables)+2)
	for name, value := range inputVariables {
		variables[name] = value
	}
	for name, value := range functions.ContextVariables(opts.BaseDir, opts.RootDir) {
		variables[name] = value
	}
	c := newConverter(file.Bytes, variables, functions.EvalFuncsWithRoot(opts.BaseDir, opts.RootDir, opts.FS))
	c.file = file.Body.(*hclsyntax.Body)
	c.instancesLeft = MaxExtraInstances
	body, err := c.convertBody(ctx, c.file, 0)
	if err != nil {
		return nil, err
	}
	return BuildLayers(body, c.expanded), nil
}

// DefaultConverted an hcl File to a toJson serializable object
// This assumes that the body is a hclsyntax.Body
var DefaultConverted = func(ctx context.Context, file *hcl.File, inputVariables VariableMap) (model.Document, error) {
	return Convert(ctx, file, inputVariables, Options{})
}

type converter struct {
	bytes     []byte
	inputVars VariableMap
	renderer  *partial.Renderer
	// file is the body of the whole file; its blocks each get a fresh dynamicLeft.
	file        *hclsyntax.Body
	dynamicLeft int
	// dynamicWarned records that an overflow was already logged for this file.
	dynamicWarned bool
	// expanded holds the blocks whose instances differ, for BuildLayers.
	expanded []Expanded
	// instancesLeft is how many instances beyond the first the file may still
	// expand its top-level blocks into.
	instancesLeft int
	// instancesWarned records that an expansion cap was already logged for this file.
	instancesWarned bool
}

func newConverter(src []byte, variables VariableMap, funcs map[string]function.Function) converter {
	return converter{
		bytes:     src,
		inputVars: variables,
		renderer: &partial.Renderer{
			Ctx:    &hcl.EvalContext{Variables: variables, Functions: funcs},
			Source: partial.BytesSource(src),
		},
	}
}

func (c *converter) rangeSource(r hcl.Range) string {
	return string(c.bytes[r.Start.Byte:r.End.Byte])
}

func (c *converter) convertBody(ctx context.Context, body *hclsyntax.Body, defLine int) (model.Document, error) {
	var err error
	out := make(model.Document)
	ddLines := make(map[string]model.LineObject)
	// set line info for the body
	ddLines["_dd__default"] = model.LineObject{
		Line: defLine,
	}

	if body.Attributes != nil {
		for key, value := range body.Attributes {
			out[key], err = c.convertExpression(value.Expr)
			// set line info for the body value
			ddLines["_dd_"+key] = model.LineObject{
				Line: value.SrcRange.Start.Line,
				Arr:  c.getArrLines(value.Expr),
			}
			if err != nil {
				return nil, err
			}
		}
	}

	for _, block := range body.Blocks {
		if body == c.file {
			c.dynamicLeft = dynamicblock.MaxGeneratedPerResource
		}
		if body == c.file {
			handled, err := c.convertTopLevelInstances(ctx, block, out, ddLines)
			if err != nil {
				return nil, err
			}
			if handled {
				continue
			}
		}
		if dynamicblock.Is(block) {
			expanded, err := c.convertDynamicBlock(ctx, block, out)
			if err != nil {
				return nil, err
			}
			if expanded {
				ddLines["_dd_"+dynamicblock.GeneratedType(block)] = model.LineObject{
					Line: block.TypeRange.Start.Line,
				}
				continue
			}
		}
		// set line info for block
		ddLines["_dd_"+block.Type] = model.LineObject{
			Line: block.TypeRange.Start.Line,
		}
		err = c.convertBlock(ctx, block, out, block.TypeRange.Start.Line)
		if err != nil {
			return nil, err
		}
	}

	out["_dd_lines"] = ddLines

	return out, nil
}

// getArrLines will get line information for the array elements
func (c *converter) getArrLines(expr hclsyntax.Expression) []map[string]*model.LineObject {
	arr := make([]map[string]*model.LineObject, 0)
	if v, ok := expr.(*hclsyntax.TupleConsExpr); ok {
		for _, ex := range v.Exprs {
			arrEx := make(map[string]*model.LineObject)
			// set default line of array
			arrEx["_dd__default"] = &model.LineObject{
				Line: ex.Range().Start.Line,
			}
			switch valType := ex.(type) {
			case *hclsyntax.ObjectConsExpr:
				arrEx["_dd__default"] = &model.LineObject{
					Line: ex.Range().Start.Line + 1,
				}
				// set lines for array elements
				for _, item := range valType.Items {
					key, err := c.convertKey(item.KeyExpr)
					if err != nil {
						return nil
					}
					arrEx["_dd_"+key] = &model.LineObject{
						Line: item.KeyExpr.Range().Start.Line,
					}
				}
			case *hclsyntax.TupleConsExpr:
				// set lines for array elements if type is different than array, map/object
				arrEx["_dd__default"] = &model.LineObject{
					Arr: c.getArrLines(valType),
				}
			}

			arr = append(arr, arrEx)
		}
	}
	return arr
}

func (c *converter) convertBlock(ctx context.Context, block *hclsyntax.Block, out model.Document, defLine int) error {
	value, err := c.convertBody(ctx, block.Body, defLine)
	if err != nil {
		return err
	}
	return insertBlock(ctx, out, append([]string{block.Type}, block.Labels...), value)
}

// convertDynamicBlock adds the blocks a dynamic block generates to out, each
// converted with the block's iterator bound to its element. It reports false,
// adding nothing, when the block's for_each or labels do not resolve for every
// element, so the block is kept as written.
func (c *converter) convertDynamicBlock(ctx context.Context, block *hclsyntax.Block, out model.Document) (bool, error) {
	content := dynamicblock.Content(block)
	expansion := dynamicblock.Expand(block, c.renderer.Ctx)
	if content != nil && expansion.OverCap {
		c.noteDynamicOverflow(ctx, block, expansion.Requested, dynamicblock.MaxExpansion)
	}
	if content == nil || !expansion.Resolved {
		return false, nil
	}
	if c.inputVars == nil {
		c.inputVars = make(VariableMap)
		c.renderer.Ctx.Variables = c.inputVars
	}
	name := dynamicblock.IteratorName(block)
	previous, hadPrevious := c.inputVars[name]
	defer func() {
		if hadPrevious {
			c.inputVars[name] = previous
		} else {
			delete(c.inputVars, name)
		}
	}()
	paths := make([][]string, 0, len(expansion.Iterators))
	for _, iterator := range expansion.Iterators {
		c.inputVars[name] = iterator
		labels, ok := dynamicblock.Labels(block, c.renderer.Ctx)
		if !ok {
			return false, nil
		}
		paths = append(paths, append([]string{dynamicblock.GeneratedType(block)}, labels...))
	}
	// Claimed all or nothing per block: a block that does not fit stays as written.
	if len(expansion.Iterators) > c.dynamicLeft {
		c.noteDynamicOverflow(ctx, block, expansion.Requested, dynamicblock.MaxGeneratedPerResource)
		return false, nil
	}
	c.dynamicLeft -= len(expansion.Iterators)
	for i, iterator := range expansion.Iterators {
		c.inputVars[name] = iterator
		value, err := c.convertBody(ctx, content, block.TypeRange.Start.Line)
		if err != nil {
			return true, err
		}
		if err := insertBlock(ctx, out, paths[i], value); err != nil {
			return true, err
		}
	}
	return true, nil
}

// noteDynamicOverflow logs the first dynamic block kept as written for exceeding a
// cap, once per file, as the evaluator does per scan.
func (c *converter) noteDynamicOverflow(ctx context.Context, block *hclsyntax.Block, requested, limit int) {
	if c.dynamicWarned {
		return
	}
	c.dynamicWarned = true
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().
		Str("expansion_kind", "dynamic").
		Str("address", "dynamic."+dynamicblock.GeneratedType(block)).
		Int("requested_instances", requested).
		Int("count_expansion_cap", limit).
		Msg("tfeval: dynamic block expansion cap exceeded; block scanned as written")
}

func insertBlock(ctx context.Context, out model.Document, path []string, value model.Document) error {
	if value == nil {
		return nil
	}
	key := path[0]
	for _, label := range path[1:] {
		if inner, exists := out[key]; exists {
			var ok bool
			out, ok = inner.(model.Document)
			if !ok {
				err := fmt.Errorf("unable to convert Block to JSON: %v", strings.Join(path, "."))
				contextLogger := logger.FromContext(ctx)
				contextLogger.Error().Msg(err.Error())
				return err
			}
		} else {
			obj := make(model.Document)
			out[key] = obj
			out = obj
		}
		key = label
	}

	if current, exists := out[key]; exists {
		if list, ok := current.([]interface{}); ok {
			out[key] = append(list, value)
		} else {
			out[key] = []interface{}{current, value}
		}
	} else {
		out[key] = value
	}

	return nil
}

func (c *converter) convertExpression(expr hclsyntax.Expression) (interface{}, error) {
	return hclexpr.Dispatch(expr, &converterExprVisitor{c: c})
}

// converterExprVisitor implements hclexpr.Visitor[interface{}] for convertExpression.
type converterExprVisitor struct {
	c *converter
}

func (v *converterExprVisitor) VisitLiteralValue(e *hclsyntax.LiteralValueExpr) (interface{}, error) {
	return ctyjson.SimpleJSONValue{Value: e.Val}, nil
}
func (v *converterExprVisitor) VisitTemplateExpr(e *hclsyntax.TemplateExpr) (interface{}, error) {
	return v.c.convertTemplate(e)
}
func (v *converterExprVisitor) VisitScopeTraversal(e *hclsyntax.ScopeTraversalExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitIndexExpr(e *hclsyntax.IndexExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitRelativeTraversal(e *hclsyntax.RelativeTraversalExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitFunctionCall(e *hclsyntax.FunctionCallExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitConditional(e *hclsyntax.ConditionalExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitTupleCons(e *hclsyntax.TupleConsExpr) (interface{}, error) {
	list := make([]interface{}, 0, len(e.Exprs))
	for _, ex := range e.Exprs {
		elem, err := v.c.convertExpression(ex)
		if err != nil {
			return nil, err
		}
		list = append(list, elem)
	}
	return list, nil
}
func (v *converterExprVisitor) VisitObjectCons(e *hclsyntax.ObjectConsExpr) (interface{}, error) {
	return v.c.objectConsExpr(e)
}
func (v *converterExprVisitor) VisitTemplateJoin(e *hclsyntax.TemplateJoinExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitBinaryOp(e *hclsyntax.BinaryOpExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitUnaryOp(e *hclsyntax.UnaryOpExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitForExpr(e *hclsyntax.ForExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitSplatExpr(e *hclsyntax.SplatExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitAnonSymbol(e *hclsyntax.AnonSymbolExpr) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitExprSyntaxError(e *hclsyntax.ExprSyntaxError) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}
func (v *converterExprVisitor) VisitDefault(e hclsyntax.Expression) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}

func (c *converter) objectConsExpr(value *hclsyntax.ObjectConsExpr) (model.Document, error) {
	m := make(model.Document)
	for _, item := range value.Items {
		key, err := c.convertKey(item.KeyExpr)
		if err != nil {
			return nil, err
		}
		m[key], err = c.convertExpression(item.ValueExpr)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (c *converter) convertKey(keyExpr hclsyntax.Expression) (string, error) {
	// a key should never have dynamic input
	if k, isKeyExpr := keyExpr.(*hclsyntax.ObjectConsKeyExpr); isKeyExpr {
		keyExpr = k.Wrapped
		if _, isTraversal := keyExpr.(*hclsyntax.ScopeTraversalExpr); isTraversal {
			return c.rangeSource(keyExpr.Range()), nil
		}
	}
	return c.convertStringPart(keyExpr)
}

func (c *converter) convertTemplate(t *hclsyntax.TemplateExpr) (string, error) {
	if t.IsStringLiteral() {
		v, err := t.Value(nil)
		if err != nil {
			return "", err
		}
		if s, ok := ctyutil.ConcreteString(v); ok {
			return s, nil
		}
		return c.wrapExpr(t)
	}
	builder := &strings.Builder{}
	for _, part := range t.Parts {
		s, err := c.convertStringPart(part)
		if err != nil {
			return "", err
		}
		builder.WriteString(s)
	}

	s := builder.String()

	builder.Reset()
	builder = nil

	return s, nil
}

func (c *converter) convertStringPart(expr hclsyntax.Expression) (string, error) {
	return hclexpr.Dispatch(expr, &converterStringPartVisitor{c: c})
}

// converterStringPartVisitor implements hclexpr.Visitor[string] for convertStringPart.
type converterStringPartVisitor struct {
	c *converter
}

func (v *converterStringPartVisitor) VisitLiteralValue(e *hclsyntax.LiteralValueExpr) (string, error) {
	s, err := ctyconvert.Convert(e.Val, cty.String)
	if err != nil {
		return "", err
	}
	if str, ok := ctyutil.ConcreteString(s); ok {
		return str, nil
	}
	return v.c.wrapExpr(e)
}
func (v *converterStringPartVisitor) VisitTemplateExpr(e *hclsyntax.TemplateExpr) (string, error) {
	return v.c.convertTemplate(e)
}
func (v *converterStringPartVisitor) VisitScopeTraversal(e *hclsyntax.ScopeTraversalExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitIndexExpr(e *hclsyntax.IndexExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitRelativeTraversal(e *hclsyntax.RelativeTraversalExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitFunctionCall(e *hclsyntax.FunctionCallExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitConditional(e *hclsyntax.ConditionalExpr) (string, error) {
	return v.c.convertTemplateConditional(e)
}
func (v *converterStringPartVisitor) VisitTupleCons(e *hclsyntax.TupleConsExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitObjectCons(e *hclsyntax.ObjectConsExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitTemplateJoin(e *hclsyntax.TemplateJoinExpr) (string, error) {
	return v.c.convertTemplateFor(e.Tuple.(*hclsyntax.ForExpr))
}
func (v *converterStringPartVisitor) VisitBinaryOp(e *hclsyntax.BinaryOpExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitUnaryOp(e *hclsyntax.UnaryOpExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitForExpr(e *hclsyntax.ForExpr) (string, error) {
	return v.c.convertTemplateFor(e)
}
func (v *converterStringPartVisitor) VisitSplatExpr(e *hclsyntax.SplatExpr) (string, error) {
	return v.c.tryEvalToString(e)
}
func (v *converterStringPartVisitor) VisitAnonSymbol(e *hclsyntax.AnonSymbolExpr) (string, error) {
	return v.VisitDefault(e)
}
func (v *converterStringPartVisitor) VisitExprSyntaxError(e *hclsyntax.ExprSyntaxError) (string, error) {
	return v.VisitDefault(e)
}
func (v *converterStringPartVisitor) VisitDefault(e hclsyntax.Expression) (string, error) {
	val, _ := e.Value(&hcl.EvalContext{Variables: v.c.inputVars})
	if s, ok := ctyutil.ConcreteString(val); ok {
		return s, nil
	}
	return v.c.wrapExpr(e)
}

func (c *converter) convertTemplateConditional(expr *hclsyntax.ConditionalExpr) (string, error) {
	builder := &strings.Builder{}
	builder.WriteString("%{if ")
	builder.WriteString(c.rangeSource(expr.Condition.Range()))
	builder.WriteString("}")
	trueResult, err := c.convertStringPart(expr.TrueResult)
	if err != nil {
		return "", nil
	}
	builder.WriteString(trueResult)
	falseResult, err := c.convertStringPart(expr.FalseResult)
	if err != nil {
		return "", nil
	}
	if falseResult != "" {
		builder.WriteString("%{else}")
		builder.WriteString(falseResult)
	}
	builder.WriteString("%{endif}")

	s := builder.String()

	builder.Reset()
	builder = nil

	return s, nil
}

func (c *converter) convertTemplateFor(expr *hclsyntax.ForExpr) (string, error) {
	builder := &strings.Builder{}
	builder.WriteString("%{for ")
	if expr.KeyVar != "" {
		builder.WriteString(expr.KeyVar)
		builder.WriteString(", ")
	}
	builder.WriteString(expr.ValVar)
	builder.WriteString(" in ")
	builder.WriteString(c.rangeSource(expr.CollExpr.Range()))
	builder.WriteString("}")
	templ, err := c.convertStringPart(expr.ValExpr)
	if err != nil {
		return "", err
	}
	builder.WriteString(templ)
	builder.WriteString("%{endfor}")

	s := builder.String()

	builder.Reset()
	builder = nil
	return s, nil
}

// tryEvalExpression renders expr, each unresolved part as its own "${expr}"
// text. An unresolved string stays a plain string.
func (c *converter) tryEvalExpression(expr hclsyntax.Expression) (interface{}, error) {
	if val, diags := expr.Value(c.renderer.Ctx); !diags.HasErrors() && val.IsWhollyKnown() {
		return ctyjson.SimpleJSONValue{Value: val}, nil
	}
	val, ok := c.renderer.RenderUnresolved(expr)
	if !ok {
		return c.wrapExpr(expr)
	}
	if s, ok := ctyutil.ConcreteString(val); ok {
		return s, nil
	}
	return ctyjson.SimpleJSONValue{Value: val}, nil
}

func (c *converter) tryEvalToString(expr hclsyntax.Expression) (string, error) {
	return c.renderer.StringPart(expr), nil
}

func (c *converter) wrapExpr(expr hclsyntax.Expression) (string, error) {
	if s, ok := c.renderer.Text(expr); ok {
		return s, nil
	}
	return "${" + c.rangeSource(expr.Range()) + "}", nil
}
