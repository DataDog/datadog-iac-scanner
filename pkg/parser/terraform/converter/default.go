/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package converter

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// VariableMap represents a set of terraform input variables
type VariableMap map[string]cty.Value

// This file is attributed to https://github.com/tmccombs/hcl2json.
// convertBlock() is manipulated for combining the both blocks and labels for one given resource.

// DefaultConverted an hcl File to a toJson serializable object
// This assumes that the body is a hclsyntax.Body
var DefaultConverted = func(ctx context.Context, file *hcl.File, inputVariables VariableMap) (model.Document, error) {
	c := converter{bytes: file.Bytes, inputVars: inputVariables}
	body, err := c.convertBody(ctx, file.Body.(*hclsyntax.Body), 0)

	if err != nil {
		if er, ok := err.(*hcl.Diagnostic); ok && er.Subject != nil {
			return nil, err
		}

		return nil, err
	}

	return body, nil
}

type converter struct {
	bytes     []byte
	inputVars VariableMap
}

const (
	ddLinesKey            = "_dd_"
	ctyFriendlyNameString = "string"
)

func (c *converter) rangeSource(r hcl.Range) string {
	return string(c.bytes[r.Start.Byte:r.End.Byte])
}

func (c *converter) convertBody(ctx context.Context, body *hclsyntax.Body, defLine int) (model.Document, error) {
	var err error
	var v string
	countValue := body.Attributes["count"]
	count := -1

	if countValue != nil {
		value, err := countValue.Expr.Value(nil)
		if err == nil {
			switch value.Type() {
			case cty.String:
				v = value.AsString()
			case cty.Number:
				v = value.AsBigFloat().String()
			}

			intValue, err := strconv.Atoi(v)
			if err == nil {
				count = intValue
			}
		}
	}

	if count == 0 {
		return nil, nil
	}

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
	contextLogger := logger.FromContext(ctx)
	var key = block.Type
	value, err := c.convertBody(ctx, block.Body, defLine)

	if err != nil {
		return err
	}

	if value == nil {
		return nil
	}

	for _, label := range block.Labels {
		if inner, exists := out[key]; exists {
			var ok bool
			out, ok = inner.(model.Document)
			if !ok {
				err = fmt.Errorf("unable to convert Block to JSON: %v.%v", block.Type, strings.Join(block.Labels, "."))
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
	return v.c.evalFunction(e)
}
func (v *converterExprVisitor) VisitConditional(e *hclsyntax.ConditionalExpr) (interface{}, error) {
	val, err := e.Value(&hcl.EvalContext{
		Variables: v.c.inputVars,
		Functions: functions.TerraformFuncs,
	})
	if err != nil {
		return v.c.wrapExpr(e)
	}
	return ctyjson.SimpleJSONValue{Value: val}, nil
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
func (v *converterExprVisitor) VisitDefault(e hclsyntax.Expression) (interface{}, error) {
	return v.c.tryEvalExpression(e)
}

func checkValue(val cty.Value) bool {
	if val.Type().HasDynamicTypes() || !val.IsKnown() {
		return true
	}
	if !val.Type().IsPrimitiveType() && checkDynamicKnownTypes(val) {
		return true
	}
	return false
}

func checkDynamicKnownTypes(valueConverted cty.Value) bool {
	if !valueConverted.Type().HasDynamicTypes() && valueConverted.IsKnown() {
		if valueConverted.Type().FriendlyName() == "tuple" {
			for _, val := range valueConverted.AsValueSlice() {
				if checkValue(val) {
					return true
				}
			}
		}
		if valueConverted.Type().FriendlyName() == "object" {
			for _, val := range valueConverted.AsValueMap() {
				if checkValue(val) {
					return true
				}
			}
		}
		return false
	}
	return true
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
		// safe because the value is just the string
		v, err := t.Value(nil)
		if err != nil {
			return "", err
		}
		return v.AsString(), nil
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
	return s.AsString(), nil
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
func (v *converterStringPartVisitor) VisitDefault(e hclsyntax.Expression) (string, error) {
	val, _ := e.Value(&hcl.EvalContext{Variables: v.c.inputVars})
	if val.Type().FriendlyName() == ctyFriendlyNameString {
		return val.AsString(), nil
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

func (c *converter) tryEvalExpression(expr hclsyntax.Expression) (interface{}, error) {
	val, _ := expr.Value(&hcl.EvalContext{
		Variables: c.inputVars,
		Functions: functions.TerraformFuncs,
	})
	if !checkDynamicKnownTypes(val) {
		return ctyjson.SimpleJSONValue{Value: val}, nil
	}
	return c.wrapExpr(expr)
}

func (c *converter) tryEvalToString(expr hclsyntax.Expression) (string, error) {
	val, _ := expr.Value(&hcl.EvalContext{
		Variables: c.inputVars,
		Functions: functions.TerraformFuncs,
	})
	if val.Type().FriendlyName() == ctyFriendlyNameString {
		return val.AsString(), nil
	}
	return c.wrapExpr(expr)
}

func (c *converter) wrapExpr(expr hclsyntax.Expression) (string, error) {
	expression := c.rangeSource(expr.Range())
	return "${" + expression + "}", nil
}

func (c *converter) evalFunction(expression hclsyntax.Expression) (interface{}, error) {
	expressionEvaluated, err := expression.Value(&hcl.EvalContext{
		Variables: c.inputVars,
		Functions: functions.TerraformFuncs,
	})

	if err != nil {
		// Initialize inputVars if nil
		if c.inputVars == nil {
			c.inputVars = make(VariableMap)
		}
		for _, expressionError := range err {
			if expressionError.Summary == "Unknown variable" || expressionError.Summary == "Variables not allowed" {
				jsonPath := c.rangeSource(expressionError.Expression.Range())
				rootKey := strings.Split(jsonPath, ".")[0]
				if strings.Contains(jsonPath, ".") {
					jsonCtyValue, convertErr := createEntryInputVar(strings.Split(jsonPath, ".")[1:], jsonPath)
					if convertErr != nil {
						return c.wrapExpr(expression)
					}
					c.inputVars[rootKey] = jsonCtyValue
				} else {
					c.inputVars[rootKey] = cty.StringVal(jsonPath)
				}
			}
		}

		// Retry evaluation with updated variables
		expressionEvaluated, err = expression.Value(&hcl.EvalContext{
			Variables: c.inputVars,
			Functions: functions.TerraformFuncs,
		})

		if err != nil {
			return c.wrapExpr(expression)
		}
	}
	if !expressionEvaluated.HasWhollyKnownType() {
		// in some cases, the expression is evaluated with no error but the type is unknown.
		// this causes the json marshaling of the Document later on to fail with an error, and the entire scan fails.
		// Therefore, we prefer to wrap it as a string and continue the scan.
		return c.wrapExpr(expression)
	}
	return ctyjson.SimpleJSONValue{Value: expressionEvaluated}, nil
}

func createEntryInputVar(path []string, defaultValue string) (cty.Value, error) {
	mapJSON := "{"
	closeMap := "}"
	for idx, key := range path {
		if idx+1 < len(path) {
			mapJSON += fmt.Sprintf("%q:{", key)
			closeMap += "}"
		} else {
			mapJSON += fmt.Sprintf("%q: %q", key, defaultValue)
		}
	}
	mapJSON += closeMap
	jsonType, err := ctyjson.ImpliedType([]byte(mapJSON))
	if err != nil {
		return cty.NilVal, err
	}
	value, err := ctyjson.Unmarshal([]byte(mapJSON), jsonType)
	if err != nil {
		return cty.NilVal, err
	}
	return value, nil
}
