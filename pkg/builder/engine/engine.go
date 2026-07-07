/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyConvert "github.com/zclconf/go-cty/cty/convert"
)

// Engine contains the conditions of rules and comments positions
type Engine struct {
}

// ExpToString converts an expression into a string
func (e *Engine) ExpToString(ctx context.Context, expr hclsyntax.Expression) (string, error) {
	return hclexpr.Dispatch(expr, &engineVisitor{e: e, ctx: ctx})
}

// engineVisitor implements hclexpr.Visitor[string] for ExpToString.
type engineVisitor struct {
	e   *Engine
	ctx context.Context
}

func (v *engineVisitor) VisitLiteralValue(e *hclsyntax.LiteralValueExpr) (string, error) {
	return v.e.expToStringLiteralValue(e)
}
func (v *engineVisitor) VisitTemplateExpr(e *hclsyntax.TemplateExpr) (string, error) {
	return v.e.expToStringTemplateExpr(v.ctx, e)
}
func (v *engineVisitor) VisitScopeTraversal(e *hclsyntax.ScopeTraversalExpr) (string, error) {
	return v.e.expToStringScopeTraversal(e), nil
}
func (v *engineVisitor) VisitIndexExpr(e *hclsyntax.IndexExpr) (string, error) {
	return v.e.indexExprToString(v.ctx, e)
}
func (v *engineVisitor) VisitRelativeTraversal(e *hclsyntax.RelativeTraversalExpr) (string, error) {
	return v.e.expToStringRelativeTraversal(v.ctx, e)
}
func (v *engineVisitor) VisitFunctionCall(e *hclsyntax.FunctionCallExpr) (string, error) {
	return v.e.expToStringFunctionCall(v.ctx, e)
}
func (v *engineVisitor) VisitConditional(e *hclsyntax.ConditionalExpr) (string, error) {
	return v.e.expToStringConditionalExpr(v.ctx, e)
}
func (v *engineVisitor) VisitTupleCons(e *hclsyntax.TupleConsExpr) (string, error) {
	return v.e.expToStringTupleConsExpr(v.ctx, e)
}
func (v *engineVisitor) VisitObjectCons(e *hclsyntax.ObjectConsExpr) (string, error) {
	return v.e.expToStringObjectConsExpr(v.ctx, e)
}
func (v *engineVisitor) VisitTemplateJoin(e *hclsyntax.TemplateJoinExpr) (string, error) {
	// A template join wraps the for-loop of a %{for}...%{endfor} template
	// directive; render the underlying for-expression.
	return v.e.ExpToString(v.ctx, e.Tuple)
}
func (v *engineVisitor) VisitBinaryOp(e *hclsyntax.BinaryOpExpr) (string, error) {
	lhs, err := v.e.ExpToString(v.ctx, e.LHS)
	if err != nil {
		return "", err
	}
	rhs, err := v.e.ExpToString(v.ctx, e.RHS)
	if err != nil {
		return "", err
	}
	return lhs + " " + hclexpr.BinaryOpSymbol(e.Op) + " " + rhs, nil
}
func (v *engineVisitor) VisitUnaryOp(e *hclsyntax.UnaryOpExpr) (string, error) {
	valStr, err := v.e.ExpToString(v.ctx, e.Val)
	if err != nil {
		return "", err
	}
	return hclexpr.UnaryOpSymbol(e.Op) + valStr, nil
}
func (v *engineVisitor) VisitForExpr(e *hclsyntax.ForExpr) (string, error) {
	collStr, err := v.e.ExpToString(v.ctx, e.CollExpr)
	if err != nil {
		return "", err
	}
	valStr, err := v.e.ExpToString(v.ctx, e.ValExpr)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if e.KeyExpr != nil {
		keyStr, err := v.e.ExpToString(v.ctx, e.KeyExpr)
		if err != nil {
			return "", err
		}
		b.WriteString("{for ")
		b.WriteString(e.KeyVar)
		b.WriteString(", ")
		b.WriteString(e.ValVar)
		b.WriteString(" in ")
		b.WriteString(collStr)
		b.WriteString(" : ")
		b.WriteString(keyStr)
		b.WriteString(" => ")
		b.WriteString(valStr)
		if e.CondExpr != nil {
			condStr, err := v.e.ExpToString(v.ctx, e.CondExpr)
			if err != nil {
				return "", err
			}
			b.WriteString(" if ")
			b.WriteString(condStr)
		}
		b.WriteString("}")
	} else {
		b.WriteString("[for ")
		b.WriteString(e.ValVar)
		b.WriteString(" in ")
		b.WriteString(collStr)
		b.WriteString(" : ")
		b.WriteString(valStr)
		if e.CondExpr != nil {
			condStr, err := v.e.ExpToString(v.ctx, e.CondExpr)
			if err != nil {
				return "", err
			}
			b.WriteString(" if ")
			b.WriteString(condStr)
		}
		b.WriteString("]")
	}
	return b.String(), nil
}
func (v *engineVisitor) VisitSplatExpr(e *hclsyntax.SplatExpr) (string, error) {
	sourceStr, err := v.e.ExpToString(v.ctx, e.Source)
	if err != nil {
		return "", err
	}
	base := sourceStr + "[*]"
	// e.Each is a traversal rooted at the anonymous item symbol (which renders
	// as an empty string), so rendering it yields just the trailing traversal
	// (e.g. ".id" for var.list[*].id, or "" for a bare var.list[*]).
	if e.Each != nil && e.Each != e.Source {
		eachStr, err := v.e.ExpToString(v.ctx, e.Each)
		if err == nil {
			return base + eachStr, nil
		}
	}
	return base, nil
}
func (v *engineVisitor) VisitAnonSymbol(e *hclsyntax.AnonSymbolExpr) (string, error) {
	// The anonymous splat item renders as an empty string so that a trailing
	// traversal (e.g. .id) composes onto the splat base in VisitSplatExpr.
	return "", nil
}
func (v *engineVisitor) VisitExprSyntaxError(e *hclsyntax.ExprSyntaxError) (string, error) {
	return "", fmt.Errorf("can't convert invalid expression %T to string", e)
}
func (v *engineVisitor) VisitDefault(e hclsyntax.Expression) (string, error) {
	log := logger.FromContext(v.ctx)
	log.Error().Msgf("can't convert expression %T to string", e)
	return "", fmt.Errorf("can't convert expression %T to string", e)
}

func (e *Engine) expToStringLiteralValue(t *hclsyntax.LiteralValueExpr) (string, error) {
	s, err := ctyConvert.Convert(t.Val, cty.String)
	if err != nil {
		return "", err
	}
	return s.AsString(), nil
}

func (e *Engine) expToStringTemplateExpr(ctx context.Context, t *hclsyntax.TemplateExpr) (string, error) {
	if t.IsStringLiteral() {
		v, err := t.Value(nil)
		if err != nil {
			return "", err
		}
		return v.AsString(), nil
	}
	return e.buildString(ctx, t.Parts)
}

func (e *Engine) expToStringScopeTraversal(t *hclsyntax.ScopeTraversalExpr) string {
	items := evaluateScopeTraversalExpr(t.Traversal)
	return strings.Join(items, ".")
}

func (e *Engine) expToStringRelativeTraversal(ctx context.Context, t *hclsyntax.RelativeTraversalExpr) (string, error) {
	sourceStr, err := e.ExpToString(ctx, t.Source)
	if err != nil {
		return "", err
	}
	if len(t.Traversal) == 0 {
		return sourceStr, nil
	}
	return sourceStr + relativeTraversalToString(t.Traversal), nil
}

func (e *Engine) expToStringFunctionCall(ctx context.Context, t *hclsyntax.FunctionCallExpr) (string, error) {
	args := make([]string, 0, len(t.Args))
	for _, arg := range t.Args {
		s, err := e.ExpToString(ctx, arg)
		if err != nil {
			return "", err
		}
		args = append(args, s)
	}
	return t.Name + "(" + strings.Join(args, ", ") + ")", nil
}

func (e *Engine) expToStringConditionalExpr(ctx context.Context, t *hclsyntax.ConditionalExpr) (string, error) {
	condStr, err := e.ExpToString(ctx, t.Condition)
	if err != nil {
		return "", err
	}
	trueStr, err := e.ExpToString(ctx, t.TrueResult)
	if err != nil {
		return "", err
	}
	falseStr, err := e.ExpToString(ctx, t.FalseResult)
	if err != nil {
		return "", err
	}
	return condStr + " ? " + trueStr + " : " + falseStr, nil
}

func (e *Engine) expToStringTupleConsExpr(ctx context.Context, t *hclsyntax.TupleConsExpr) (string, error) {
	parts := make([]string, 0, len(t.Exprs))
	for _, ex := range t.Exprs {
		s, err := e.ExpToString(ctx, ex)
		if err != nil {
			return "", err
		}
		parts = append(parts, s)
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}

func (e *Engine) expToStringObjectConsExpr(ctx context.Context, t *hclsyntax.ObjectConsExpr) (string, error) {
	parts := make([]string, 0, len(t.Items))
	for _, item := range t.Items {
		keyStr, err := e.ExpToString(ctx, item.KeyExpr)
		if err != nil {
			return "", err
		}
		valStr, err := e.ExpToString(ctx, item.ValueExpr)
		if err != nil {
			return "", err
		}
		parts = append(parts, keyStr+": "+valStr)
	}
	return "{" + strings.Join(parts, ", ") + "}", nil
}

func (e *Engine) buildString(ctx context.Context, parts []hclsyntax.Expression) (string, error) {
	builder := &strings.Builder{}

	for _, part := range parts {
		s, err := e.ExpToString(ctx, part)
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

func (e *Engine) indexExprToString(ctx context.Context, t *hclsyntax.IndexExpr) (string, error) {
	if t == nil || t.Collection == nil || t.Key == nil {
		return "", fmt.Errorf("invalid IndexExpr: nil collection or key")
	}
	coll, err := e.ExpToString(ctx, t.Collection)
	if err != nil {
		return "", err
	}
	key, err := e.ExpToString(ctx, t.Key)
	if err != nil {
		return "", err
	}
	return coll + "[" + key + "]", nil
}

func evaluateScopeTraversalExpr(t hcl.Traversal) []string {
	items := make([]string, 0)
	for _, part := range t {
		switch tt := part.(type) {
		case hcl.TraverseAttr:
			items = append(items, tt.Name)
		case hcl.TraverseRoot:
			items = append(items, tt.Name)
		case hcl.TraverseIndex:
			switch tt.Key.Type() {
			case cty.Number:
				items = append(items, tt.Key.AsBigFloat().String())
			case cty.String:
				items = append(items, tt.Key.AsString())
			}
		}
	}
	return items
}

// relativeTraversalToString formats a relative traversal (e.g. .attr or [0]) so that
// TraverseAttr becomes ".name" and TraverseIndex becomes "[key]".
func relativeTraversalToString(t hcl.Traversal) string {
	var b strings.Builder
	for _, step := range t {
		switch s := step.(type) {
		case hcl.TraverseAttr:
			b.WriteString(".")
			b.WriteString(s.Name)
		case hcl.TraverseIndex:
			b.WriteString("[")
			switch s.Key.Type() {
			case cty.Number:
				b.WriteString(s.Key.AsBigFloat().String())
			case cty.String:
				b.WriteString(s.Key.AsString())
			}
			b.WriteString("]")
		}
	}
	return b.String()
}
