/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package hclexpr

import (
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Visitor is the interface for handling each HCL expression type in one place.
// Implement this interface for each dispatch site (engine, inspector, modules, converter).
// Adding a new expression type: add a method here and a case in Dispatch below.
type Visitor[T any] interface {
	VisitLiteralValue(e *hclsyntax.LiteralValueExpr) (T, error)
	VisitTemplateExpr(e *hclsyntax.TemplateExpr) (T, error)
	VisitScopeTraversal(e *hclsyntax.ScopeTraversalExpr) (T, error)
	VisitIndexExpr(e *hclsyntax.IndexExpr) (T, error)
	VisitRelativeTraversal(e *hclsyntax.RelativeTraversalExpr) (T, error)
	VisitFunctionCall(e *hclsyntax.FunctionCallExpr) (T, error)
	VisitConditional(e *hclsyntax.ConditionalExpr) (T, error)
	VisitTupleCons(e *hclsyntax.TupleConsExpr) (T, error)
	VisitObjectCons(e *hclsyntax.ObjectConsExpr) (T, error)
	VisitTemplateJoin(e *hclsyntax.TemplateJoinExpr) (T, error)
	VisitBinaryOp(e *hclsyntax.BinaryOpExpr) (T, error)
	VisitUnaryOp(e *hclsyntax.UnaryOpExpr) (T, error)
	VisitForExpr(e *hclsyntax.ForExpr) (T, error)
	VisitSplatExpr(e *hclsyntax.SplatExpr) (T, error)
	// VisitAnonSymbol handles the synthetic placeholder for the current item
	// inside a splat's Each expression (e.g. the item in var.list[*].id).
	VisitAnonSymbol(e *hclsyntax.AnonSymbolExpr) (T, error)
	// VisitExprSyntaxError handles the placeholder produced for invalid or
	// incomplete expressions that could not be parsed.
	VisitExprSyntaxError(e *hclsyntax.ExprSyntaxError) (T, error)
	VisitDefault(e hclsyntax.Expression) (T, error)
}

// Dispatch unwraps expr then dispatches to the appropriate Visitor method.
// Add new expression types here (or in dispatchComposite) and to the Visitor
// interface so all sites stay in sync. The dispatch is split across two
// functions purely to keep each below the cyclomatic complexity limit.
func Dispatch[T any](expr hclsyntax.Expression, v Visitor[T]) (T, error) {
	expr = Unwrap(expr)
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		return v.VisitLiteralValue(e)
	case *hclsyntax.TemplateExpr:
		return v.VisitTemplateExpr(e)
	case *hclsyntax.ScopeTraversalExpr:
		return v.VisitScopeTraversal(e)
	case *hclsyntax.IndexExpr:
		return v.VisitIndexExpr(e)
	case *hclsyntax.RelativeTraversalExpr:
		return v.VisitRelativeTraversal(e)
	case *hclsyntax.FunctionCallExpr:
		return v.VisitFunctionCall(e)
	case *hclsyntax.ConditionalExpr:
		return v.VisitConditional(e)
	default:
		return dispatchComposite(expr, v)
	}
}

// dispatchComposite handles the composite, operator, and synthetic expression
// types. It receives an already-unwrapped expression from Dispatch.
func dispatchComposite[T any](expr hclsyntax.Expression, v Visitor[T]) (T, error) {
	switch e := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		return v.VisitTupleCons(e)
	case *hclsyntax.ObjectConsExpr:
		return v.VisitObjectCons(e)
	case *hclsyntax.TemplateJoinExpr:
		return v.VisitTemplateJoin(e)
	case *hclsyntax.BinaryOpExpr:
		return v.VisitBinaryOp(e)
	case *hclsyntax.UnaryOpExpr:
		return v.VisitUnaryOp(e)
	case *hclsyntax.ForExpr:
		return v.VisitForExpr(e)
	case *hclsyntax.SplatExpr:
		return v.VisitSplatExpr(e)
	case *hclsyntax.AnonSymbolExpr:
		return v.VisitAnonSymbol(e)
	case *hclsyntax.ExprSyntaxError:
		return v.VisitExprSyntaxError(e)
	default:
		return v.VisitDefault(expr)
	}
}
