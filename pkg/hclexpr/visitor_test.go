/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package hclexpr

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// recordingVisitor records which Visit* method was called.
type recordingVisitor struct {
	called string
}

func (r *recordingVisitor) VisitLiteralValue(_ *hclsyntax.LiteralValueExpr) (string, error) {
	r.called = "LiteralValue"
	return r.called, nil
}
func (r *recordingVisitor) VisitTemplateExpr(_ *hclsyntax.TemplateExpr) (string, error) {
	r.called = "TemplateExpr"
	return r.called, nil
}
func (r *recordingVisitor) VisitScopeTraversal(_ *hclsyntax.ScopeTraversalExpr) (string, error) {
	r.called = "ScopeTraversal"
	return r.called, nil
}
func (r *recordingVisitor) VisitIndexExpr(_ *hclsyntax.IndexExpr) (string, error) {
	r.called = "IndexExpr"
	return r.called, nil
}
func (r *recordingVisitor) VisitRelativeTraversal(_ *hclsyntax.RelativeTraversalExpr) (string, error) {
	r.called = "RelativeTraversal"
	return r.called, nil
}
func (r *recordingVisitor) VisitFunctionCall(_ *hclsyntax.FunctionCallExpr) (string, error) {
	r.called = "FunctionCall"
	return r.called, nil
}
func (r *recordingVisitor) VisitConditional(_ *hclsyntax.ConditionalExpr) (string, error) {
	r.called = "Conditional"
	return r.called, nil
}
func (r *recordingVisitor) VisitTupleCons(_ *hclsyntax.TupleConsExpr) (string, error) {
	r.called = "TupleCons"
	return r.called, nil
}
func (r *recordingVisitor) VisitObjectCons(_ *hclsyntax.ObjectConsExpr) (string, error) {
	r.called = "ObjectCons"
	return r.called, nil
}
func (r *recordingVisitor) VisitTemplateJoin(_ *hclsyntax.TemplateJoinExpr) (string, error) {
	r.called = "TemplateJoin"
	return r.called, nil
}
func (r *recordingVisitor) VisitBinaryOp(_ *hclsyntax.BinaryOpExpr) (string, error) {
	r.called = "BinaryOp"
	return r.called, nil
}
func (r *recordingVisitor) VisitUnaryOp(_ *hclsyntax.UnaryOpExpr) (string, error) {
	r.called = "UnaryOp"
	return r.called, nil
}
func (r *recordingVisitor) VisitForExpr(_ *hclsyntax.ForExpr) (string, error) {
	r.called = "ForExpr"
	return r.called, nil
}
func (r *recordingVisitor) VisitSplatExpr(_ *hclsyntax.SplatExpr) (string, error) {
	r.called = "SplatExpr"
	return r.called, nil
}
func (r *recordingVisitor) VisitAnonSymbol(_ *hclsyntax.AnonSymbolExpr) (string, error) {
	r.called = "AnonSymbol"
	return r.called, nil
}
func (r *recordingVisitor) VisitExprSyntaxError(_ *hclsyntax.ExprSyntaxError) (string, error) {
	r.called = "ExprSyntaxError"
	return r.called, nil
}
func (r *recordingVisitor) VisitDefault(_ hclsyntax.Expression) (string, error) {
	r.called = "Default"
	return r.called, nil
}

func TestDispatch(t *testing.T) {
	parse := func(t *testing.T, src string) hclsyntax.Expression {
		t.Helper()
		expr, diags := hclsyntax.ParseExpression([]byte(src), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse %q failed: %v", src, diags)
		}
		return expr
	}

	tests := []struct {
		name string
		src  string
		want string
	}{
		{"LiteralValue", `42`, "LiteralValue"},
		{"ScopeTraversal", `var.x`, "ScopeTraversal"},
		{"TemplateExpr", `"hello ${var.x} world"`, "TemplateExpr"},
		{"IndexExpr", `list[var.i]`, "IndexExpr"},
		{"RelativeTraversal", `list[var.i].name`, "RelativeTraversal"},
		{"FunctionCall", `upper("x")`, "FunctionCall"},
		{"Conditional", `true ? 1 : 2`, "Conditional"},
		{"TupleCons", `[1, 2]`, "TupleCons"},
		{"ObjectCons", `{a = 1}`, "ObjectCons"},
		{"TemplateJoin", ``, "TemplateJoin"}, // no parseable src; expr built in loop below
		{"BinaryOp", `1 + 2`, "BinaryOp"},
		{"UnaryOp", `-1`, "UnaryOp"},
		{"ForExpr", `[for x in var.list : x]`, "ForExpr"},
		{"SplatExpr", `var.list[*]`, "SplatExpr"},
		{"AnonSymbol", ``, "AnonSymbol"},           // synthetic; expr built in loop below
		{"ExprSyntaxError", ``, "ExprSyntaxError"}, // synthetic; expr built in loop below
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expr hclsyntax.Expression
			switch tt.name {
			case "TemplateJoin":
				forExpr, diags := hclsyntax.ParseExpression([]byte(`[for x in var.list : x]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
				if diags.HasErrors() {
					t.Fatalf("parse for-expr failed: %v", diags)
				}
				expr = &hclsyntax.TemplateJoinExpr{Tuple: forExpr}
			case "AnonSymbol":
				expr = &hclsyntax.AnonSymbolExpr{}
			case "ExprSyntaxError":
				expr = &hclsyntax.ExprSyntaxError{}
			default:
				expr = parse(t, tt.src)
			}
			v := &recordingVisitor{}
			got, err := Dispatch[string](expr, v)
			if err != nil {
				t.Fatalf("Dispatch error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Dispatch returned %q, want %q", got, tt.want)
			}
			if v.called != tt.want {
				t.Errorf("visitor called %q, want %q", v.called, tt.want)
			}
		})
	}
}

func TestDispatch_UnwrapsBeforeDispatch(t *testing.T) {
	parse := func(t *testing.T, src string) hclsyntax.Expression {
		t.Helper()
		expr, diags := hclsyntax.ParseExpression([]byte(src), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse %q failed: %v", src, diags)
		}
		return expr
	}

	tests := []struct {
		name string
		src  string
		want string
	}{
		{"TemplateWrapExpr_unwraps", `"${var.x}"`, "ScopeTraversal"},
		{"ParenthesesExpr_unwraps", `(var.x)`, "ScopeTraversal"},
		{"nested_unwrap", `"${(var.x)}"`, "ScopeTraversal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := parse(t, tt.src)
			v := &recordingVisitor{}
			got, err := Dispatch[string](expr, v)
			if err != nil {
				t.Fatalf("Dispatch error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Dispatch returned %q, want %q", got, tt.want)
			}
			if v.called != tt.want {
				t.Errorf("visitor called %q, want %q", v.called, tt.want)
			}
		})
	}
}

func TestDispatch_UnknownExprType(t *testing.T) {
	// A wrapper with no inner expression unwraps to nil, which no case matches,
	// so Dispatch must fall through to VisitDefault. (A custom hclsyntax.Expression
	// cannot be constructed outside the package, and every concrete exported type
	// is now handled explicitly.)
	expr := &hclsyntax.ParenthesesExpr{}
	v := &recordingVisitor{}
	got, _ := Dispatch[string](expr, v)
	if got != "Default" {
		t.Errorf("got %q, want Default", got)
	}
	if v.called != "Default" {
		t.Errorf("visitor called %q, want Default", v.called)
	}
}
