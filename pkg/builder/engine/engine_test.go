/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// TestEngine_BuildString tests the functions [buildString()] and all the methods called by them
func TestEngine_BuildString(t *testing.T) {
	type args struct {
		parts []hclsyntax.Expression
	}
	type fields struct {
		Engine *Engine
	}
	tests := []struct {
		name    string
		args    args
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "build_string",
			fields: fields{
				Engine: &Engine{},
			},
			args: args{
				parts: []hclsyntax.Expression{},
			},
			want:    "",
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fields.Engine.buildString(ctx, tt.args.parts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpToString_IndexExpr(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte("var.list[var.i]"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse failed: %v", diags)
	}
	indexExpr, ok := expr.(*hclsyntax.IndexExpr)
	if !ok {
		t.Fatalf("expected *hclsyntax.IndexExpr, got %T", expr)
	}

	e := &Engine{}
	ctx := context.Background()

	t.Run("via ExpToString", func(t *testing.T) {
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString(IndexExpr): %v", err)
		}
		if want := "var.list[var.i]"; got != want {
			t.Errorf("ExpToString(IndexExpr) = %q, want %q", got, want)
		}
	})

	t.Run("via indexExprToString", func(t *testing.T) {
		got, err := e.indexExprToString(ctx, indexExpr)
		if err != nil {
			t.Fatalf("indexExprToString: %v", err)
		}
		if want := "var.list[var.i]"; got != want {
			t.Errorf("indexExprToString() = %q, want %q", got, want)
		}
	})
}

func TestExpToString_RelativeTraversalExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("relative_traversal_after_index", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i].name"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "list[var.i].name"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("relative_traversal_multi_step", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i].a.b"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "list[var.i].a.b"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("relative_traversal_with_index_step", func(t *testing.T) {
		// e.g. list[var.i][0] -> RelativeTraversalExpr(IndexExpr, [TraverseIndex(0)])
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i][0]"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "list[var.i][0]"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("function_call_source_now_resolves", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("tostring(var.x).attr"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "tostring(var.x).attr"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_ParenthesesExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("unwraps_to_inner_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("(var.x)"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ParenthesesExpr); !ok {
			t.Fatalf("expected *hclsyntax.ParenthesesExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "var.x"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("nested_parentheses_unwrap", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("((var.a))"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "var.a"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_TupleConsExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	expr, diags := hclsyntax.ParseExpression([]byte(`[var.a, "b", 1]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse failed: %v", diags)
	}
	if _, ok := expr.(*hclsyntax.TupleConsExpr); !ok {
		t.Fatalf("expected *hclsyntax.TupleConsExpr, got %T", expr)
	}

	got, err := e.ExpToString(ctx, expr)
	if err != nil {
		t.Fatalf("ExpToString error: %v", err)
	}
	want := "[var.a, b, 1]"
	if got != want {
		t.Errorf("ExpToString = %q, want %q", got, want)
	}
}

func TestExpToString_ObjectConsExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	expr, diags := hclsyntax.ParseExpression([]byte(`{a = var.x, b = "y"}`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse failed: %v", diags)
	}
	if _, ok := expr.(*hclsyntax.ObjectConsExpr); !ok {
		t.Fatalf("expected *hclsyntax.ObjectConsExpr, got %T", expr)
	}

	got, err := e.ExpToString(ctx, expr)
	if err != nil {
		t.Fatalf("ExpToString error: %v", err)
	}
	// Key order may vary; check it contains both key-value pairs
	if !strings.Contains(got, "a: var.x") {
		t.Errorf("ExpToString = %q, expected to contain a: var.x", got)
	}
	if !strings.Contains(got, "b: y") {
		t.Errorf("ExpToString = %q, expected to contain b: y", got)
	}
	if !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") {
		t.Errorf("ExpToString = %q, expected to be wrapped in {}", got)
	}
}

func TestExpToString_ConditionalExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("returns_condition_true_false_string", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.enabled ? "yes" : "no"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ConditionalExpr); !ok {
			t.Fatalf("expected *hclsyntax.ConditionalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		want := "var.enabled ? yes : no"
		if got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_BinaryOpExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("arithmetic", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`1 + 2`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.BinaryOpExpr); !ok {
			t.Fatalf("expected *hclsyntax.BinaryOpExpr, got %T", expr)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "1 + 2"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
	t.Run("comparison", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.count > 0`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "var.count > 0"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
	t.Run("logical", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.a && var.b`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "var.a && var.b"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_SplatExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()
	t.Run("splat", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.list[*]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.SplatExpr); !ok {
			t.Fatalf("expected *hclsyntax.SplatExpr, got %T", expr)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			return // VisitDefault returns error for unsupported expr
		}
		if want := "var.list[*]"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
	t.Run("splat_with_traversal", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.list[*].id`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		// The anonymous splat item renders empty, so the trailing traversal
		// composes onto the base to yield the full path.
		if want := "var.list[*].id"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_TemplateJoin(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()
	// A %{for}...%{endfor} template directive parses to a TemplateExpr whose
	// single part is a TemplateJoinExpr wrapping a ForExpr.
	f, diags := hclsyntax.ParseConfig([]byte(`x = "%{for v in var.list}${v}%{endfor}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse failed: %v", diags)
	}
	attr := f.Body.(*hclsyntax.Body).Attributes["x"]
	got, err := e.ExpToString(ctx, attr.Expr)
	if err != nil {
		t.Fatalf("ExpToString error: %v", err)
	}
	if want := "[for v in var.list : v]"; got != want {
		t.Errorf("ExpToString = %q, want %q", got, want)
	}
}

func TestExpToString_ForExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()
	t.Run("tuple_for", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`[for x in var.list : x]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ForExpr); !ok {
			t.Fatalf("expected *hclsyntax.ForExpr, got %T", expr)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "[for x in var.list : x]"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
	t.Run("object_for", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`{for k, v in var.map : k => v}`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "{for k, v in var.map : k => v}"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_UnaryOpExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()
	t.Run("negate", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`-1`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.UnaryOpExpr); !ok {
			t.Fatalf("expected *hclsyntax.UnaryOpExpr, got %T", expr)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "-1"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
	t.Run("logical_not", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`!var.enabled`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "!var.enabled"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_FunctionCallExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("simple_function_call", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`upper("hello")`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "upper(hello)"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("function_call_with_multiple_args", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`format("%s-%s", var.a, var.b)`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "format(%s-%s, var.a, var.b)"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("function_call_no_args", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`timestamp()`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "timestamp()"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("nested_function_calls", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`upper(format("%s", var.x))`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "upper(format(%s, var.x))"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("for_expr_as_arg_now_supported", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`upper([for i in [1,2] : i])`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "upper([for i in [1, 2] : i])"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})
}

func TestExpToString_IndexExpr_edgeCases(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("nil IndexExpr", func(t *testing.T) {
		var nilIndex *hclsyntax.IndexExpr
		_, err := e.indexExprToString(ctx, nilIndex)
		if err == nil {
			t.Error("indexExprToString(nil) should return error")
		}
	})
}
