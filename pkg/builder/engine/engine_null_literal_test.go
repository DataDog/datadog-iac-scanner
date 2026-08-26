/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"testing"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// A null or unknown literal converts to cty.String without error but cannot be
// read with AsString. ExpToString has to report that as an error, because it
// runs under a per-directory singleflight: a panic there aborts the resolve for
// every file in the directory, not just the expression that caused it.
func TestExpToString_NullAndUnknownLiteralsReturnError(t *testing.T) {
	cases := []struct {
		name string
		val  cty.Value
	}{
		{"null string", cty.NullVal(cty.String)},
		{"null number", cty.NullVal(cty.Number)},
		{"null bool", cty.NullVal(cty.Bool)},
		{"null dynamic", cty.NullVal(cty.DynamicPseudoType)},
		{"unknown string", cty.UnknownVal(cty.String)},
		{"unknown dynamic", cty.UnknownVal(cty.DynamicPseudoType)},
	}

	e := &Engine{}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expr := &hclsyntax.LiteralValueExpr{Val: tc.val}
			got, err := e.ExpToString(ctx, expr)
			if err == nil {
				t.Fatalf("ExpToString(%s) = %q, want an error rather than a panic", tc.name, got)
			}
			if got != "" {
				t.Fatalf("ExpToString(%s) = %q, want the empty string alongside the error", tc.name, got)
			}
		})
	}
}

// Known literals must keep converting exactly as before.
func TestExpToString_KnownLiteralsStillConvert(t *testing.T) {
	cases := []struct {
		name string
		val  cty.Value
		want string
	}{
		{"string", cty.StringVal("hello"), "hello"},
		{"number", cty.NumberIntVal(42), "42"},
		{"bool", cty.BoolVal(true), "true"},
		{"empty string", cty.StringVal(""), ""},
	}

	e := &Engine{}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expr := &hclsyntax.LiteralValueExpr{Val: tc.val}
			got, err := e.ExpToString(ctx, expr)
			if err != nil {
				t.Fatalf("ExpToString(%s) returned error %v", tc.name, err)
			}
			if got != tc.want {
				t.Fatalf("ExpToString(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}
