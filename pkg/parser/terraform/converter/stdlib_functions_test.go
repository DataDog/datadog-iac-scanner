package converter_test

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

func TestStdlibFunctionEvaluation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		attr  string
		want  cty.Value
	}{
		{
			name:  "length string",
			input: `block "t" { n = length("hello") }`,
			attr:  "n",
			want:  cty.NumberIntVal(5),
		},
		{
			name:  "coalesce empty string",
			input: `block "t" { n = coalesce("", "kept") }`,
			attr:  "n",
			want:  cty.StringVal("kept"),
		},
		{
			name:  "lookup default",
			input: `block "t" { n = lookup({a = "x"}, "b", "d") }`,
			attr:  "n",
			want:  cty.StringVal("d"),
		},
		{
			name:  "index",
			input: `block "t" { n = index(["a", "b"], "b") }`,
			attr:  "n",
			want:  cty.NumberIntVal(1),
		},
		{
			name:  "replace",
			input: `block "t" { n = replace("a-b", "-", "_") }`,
			attr:  "n",
			want:  cty.StringVal("a_b"),
		},
		{
			name:  "tostring",
			input: `block "t" { n = tostring(5) }`,
			attr:  "n",
			want:  cty.StringVal("5"),
		},
		{
			name:  "try fallback",
			input: `block "t" { n = try(var.missing, "fallback") }`,
			attr:  "n",
			want:  cty.StringVal("fallback"),
		},
		{
			name:  "can unknown",
			input: `block "t" { n = can(var.missing) }`,
			attr:  "n",
			want:  cty.False,
		},
		{
			name:  "yamldecode",
			input: "block \"t\" { n = yamldecode(\"a: 1\\n\") }",
			attr:  "n",
			want:  cty.ObjectVal(map[string]cty.Value{"a": cty.NumberIntVal(1)}),
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file, diags := hclsyntax.ParseConfig([]byte(tt.input), "test.tf", hcl.Pos{Byte: 0, Line: 1, Column: 1})
			if diags.HasErrors() {
				t.Fatalf("parse: %v", diags)
			}
			doc, err := converter.DefaultConverted(ctx, file, converter.VariableMap{})
			if err != nil {
				t.Fatal(err)
			}
			got, ok := doc["block"].(model.Document)["t"].(model.Document)[tt.attr].(ctyjson.SimpleJSONValue)
			if !ok {
				t.Fatalf("attr %s = %#v, want evaluated cty value", tt.attr, doc["block"].(model.Document)["t"].(model.Document)[tt.attr])
			}
			if !got.Value.RawEquals(tt.want) {
				t.Fatalf("got %#v, want %#v", got.Value, tt.want)
			}
		})
	}
}

func TestTryCanDoNotAssumeUnsetRequiredInput(t *testing.T) {
	t.Parallel()

	vars := converter.VariableMap{
		"var": cty.ObjectVal(map[string]cty.Value{
			"required": cty.UnknownVal(cty.DynamicPseudoType),
		}),
	}
	tests := []struct {
		name  string
		input string
	}{
		{name: "try", input: `block "t" { n = try(var.required, false) }`},
		{name: "can", input: `block "t" { n = can(var.required) }`},
	}
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file, diags := hclsyntax.ParseConfig([]byte(tt.input), "test.tf", hcl.Pos{Byte: 0, Line: 1, Column: 1})
			if diags.HasErrors() {
				t.Fatalf("parse: %v", diags)
			}
			doc, err := converter.DefaultConverted(ctx, file, vars)
			if err != nil {
				t.Fatal(err)
			}
			got := doc["block"].(model.Document)["t"].(model.Document)["n"]
			if val, ok := got.(ctyjson.SimpleJSONValue); ok && val.Value.IsWhollyKnown() {
				t.Fatalf("got known %#v, want unresolved interpolation for unset required input", val.Value)
			}
		})
	}
}
