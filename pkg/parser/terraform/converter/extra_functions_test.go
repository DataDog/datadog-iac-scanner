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

func TestExtraFunctionEvaluation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  cty.Value
	}{
		{name: "startswith", input: `block "t" { n = startswith("hello", "he") }`, want: cty.True},
		{name: "endswith", input: `block "t" { n = endswith("hello", "lo") }`, want: cty.True},
		{name: "strcontains", input: `block "t" { n = strcontains("hello", "ell") }`, want: cty.True},
		{name: "alltrue", input: `block "t" { n = alltrue([true, true]) }`, want: cty.True},
		{name: "anytrue", input: `block "t" { n = anytrue([false, true]) }`, want: cty.True},
		{name: "sum", input: `block "t" { n = sum([1, 2, 3]) }`, want: cty.NumberIntVal(6)},
		{name: "one", input: `block "t" { n = one(["only"]) }`, want: cty.StringVal("only")},
		{name: "cidrhost", input: `block "t" { n = cidrhost("10.0.0.0/24", 5) }`, want: cty.StringVal("10.0.0.5")},
		{name: "cidrnetmask", input: `block "t" { n = cidrnetmask("10.0.0.0/16") }`, want: cty.StringVal("255.255.0.0")},
		{name: "urlencode", input: `block "t" { n = urlencode("a b") }`, want: cty.StringVal("a+b")},
		{name: "md5", input: `block "t" { n = md5("hello") }`, want: cty.StringVal("5d41402abc4b2a76b9719d911017c592")},
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
			got, ok := doc["block"].(model.Document)["t"].(model.Document)["n"].(ctyjson.SimpleJSONValue)
			if !ok {
				t.Fatalf("attr = %#v", doc["block"].(model.Document)["t"].(model.Document)["n"])
			}
			if !got.Value.RawEquals(tt.want) {
				t.Fatalf("got %#v, want %#v", got.Value, tt.want)
			}
		})
	}
}
