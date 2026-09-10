package converter_test

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

func TestFileFunctionEvaluation(t *testing.T) {
	t.Parallel()

	fsys := vfs.NewMemFS(map[string][]byte{
		"mod/note.txt": []byte("hello"),
	})
	input := `block "t" { n = file("note.txt") }`
	file, diags := hclsyntax.ParseConfig([]byte(input), "main.tf", hcl.Pos{Byte: 0, Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse: %v", diags)
	}
	doc, err := converter.Convert(context.Background(), file, converter.VariableMap{}, converter.Options{
		BaseDir: "mod",
		FS:      fsys,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := doc["block"].(model.Document)["t"].(model.Document)["n"].(ctyjson.SimpleJSONValue)
	if !ok {
		t.Fatalf("attr = %#v", doc["block"].(model.Document)["t"].(model.Document)["n"])
	}
	if !got.Value.RawEquals(cty.StringVal("hello")) {
		t.Fatalf("got %#v", got.Value)
	}
}

func TestFileFunctionEscapeWraps(t *testing.T) {
	t.Parallel()

	fsys := vfs.NewMemFS(map[string][]byte{
		"outside/secret": []byte("nope"),
		"mod/main.tf":    []byte(""),
	})
	input := `block "t" { n = file("../outside/secret") }`
	file, diags := hclsyntax.ParseConfig([]byte(input), "main.tf", hcl.Pos{Byte: 0, Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse: %v", diags)
	}
	doc, err := converter.Convert(context.Background(), file, converter.VariableMap{}, converter.Options{
		BaseDir: "mod",
		FS:      fsys,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := doc["block"].(model.Document)["t"].(model.Document)["n"]
	s, ok := got.(string)
	if !ok {
		t.Fatalf("expected wrapped string, got %#v", got)
	}
	if s != `${file("../outside/secret")}` {
		t.Fatalf("wrap = %q", s)
	}
}
