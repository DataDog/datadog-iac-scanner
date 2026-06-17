/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestCtyValueToDocument(t *testing.T) {
	tests := []struct {
		name  string
		value cty.Value
		want  interface{}
	}{
		{"string", cty.StringVal("hello"), "hello"},
		{"bool", cty.True, true},
		{"number", cty.NumberIntVal(42), json.Number("42")},
		{"null", cty.NullVal(cty.String), nil},
		{"unknown", cty.UnknownVal(cty.DynamicPseudoType), UnknownAttributePlaceholder},
		{
			"list",
			cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}),
			[]interface{}{"a", "b"},
		},
		{
			"object",
			cty.ObjectVal(map[string]cty.Value{"enabled": cty.True}),
			map[string]interface{}{"enabled": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ctyValueToDocument(tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestAttributesToDocumentPreservesUnknownKeys(t *testing.T) {
	r := ResolvedResource{
		Attributes: map[string]cty.Value{
			"bucket": cty.StringVal("my-bucket"),
			"acl":    cty.UnknownVal(cty.DynamicPseudoType),
		},
	}
	doc := AttributesToDocument(&r)
	if doc["bucket"] != "my-bucket" {
		t.Fatalf("bucket = %#v, want my-bucket", doc["bucket"])
	}
	if got, ok := doc["acl"]; !ok || got != UnknownAttributePlaceholder {
		t.Fatalf("unknown attribute acl = %#v, want %q", got, UnknownAttributePlaceholder)
	}
}

func TestCalledLocalDirs(t *testing.T) {
	root := t.TempDir()

	writeModule(t, root, "child", map[string]string{
		"main.tf": `resource "aws_s3_bucket" "this" { bucket = "x" }`,
	})
	rootDir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "child" {
  source = "../child"
}

module "remote" {
  source = "terraform-aws-modules/s3-bucket/aws"
}
`,
	})

	got := CalledLocalDirs(rootDir)
	want := []string{filepath.Join(root, "child")}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CalledLocalDirs = %#v, want %#v", got, want)
	}
}

func TestCalledLocalDirs_NoModules(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `resource "aws_s3_bucket" "this" { bucket = "x" }`,
	})
	if got := CalledLocalDirs(dir); got != nil {
		t.Fatalf("CalledLocalDirs = %#v, want nil", got)
	}
}
