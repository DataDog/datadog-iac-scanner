/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
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
			got := ctyValueToDocument(tt.value, attrSource{})
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

// documentFor evaluates dir and returns the document of one resolved resource.
func documentFor(t *testing.T, dir, typ, name string) map[string]interface{} {
	t.Helper()
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, typ, name)
	return AttributesToDocument(&r)
}

func TestAttributesToDocumentKeepsReferenceText(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.target.id
  target_bucket = aws_s3_bucket.logs.bucket
  keys          = [aws_kms_key.a.arn, "literal-key"]
  indexed       = aws_subnet.private[0].id
  computed      = timestamp()

  rule {
    role_arn = aws_iam_role.replication.arn
  }
}
`,
	})

	doc := documentFor(t, dir, "aws_s3_bucket_logging", "this")

	// A reference to a resource outside the module stays unresolved, but the
	// reference text is what lets rules associate the two resources.
	if got := doc["bucket"]; got != "${aws_s3_bucket.target.id}" {
		t.Errorf("bucket = %#v, want ${aws_s3_bucket.target.id}", got)
	}
	// A reference that does resolve keeps its resolved value.
	if got := doc["target_bucket"]; got != "logs" {
		t.Errorf("target_bucket = %#v, want logs", got)
	}
	// A list is unknown as a whole once one element is, so the resolvable
	// elements have to survive alongside the recovered reference.
	want := []interface{}{"${aws_kms_key.a.arn}", "literal-key"}
	if got := doc["keys"]; !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %#v, want %#v", got, want)
	}
	if got := doc["indexed"]; got != "${aws_subnet.private[0].id}" {
		t.Errorf("indexed = %#v, want ${aws_subnet.private[0].id}", got)
	}
	// Not a reference, so there is nothing to recover.
	if got := doc["computed"]; got != UnknownAttributePlaceholder {
		t.Errorf("computed = %#v, want %q", got, UnknownAttributePlaceholder)
	}

	rules, ok := doc["rule"].(map[string]interface{})
	if !ok {
		t.Fatalf("rule = %#v, want object", doc["rule"])
	}
	if got := rules["role_arn"]; got != "${aws_iam_role.replication.arn}" {
		t.Errorf("rule.role_arn = %#v, want ${aws_iam_role.replication.arn}", got)
	}
}

// Reference text is recovered only when building the document, so a resource
// that reads an unresolved attribute of a sibling reports its own reference
// rather than inheriting the sibling's.
func TestAttributesToDocumentReferenceTextDoesNotChain(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "a" {
  bucket = var.never_set
}

resource "aws_s3_bucket_versioning" "b" {
  bucket = aws_s3_bucket.a.bucket
}
`,
	})

	doc := documentFor(t, dir, "aws_s3_bucket_versioning", "b")
	if got := doc["bucket"]; got != "${aws_s3_bucket.a.bucket}" {
		t.Fatalf("bucket = %#v, want ${aws_s3_bucket.a.bucket}", got)
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
