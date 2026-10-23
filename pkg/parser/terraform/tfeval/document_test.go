/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
			got := ctyValueToDocument(tt.value, &attrSource{}, nil)
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
	// Not a reference, so it stands as its own text, as the plain parser has it.
	if got := doc["computed"]; got != "${timestamp()}" {
		t.Errorf("computed = %#v, want ${timestamp()}", got)
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

	got := CalledLocalDirs(rootDir, nil)
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
	if got := CalledLocalDirs(dir, nil); got != nil {
		t.Fatalf("CalledLocalDirs = %#v, want nil", got)
	}
}

// An expanded dynamic block must not stand in for the as-written one that shares
// its key: the as-written block's references stay unresolved, with their text.
func TestAttributesToDocument_ExpandedSiblingDoesNotMapAsWritten(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = var.unknown
    content {
      cidr_blocks = [aws_vpc.unknown.cidr_block]
    }
  }
  dynamic "ingress" {
    for_each = ["a"]
    content {
      cidr_blocks = [aws_vpc.known.cidr_block]
    }
  }
}
`,
	})
	doc := documentFor(t, dir, "aws_security_group", "sg")
	kept := fmt.Sprint(doc["dynamic"])
	if !strings.Contains(kept, "${aws_vpc.unknown.cidr_block}") {
		t.Fatalf("as-written block lost its reference text: dynamic = %v", doc["dynamic"])
	}
}

// A dynamic block's content is evaluated with its loop variable bound, but the
// renderer's context binds no iterator. Rendering a partly known value through
// that context would re-derive the parts evaluation had resolved as their text,
// so an expression reading the iterator is walked by element instead: known
// elements keep their values and only the unknown ones recover their reference.
func TestAttributesToDocumentKeepsKnownValuesInDynamicContent(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "extra" {}

resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [{ cidr = "0.0.0.0/0" }]
    content {
      cidr_blocks = [ingress.value.cidr, var.extra]
    }
  }
}
`})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": `
module "c" {
  source = "../child"
}
`})

	doc := documentFor(t, dir, "aws_security_group", "sg")
	// One generated block collapses to an object, as a block written once would.
	ingress, ok := doc["ingress"].(map[string]interface{})
	if !ok {
		t.Fatalf("ingress = %#v, want an object", doc["ingress"])
	}
	cidr, ok := ingress["cidr_blocks"].([]interface{})
	if !ok {
		t.Fatalf("cidr_blocks = %#v, want a list", ingress["cidr_blocks"])
	}
	want := []interface{}{"0.0.0.0/0", "${var.extra}"}
	if !reflect.DeepEqual(cidr, want) {
		t.Errorf("cidr_blocks = %#v, want %#v", cidr, want)
	}
}

// The iterator walk also reaches values under the nested blocks of generated
// content, so a policy statement keeps the principal evaluation resolved next
// to the reference of the one it did not.
func TestAttributesToDocumentKeepsKnownPrincipalsInDynamicStatement(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "extra" {}

data "aws_iam_policy_document" "p" {
  dynamic "statement" {
    for_each = [{ principal = "arn:aws:iam::123456789012:root" }]
    content {
      effect  = "Allow"
      actions = ["sqs:*"]
      principals {
        type        = "AWS"
        identifiers = [statement.value.principal, var.extra]
      }
    }
  }
}
`})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": `
module "c" {
  source = "../child"
}
`})

	doc := documentFor(t, dir, "aws_iam_policy_document", "p")
	// One generated block collapses to an object, as a block written once would.
	st, ok := doc["statement"].(map[string]interface{})
	if !ok {
		t.Fatalf("statement = %#v, want an object", doc["statement"])
	}
	// One nested block collapses to an object, as a block written once would.
	principals, ok := st["principals"].(map[string]interface{})
	if !ok {
		t.Fatalf("principals = %#v, want an object", st["principals"])
	}
	identifiers, ok := principals["identifiers"].([]interface{})
	if !ok {
		t.Fatalf("identifiers = %#v, want a list", principals["identifiers"])
	}
	want := []interface{}{"arn:aws:iam::123456789012:root", "${var.extra}"}
	if !reflect.DeepEqual(identifiers, want) {
		t.Errorf("identifiers = %#v, want %#v", identifiers, want)
	}
}

// Iterator names also propagate through the nested values of generated
// content: an object or list one level under a dynamic attribute keeps its
// known elements next to the reference of the ones it did not resolve.
func TestAttributesToDocumentKeepsKnownValuesInNestedDynamicContent(t *testing.T) {
	cases := map[string]string{
		"object": `rule = { cidrs = [ingress.value.cidr, var.extra] }`,
		"list":   `rule = [[ingress.value.cidr, var.extra]]`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeModule(t, root, "child", map[string]string{"main.tf": `
variable "extra" {}

resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [{ cidr = "0.0.0.0/0" }]
    content {
      ` + content + `
    }
  }
}
`})
			dir := writeModule(t, root, "root", map[string]string{"main.tf": `
module "c" {
  source = "../child"
}
`})

			doc := documentFor(t, dir, "aws_security_group", "sg")
			ingress, ok := doc["ingress"].(map[string]interface{})
			if !ok {
				t.Fatalf("ingress = %#v, want an object", doc["ingress"])
			}
			rule, ok := ingress["rule"]
			if !ok {
				t.Fatalf("rule missing from %#v", ingress)
			}
			if name == "object" {
				obj, ok := rule.(map[string]interface{})
				if !ok {
					t.Fatalf("rule = %#v, want an object", rule)
				}
				cidrs, ok := obj["cidrs"].([]interface{})
				if !ok {
					t.Fatalf("cidrs = %#v, want a list", obj["cidrs"])
				}
				want := []interface{}{"0.0.0.0/0", "${var.extra}"}
				if !reflect.DeepEqual(cidrs, want) {
					t.Errorf("cidrs = %#v, want %#v", cidrs, want)
				}
				return
			}
			outer, ok := rule.([]interface{})
			if !ok {
				t.Fatalf("rule = %#v, want a list", rule)
			}
			if len(outer) != 1 {
				t.Fatalf("rule = %#v, want one element", rule)
			}
			inner, ok := outer[0].([]interface{})
			if !ok {
				t.Fatalf("rule[0] = %#v, want a list", outer[0])
			}
			want := []interface{}{"0.0.0.0/0", "${var.extra}"}
			if !reflect.DeepEqual(inner, want) {
				t.Errorf("rule[0] = %#v, want %#v", inner, want)
			}
		})
	}
}

// A for expression whose result is partly known is walked element by element
// instead of rendered from source text: the known elements survive next to the
// reference of the ones evaluation could not resolve.
func TestAttributesToDocumentKeepsKnownElementsInForExpression(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "items" {
  default = [{ k = "a" }, { k = "b" }]
}

variable "extra" {}

resource "aws_security_group" "sg" {
  ingress {
    ids = [for it in var.items : it.k == "a" ? var.extra : it.k]
  }
}
`})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": `
module "c" {
  source = "../child"
}
`})

	doc := documentFor(t, dir, "aws_security_group", "sg")
	ingress, ok := doc["ingress"].(map[string]interface{})
	if !ok {
		t.Fatalf("ingress = %#v, want an object", doc["ingress"])
	}
	ids, ok := ingress["ids"].([]interface{})
	if !ok {
		t.Fatalf("ids = %#v, want a list", ingress["ids"])
	}
	// A for result has no per-element source expression, so the unknown element
	// renders as the placeholder while the known one keeps its value.
	want := []interface{}{"${__dd_unknown__}", "b"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("ids = %#v, want %#v", ids, want)
	}
}

func TestNumberTextMatchesBigFloatText(t *testing.T) {
	for _, f := range []*big.Float{
		big.NewFloat(0), new(big.Float).Neg(big.NewFloat(0)), big.NewFloat(63), big.NewFloat(-7), big.NewFloat(1.5),
		big.NewFloat(1e30), new(big.Float).SetInt64(math.MaxInt64), new(big.Float).SetInt64(math.MinInt64),
		new(big.Float).SetPrec(512).SetFloat64(0.1),
	} {
		if got, want := numberText(f), f.Text('f', -1); got != want {
			t.Errorf("numberText(%v) = %q, want %q", f, got, want)
		}
	}
}
