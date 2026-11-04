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
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2/hclsyntax"
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

	rules := oneBlock(t, doc["rule"], "rule")
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

func TestCalledModuleDirsDoesNotFetchSkippedLocal(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"linked": "./missing",
		"main.tf": `module "local" { source = "./linked" }
module "remote" { source = "hashicorp/consul/aws" }`,
	})
	remoteDir := filepath.Join(root, "remote")
	calls := 0
	got := CalledModuleDirs(dir, func(source, _, _, _ string) (string, string, bool) {
		calls++
		if source != "hashicorp/consul/aws" {
			t.Errorf("skipped local source reached the remote resolver: %s", source)
		}
		return remoteDir, root, true
	}, vfs.DiskFS{})
	if calls != 1 || !reflect.DeepEqual(got, []string{remoteDir}) {
		t.Fatalf("called dirs = %v, remote calls = %d; want [%s], 1", got, calls, remoteDir)
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
	// One generated block is a one-element list, as a block written once is.
	ingress := oneBlock(t, doc["ingress"], "ingress")
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
	st := oneBlock(t, doc["statement"], "statement")
	principals := oneBlock(t, st["principals"], "principals")
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
			ingress := oneBlock(t, doc["ingress"], "ingress")
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
	ingress := oneBlock(t, doc["ingress"], "ingress")
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

func unknownsFor(t *testing.T, mainTF, typ, name string, withDoc bool) map[string]interface{} {
	t.Helper()
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": mainTF})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, typ, name)
	if withDoc {
		return Unknowns(&r, AttributesToDocument(&r))
	}
	return Unknowns(&r, nil)
}

func TestUnknownsRootVariableAndComputedAttribute(t *testing.T) {
	const mainTF = `
variable "unset" {}

resource "aws_route_table_association" "a" {
  name      = var.unset
  subnet_id = aws_subnet.s.id
  route     = "r"
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
  tags   = { a = "b" }
}
`
	for _, withDoc := range []bool{false, true} {
		want := map[string]interface{}{"name": true, "subnet_id": true}
		if got := unknownsFor(t, mainTF, "aws_route_table_association", "a", withDoc); !reflect.DeepEqual(got, want) {
			t.Errorf("withDoc=%v: unknown = %#v, want %#v", withDoc, got, want)
		}
		if got := unknownsFor(t, mainTF, "aws_s3_bucket", "b", withDoc); got != nil {
			t.Errorf("withDoc=%v: literal resource unknown = %#v, want nil", withDoc, got)
		}
	}
}

func TestUnknownsNestedBlockAndList(t *testing.T) {
	const mainTF = `
variable "unset" {}

resource "aws_security_group" "g" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    cidr_blocks = [var.unset, "10.0.0.0/8"]
  }
}
`
	want := map[string]interface{}{"ingress": []interface{}{
		map[string]interface{}{},
		map[string]interface{}{"cidr_blocks": []interface{}{true, false}},
	}}
	for _, withDoc := range []bool{false, true} {
		if got := unknownsFor(t, mainTF, "aws_security_group", "g", withDoc); !reflect.DeepEqual(got, want) {
			t.Errorf("withDoc=%v: unknown = %#v, want %#v", withDoc, got, want)
		}
	}
}

func TestUnknownsSingleNestedBlockFollowsDocument(t *testing.T) {
	const mainTF = `
variable "unset" {}

resource "aws_instance" "i" {
  ebs {
    size = var.unset
    type = "gp3"
  }
}
`
	want := map[string]interface{}{"ebs": []interface{}{map[string]interface{}{"size": true}}}
	if got := unknownsFor(t, mainTF, "aws_instance", "i", true); !reflect.DeepEqual(got, want) {
		t.Errorf("unknown = %#v, want %#v", got, want)
	}
}

func TestUnknownsKnownMapAndSetElementsInList(t *testing.T) {
	const mainTF = `
variable "unset" {}

resource "aws_s3_bucket" "b" {
  maps = [tomap({ a = "b" }), tomap({ a = var.unset })]
  sets = [toset(["a"]), toset([var.unset])]
}
`
	want := map[string]interface{}{
		"maps": []interface{}{map[string]interface{}{}, true},
		"sets": []interface{}{false, true},
	}
	if got := unknownsFor(t, mainTF, "aws_s3_bucket", "b", false); !reflect.DeepEqual(got, want) {
		t.Errorf("unknown = %#v, want %#v", got, want)
	}
}

// The meta-arguments are never listed as values; the placeholder of an
// unknown expansion reports its instance count as unknown.
func TestUnknownsOmitMetaArguments(t *testing.T) {
	const mainTF = `
variable "unset" {}

resource "aws_s3_bucket" "c" {
  count  = var.unset
  bucket = var.unset
}

resource "aws_s3_bucket" "f" {
  for_each = var.unset
  bucket   = "b"
}
`
	for _, withDoc := range []bool{false, true} {
		if got, want := unknownsFor(t, mainTF, "aws_s3_bucket", "c", withDoc), map[string]interface{}{"bucket": true, "count": true}; !reflect.DeepEqual(got, want) {
			t.Errorf("withDoc=%v: count unknown = %#v, want %#v", withDoc, got, want)
		}
		if got, want := unknownsFor(t, mainTF, "aws_s3_bucket", "f", withDoc), map[string]interface{}{"count": true}; !reflect.DeepEqual(got, want) {
			t.Errorf("withDoc=%v: for_each unknown = %#v, want %#v", withDoc, got, want)
		}
	}
}

func TestUnknownsRenderedTextIsWhole(t *testing.T) {
	const mainTF = `
variable "t" {}

resource "aws_s3_bucket" "b" {
  tags = merge(var.t, { a = "b" })
}

locals {
  t = { a = var.t, b = "b" }
}

resource "aws_s3_bucket" "c" {
  tags = coalesce(local.t, {})
}
`
	for _, name := range []string{"b", "c"} {
		got := unknownsFor(t, mainTF, "aws_s3_bucket", name, true)
		if want := map[string]interface{}{"tags": true}; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: unknown = %#v, want %#v", name, got, want)
		}
	}
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": mainTF})
	if got, want := documentFor(t, dir, "aws_s3_bucket", "c")["tags"], "${coalesce(local.t, {})}"; got != want {
		t.Errorf("c: tags = %#v, want %q", got, want)
	}
	unguided := map[string]interface{}{"tags": map[string]interface{}{"a": true}}
	if got := unknownsFor(t, mainTF, "aws_s3_bucket", "c", false); !reflect.DeepEqual(got, unguided) {
		t.Errorf("c without doc: unknown = %#v, want %#v", got, unguided)
	}
}

func TestUnknownsKnownVariableNotReported(t *testing.T) {
	const mainTF = `
variable "x" {
  default = "v"
}

resource "aws_s3_bucket" "b" {
  bucket = var.x
}
`
	if got := unknownsFor(t, mainTF, "aws_s3_bucket", "b", true); got != nil {
		t.Errorf("unknown = %#v, want nil", got)
	}
}

func TestRenderBodyModuleCall(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "m", map[string]string{"main.tf": "variable \"name\" {}\n"})
	writeModule(t, root, "env", map[string]string{"main.tf": `
variable "n" {}

module "m" {
  source = "../m"
  name   = var.n
  extra  = var.missing
  tags {
    owner = var.n
  }
}
`})
	e := New()
	if _, _, _, err := e.EvaluateModule(context.Background(), filepath.Join(root, "env"), map[string]cty.Value{"n": cty.StringVal("x")}); err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	scope := e.TakeRootScope()
	if scope == nil {
		t.Fatal("TakeRootScope = nil, want the root scope")
	}
	if again := e.TakeRootScope(); again != nil {
		t.Fatalf("second TakeRootScope = %p, want nil", again)
	}
	var call *hclsyntax.Block
	for _, body := range scope.Bodies {
		for _, b := range body.Blocks {
			if b.Type == "module" {
				call = b
			}
		}
	}
	if call == nil {
		t.Fatal("module block not found in scope bodies")
	}
	want := map[string]interface{}{
		"source": "../m",
		"name":   "x",
		"extra":  "${var.missing}",
		"tags":   []interface{}{map[string]interface{}{"owner": "x"}},
	}
	if got := scope.RenderBody(call.Body); !reflect.DeepEqual(got, want) {
		t.Errorf("RenderBody = %#v, want %#v", got, want)
	}
}

// oneBlock is the only object of a nested block, which is a list even when
// the block is written once.
func oneBlock(t *testing.T, v interface{}, what string) map[string]interface{} {
	t.Helper()
	blocks, ok := v.([]interface{})
	if !ok || len(blocks) != 1 {
		t.Fatalf("%s = %#v, want one block", what, v)
	}
	block, ok := blocks[0].(map[string]interface{})
	if !ok {
		t.Fatalf("%s[0] = %#v, want an object", what, blocks[0])
	}
	return block
}

func TestTakeRootScopeNilOnFailure(t *testing.T) {
	root := t.TempDir()
	ok := writeModule(t, root, "ok", map[string]string{"main.tf": "locals {\n  a = 1\n}\n"})
	e := New()
	if _, _, _, err := e.EvaluateModule(context.Background(), ok, nil); err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if _, _, _, err := e.EvaluateModule(context.Background(), filepath.Join(root, "missing"), nil); err == nil {
		t.Fatal("EvaluateModule of a missing dir succeeded, want an error")
	}
	if got := e.TakeRootScope(); got != nil {
		t.Fatalf("TakeRootScope after failure = %p, want nil", got)
	}
}

// An attribute evaluated to null is unset, in the resource body and in its
// nested blocks; a provisioner is a list of bodies even when written once.
func TestAttributesToDocumentNullsAndProvisioners(t *testing.T) {
	root := t.TempDir()
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
variable "none" {
  default = null
}
resource "aws_instance" "i" {
  key_name = var.none
  ami      = "a"
  ebs_block_device {
    kms_key_id = null
    encrypted  = true
  }
  provisioner "local-exec" {
    command = "echo"
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := findResource(t, resources, "aws_instance", "i")
	doc := AttributesToDocument(&r)
	if _, ok := doc["key_name"]; ok {
		t.Fatalf("key_name = %#v, want it left out", doc["key_name"])
	}
	ebs := doc["ebs_block_device"].([]interface{})[0].(map[string]interface{})
	if _, ok := ebs["kms_key_id"]; ok || ebs["encrypted"] != true {
		t.Fatalf("ebs_block_device = %#v, want kms_key_id left out", ebs)
	}
	if got := doc["provisioner"].(map[string]interface{})["local-exec"]; len(got.([]interface{})) != 1 {
		t.Fatalf("provisioner.local-exec = %#v, want a list of one body", got)
	}
}
