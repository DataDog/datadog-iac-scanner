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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

func TestCtyValueToDocument(t *testing.T) {
	tests := []struct {
		name  string
		value cty.Value
		want  interface{}
	}{
		{"string", cty.StringVal("hello"), "hello"},
		{"placeholder-like string", cty.StringVal(UnknownAttributePlaceholder), UnknownAttributePlaceholder},
		{"expression-like string", cty.StringVal("${var.value}"), "${var.value}"},
		{"bool", cty.True, true},
		{"number", cty.NumberIntVal(42), json.Number("42")},
		{"null", cty.NullVal(cty.String), nil},
		{"unknown", cty.UnknownVal(cty.DynamicPseudoType), UnknownAttributePlaceholder},
		{"nil", cty.NilVal, UnknownAttributePlaceholder},
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

func TestTerraformValueFactsDescribeNativeStateWithoutValues(t *testing.T) {
	capsuleType := cty.Capsule("test capsule", reflect.TypeOf(struct{}{}))
	tests := []struct {
		name  string
		value cty.Value
		state model.TerraformNativeValueState
		path  model.TerraformFactPath
	}{
		{"known", cty.StringVal("secret-literal-291"), model.TerraformNativeKnown, model.TerraformFactPath{model.TerraformKeySegment("value")}},
		{"placeholder text is still known", cty.StringVal(UnknownAttributePlaceholder), model.TerraformNativeKnown, model.TerraformFactPath{model.TerraformKeySegment("value")}},
		{"expression text is still known", cty.StringVal("${var.value}"), model.TerraformNativeKnown, model.TerraformFactPath{model.TerraformKeySegment("value")}},
		{"null", cty.NullVal(cty.String), model.TerraformNativeNull, model.TerraformFactPath{model.TerraformKeySegment("value")}},
		{"unknown", cty.UnknownVal(cty.String), model.TerraformNativeUnknown, model.TerraformFactPath{model.TerraformKeySegment("value")}},
		{"partial", cty.ObjectVal(map[string]cty.Value{"known": cty.StringVal("yes"), "unknown": cty.UnknownVal(cty.String)}), model.TerraformNativePartial, model.TerraformFactPath{model.TerraformKeySegment("value")}},
		{"unsupported capsule", cty.CapsuleVal(capsuleType, &struct{}{}), model.TerraformNativeKnown, model.TerraformFactPath{model.TerraformKeySegment("value")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts := &terraformValueFacts{}
			_ = ctyValueToDocumentWithFacts(tt.value, &attrSource{}, nil, facts, tt.path)
			if len(facts.values) == 0 || facts.values[0].NativeState != tt.state {
				t.Fatalf("facts = %#v, want first native state %q", facts.values, tt.state)
			}
			if tt.name == "unsupported capsule" && len(facts.values) != 1 {
				t.Fatalf("unsupported value emitted %d facts at one path, want one", len(facts.values))
			}
			encoded, err := json.Marshal(facts.values)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "secret-literal-291") {
				t.Fatalf("facts unexpectedly contain a concrete value: %s", encoded)
			}
		})
	}
	facts := &terraformValueFacts{}
	got := ctyValueToDocumentWithFacts(cty.NilVal, &attrSource{}, nil, facts, model.TerraformFactPath{model.TerraformKeySegment("missing")})
	if got != UnknownAttributePlaceholder || len(facts.values) != 0 {
		t.Fatalf("NilVal rendered as %#v with facts %#v, want unresolved placeholder and no fact", got, facts.values)
	}
}

func TestTerraformValueFactsBudgetTruncatesWithoutChangingDocument(t *testing.T) {
	wide := make(map[string]cty.Value, maxTerraformFactNodes+1)
	for i := 0; i < maxTerraformFactNodes+1; i++ {
		wide[fmt.Sprintf("key-%05d", i)] = cty.StringVal("value")
	}
	value := cty.ObjectVal(wide)
	facts := &terraformValueFacts{values: make([]model.TerraformValueFact, 0, 8)}
	got := ctyValueToDocumentWithFacts(value, &attrSource{}, nil, facts, model.TerraformFactPath{model.TerraformKeySegment("value")})
	want := ctyValueToDocument(value, &attrSource{}, nil)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("facts changed rendered document")
	}
	if len(facts.values) > maxTerraformFactNodes || !facts.truncated {
		t.Fatalf("facts count=%d truncated=%v, want at most %d and truncated", len(facts.values), facts.truncated, maxTerraformFactNodes)
	}
	if facts.values[0].Presentation != model.TerraformPresentationUnproven || facts.values[0].Children != model.TerraformChildrenClosed {
		t.Fatalf("truncated aggregate fact = %#v, want unproven presentation and closed membership", facts.values[0])
	}
}

func TestTerraformValueFactsDepthBudget(t *testing.T) {
	value := cty.StringVal("leaf")
	for i := 0; i < maxTerraformFactDepth+10; i++ {
		value = cty.ObjectVal(map[string]cty.Value{"child": value})
	}
	facts := &terraformValueFacts{}
	_ = ctyValueToDocumentWithFacts(value, &attrSource{}, nil, facts, model.TerraformFactPath{model.TerraformKeySegment("value")})
	if !facts.truncated {
		t.Fatal("deep facts were not marked truncated")
	}
	if facts.values[0].Presentation != model.TerraformPresentationUnproven {
		t.Fatalf("truncated ancestor presentation = %q, want unproven", facts.values[0].Presentation)
	}
	for _, fact := range facts.values {
		if len(fact.Path) > maxTerraformFactDepth {
			t.Fatalf("fact path length %d exceeds cap %d", len(fact.Path), maxTerraformFactDepth)
		}
	}
}

func BenchmarkAttributesToDocumentWithFacts(b *testing.B) {
	for _, size := range []int{4096, 8192} {
		attrs := make(map[string]cty.Value, size)
		for i := 0; i < size; i++ {
			attrs[fmt.Sprintf("key-%05d", i)] = cty.StringVal("value")
		}
		for _, withFacts := range []bool{false, true} {
			mode := "legacy"
			if withFacts {
				mode = "facts"
			}
			b.Run(fmt.Sprintf("%s/attrs_%d", mode, size), func(b *testing.B) {
				ctx := context.Background()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r := ResolvedResource{
						Attributes: attrs,
						Scope: &ModuleScope{
							evalCtx: &hcl.EvalContext{Variables: map[string]cty.Value{}},
							sources: map[string][]byte{},
						},
					}
					if withFacts {
						_, _ = AttributesToDocumentWithFacts(ctx, &r)
					} else {
						_ = AttributesToDocumentWithContext(ctx, &r)
					}
				}
			})
		}
	}
}

func TestTerraformValueFactsBudgetIsDeterministic(t *testing.T) {
	attrs := make(map[string]cty.Value, maxTerraformFactNodes+2)
	for i := 0; i < maxTerraformFactNodes+2; i++ {
		attrs[fmt.Sprintf("key-%05d", i)] = cty.StringVal("value")
	}
	r := ResolvedResource{Attributes: attrs}
	_, first := AttributesToDocumentWithFacts(context.Background(), &r)
	_, second := AttributesToDocumentWithFacts(context.Background(), &r)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstJSON, secondJSON) {
		t.Fatal("truncated facts differ across identical renders")
	}
	if len(first.Values) != maxTerraformFactNodes || !first.Truncated {
		t.Fatalf("facts count=%d truncated=%v, want exactly %d and truncated", len(first.Values), first.Truncated, maxTerraformFactNodes)
	}
}

func TestTerraformValueFactsMarkCertificateEnrichmentAdapted(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"certificate.pem": string(fixture),
		"main.tf":         `resource "example_certificate" "this" { certificate_body = "certificate.pem" }`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := findResource(t, resources, "example_certificate", "this")
	doc, facts := AttributesToDocumentWithFacts(context.Background(), &r)
	if _, ok := doc["certificate_body"].(map[string]interface{}); !ok {
		t.Fatalf("certificate_body = %#v, want enriched object", doc["certificate_body"])
	}
	for _, fact := range facts.Values {
		if len(fact.Path) == 1 && fact.Path[0].Key == "certificate_body" {
			if fact.Presentation != model.TerraformPresentationAdapted || fact.Children != model.TerraformChildrenUnknown {
				t.Fatalf("certificate_body fact = %#v, want adapted and unknown children", fact)
			}
			return
		}
	}
	t.Fatal("certificate_body fact not found")
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
	legacy := AttributesToDocument(&r)
	withFacts, _ := AttributesToDocumentWithFacts(context.Background(), &r)
	if !reflect.DeepEqual(legacy, withFacts) {
		t.Fatalf("facts-enabled document differs from legacy conversion:\nlegacy: %#v\nwith facts: %#v", legacy, withFacts)
	}
	return legacy
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
  nested        = { ref = aws_s3_bucket.logs.bucket, literal = "literal" }
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
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := findResource(t, resources, "aws_s3_bucket_logging", "this")
	_, facts := AttributesToDocumentWithFacts(context.Background(), &r)
	if got := findTerraformFact(t, facts, "target_bucket"); got.Presentation != model.TerraformPresentationManagedReference {
		t.Errorf("target_bucket presentation = %q, want managed_reference", got.Presentation)
	}
	if got := findTerraformFact(t, facts, "rule"); got.Presentation != model.TerraformPresentationAdapted {
		t.Errorf("rule presentation = %q, want adapted", got.Presentation)
	}
	nested := findTerraformFact(t, facts, "nested")
	if nested.Presentation != model.TerraformPresentationAdapted || nested.Children != model.TerraformChildrenClosed {
		t.Errorf("nested fact = %#v, want adapted with closed children", nested)
	}
	if got := findTerraformFactAtPath(t, facts, "nested", "ref"); got.Presentation != model.TerraformPresentationManagedReference {
		t.Errorf("nested.ref presentation = %q, want managed_reference", got.Presentation)
	}

	// A reference to a resource outside the module stays unresolved, but the
	// reference text is what lets rules associate the two resources.
	if got := doc["bucket"]; got != "${aws_s3_bucket.target.id}" {
		t.Errorf("bucket = %#v, want ${aws_s3_bucket.target.id}", got)
	}
	// Even known resource references retain the identity legacy rules join on.
	if got := doc["target_bucket"]; got != "${aws_s3_bucket.logs.bucket}" {
		t.Errorf("target_bucket = %#v, want ${aws_s3_bucket.logs.bucket}", got)
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

func findTerraformFact(t *testing.T, facts model.TerraformValueFacts, key string) model.TerraformValueFact {
	t.Helper()
	for _, fact := range facts.Values {
		if len(fact.Path) == 1 && !fact.Path[0].IsIndex && fact.Path[0].Key == key {
			return fact
		}
	}
	t.Fatalf("fact %q not found in %#v", key, facts.Values)
	return model.TerraformValueFact{}
}

func findTerraformFactAtPath(t *testing.T, facts model.TerraformValueFacts, keys ...string) model.TerraformValueFact {
	t.Helper()
	for _, fact := range facts.Values {
		if len(fact.Path) != len(keys) {
			continue
		}
		matches := true
		for i, key := range keys {
			if fact.Path[i].IsIndex || fact.Path[i].Key != key {
				matches = false
				break
			}
		}
		if matches {
			return fact
		}
	}
	t.Fatalf("fact path %q not found in %#v", keys, facts.Values)
	return model.TerraformValueFact{}
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
