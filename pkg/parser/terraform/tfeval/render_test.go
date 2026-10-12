/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func policyStatement(t *testing.T, policy interface{}) map[string]interface{} {
	t.Helper()
	s, ok := policy.(string)
	if !ok {
		t.Fatalf("policy = %#v, want a JSON string", policy)
	}
	var doc struct {
		Statement []map[string]interface{}
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatalf("policy %q does not parse: %v", s, err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("policy %q has %d statements, want 1", s, len(doc.Statement))
	}
	return doc.Statement[0]
}

// A policy interpolating a computed attribute keeps everything it states, with
// only the computed part left as its reference text.
func TestRenderPolicyWithComputedReference(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
resource "aws_sqs_queue" "q" {
  name = "q"
}

resource "aws_sqs_queue_policy" "heredoc" {
  queue_url = aws_sqs_queue.q.id
  policy    = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"${aws_sqs_queue.q.arn}"}]}
POLICY
}

resource "aws_sqs_queue_policy" "jsonencode" {
  queue_url = aws_sqs_queue.q.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.q.arn
    }]
  })
}
`,
	})

	for _, name := range []string{"heredoc", "jsonencode"} {
		t.Run(name, func(t *testing.T) {
			doc := documentFor(t, dir, "aws_sqs_queue_policy", name)
			st := policyStatement(t, doc["policy"])
			want := map[string]interface{}{
				"Effect": "Allow", "Principal": "*", "Action": "sqs:*", "Resource": "${aws_sqs_queue.q.arn}",
			}
			if !reflect.DeepEqual(st, want) {
				t.Fatalf("statement = %#v, want %#v", st, want)
			}
		})
	}
}

func TestRenderPartlyResolvedValues(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
variable "account" {
  default = "123"
}

variable "tags" {
  default = { team = "core" }
}

locals {
  names = ["a", "b"]
}

resource "aws_kms_key" "k" {}

resource "aws_s3_bucket" "b" {
  bucket      = "logs-${var.account}-${aws_kms_key.k.key_id}"
  tags        = merge(var.tags, { Name = aws_kms_key.k.arn })
  list        = [for n in local.names : "${n}-${aws_kms_key.k.id}"]
  formatted   = format("%s/%s", var.account, aws_kms_key.k.id)
  conditional = aws_kms_key.k.id == "x" ? "public-read" : "private"
  fallback    = coalesce(aws_kms_key.k.id, "default")
  known_cond  = var.account == "123" ? aws_kms_key.k.arn : "*"
}
`,
	})
	doc := documentFor(t, dir, "aws_s3_bucket", "b")

	cases := map[string]interface{}{
		"bucket": "logs-123-${aws_kms_key.k.key_id}",
		"tags":   map[string]interface{}{"team": "core", "Name": "${aws_kms_key.k.arn}"},
		"list":   []interface{}{"a-${aws_kms_key.k.id}", "b-${aws_kms_key.k.id}"},
		// format places its arguments, so the resolved one keeps its value.
		"formatted": "123/${aws_kms_key.k.id}",
		// A condition on an unresolved value is not decided on its text.
		"conditional": `${aws_kms_key.k.id == "x" ? "public-read" : "private"}`,
		"fallback":    `${coalesce(aws_kms_key.k.id, "default")}`,
		// A resolved condition picks its branch.
		"known_cond": "${aws_kms_key.k.arn}",
	}
	for key, want := range cases {
		if got := doc[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
}

// A value read whole keeps its resolved parts, with the unresolved ones named
// by their path in it.
func TestRenderPartlyResolvedReference(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
resource "aws_kms_key" "k" {}

locals {
  tags = { team = "core", key = aws_kms_key.k.arn }
}

resource "aws_s3_bucket" "b" {
  tags = local.tags
}
`,
	})
	doc := documentFor(t, dir, "aws_s3_bucket", "b")
	want := map[string]interface{}{"team": "core", "key": "${local.tags.key}"}
	if got := doc["tags"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("tags = %#v, want %#v", got, want)
	}
}

func TestRenderTemplatefile(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"policy.json.tpl": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"${arn}/*"}]}`,
		"main.tf": `
resource "aws_s3_bucket" "b" {
  bucket = "b"
}

resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.b.id
  policy = templatefile("${path.module}/policy.json.tpl", { arn = aws_s3_bucket.b.arn })
}
`,
	})
	doc := documentFor(t, dir, "aws_s3_bucket_policy", "p")
	st := policyStatement(t, doc["policy"])
	if got := st["Resource"]; got != "${aws_s3_bucket.b.arn}/*" {
		t.Fatalf("Resource = %#v, want ${aws_s3_bucket.b.arn}/*", got)
	}
	if got := st["Principal"]; got != "*" {
		t.Fatalf("Principal = %#v, want *", got)
	}
}

// Each count instance renders with its own index.
func TestRenderCountInstanceInModule(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"main.tf": `
resource "aws_kms_key" "k" {}

resource "aws_sqs_queue" "q" {
  count = 2
  name  = "q-${count.index}-${aws_kms_key.k.id}"
}
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "c" {
  source = "../child"
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]interface{}{}
	for i := range resources {
		if resources[i].Type == "aws_sqs_queue" {
			got[resources[i].Name] = AttributesToDocument(&resources[i])["name"]
		}
	}
	want := map[string]interface{}{
		"q[0]": "q-0-${aws_kms_key.k.id}",
		"q[1]": "q-1-${aws_kms_key.k.id}",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %#v, want %#v", got, want)
	}
}
