/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const policyModule = `
variable "principal" {}

resource "aws_sqs_queue" "q" {
  name = "q"
}

data "aws_iam_policy_document" "p" {
  statement {
    effect    = "Allow"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.q.arn]
    principals {
      type        = "AWS"
      identifiers = [var.principal]
    }
  }
}

data "aws_iam_policy_document" "per_index" {
  count = 2
  statement {
    sid     = "s${count.index}"
    actions = ["sqs:SendMessage"]
  }
}

locals {
  policy = data.aws_iam_policy_document.p.json
}

resource "aws_sqs_queue_policy" "direct" {
  queue_url = aws_sqs_queue.q.id
  policy    = data.aws_iam_policy_document.p.json
}

resource "aws_sqs_queue_policy" "via_local" {
  queue_url = aws_sqs_queue.q.id
  policy    = local.policy
}

resource "aws_sqs_queue_policy" "indexed" {
  queue_url = aws_sqs_queue.q.id
  policy    = data.aws_iam_policy_document.per_index[1].json
}

data "aws_ami" "ubuntu" {
  most_recent = true
}

data "google_iam_policy" "kms" {
  binding {
    role    = "roles/cloudkms.cryptoKeyDecrypter"
    members = [var.principal == "*" ? "allUsers" : var.principal]
  }
}

resource "google_kms_crypto_key_iam_policy" "k" {
  crypto_key_id = "k"
  policy_data   = data.google_iam_policy.kms.policy_data
}
`

func evaluateChild(t *testing.T) []ResolvedResource {
	t.Helper()
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": policyModule})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": `
module "c" {
  source    = "../child"
  principal = "*"
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	return resources
}

func TestDataPolicyDocumentResolvesInModule(t *testing.T) {
	resources := evaluateChild(t)
	want := `{"Statement":[{"Actions":["sqs:*"],"Effect":"Allow","Principals":{"AWS":["*"]},` +
		`"Resources":["${aws_sqs_queue.q.arn}"]}],"Version":"2012-10-17"}` + "\n"
	for _, name := range []string{"direct", "via_local"} {
		doc := AttributesToDocument(ptr(findResource(t, resources, "aws_sqs_queue_policy", name)))
		require.Equal(t, want, doc["policy"], name)
	}

	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_sqs_queue_policy", "indexed")))
	var policy struct{ Statement []map[string]interface{} }
	require.NoError(t, json.Unmarshal([]byte(doc["policy"].(string)), &policy))
	require.Equal(t, "s1", policy.Statement[0]["Sid"])
}

func TestDataGoogleIAMPolicyResolvesInModule(t *testing.T) {
	resources := evaluateChild(t)
	doc := AttributesToDocument(ptr(findResource(t, resources, "google_kms_crypto_key_iam_policy", "k")))
	require.Equal(t, `{"bindings":[{"members":["allUsers"],"role":"roles/cloudkms.cryptoKeyDecrypter"}]}`, doc["policy_data"])
}

func TestDataInstancesAreReturned(t *testing.T) {
	resources := evaluateChild(t)
	var data []ResolvedResource
	for _, r := range resources {
		if r.Data {
			data = append(data, r)
		}
	}
	names := make([]string, 0, len(data))
	for _, r := range data {
		require.Equal(t, "module.c", r.ModuleAddress)
		require.Len(t, r.CallChain, 1)
		names = append(names, r.Type+"."+r.Name)
	}
	require.ElementsMatch(t, []string{
		"aws_iam_policy_document.p",
		"aws_iam_policy_document.per_index[0]",
		"aws_iam_policy_document.per_index[1]",
		"aws_ami.ubuntu",
		"google_iam_policy.kms",
	}, names)

	ami := findData(t, data, "aws_ami", "ubuntu")
	doc := AttributesToDocument(&ami)
	require.Equal(t, true, doc["most_recent"])
	require.NotContains(t, doc, "owners")

	p := findData(t, data, "aws_iam_policy_document", "p")
	require.NotContains(t, AttributesToDocument(&p), "json")
}

func evaluateWithChild(t *testing.T, e *Evaluator, child map[string]string, rootSrc string) []ResolvedResource {
	t.Helper()
	root := t.TempDir()
	writeModule(t, root, "child", child)
	dir := writeModule(t, root, "root", map[string]string{"main.tf": rootSrc})
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	return resources
}

const callChild = `
module "c" {
  source = "../child"
}
`

func TestDataPolicyDocumentInJSONModule(t *testing.T) {
	resources := evaluateWithChild(t, New(), map[string]string{"main.tf.json": `{
  "data": {"aws_iam_policy_document": {"base": {
    "statement": [{"sid": "Base", "actions": ["sqs:*"], "principals": [{"type": "AWS", "identifiers": ["*"]}]}]
  }}},
  "resource": {"aws_sqs_queue_policy": {"p": {
    "queue_url": "u",
    "policy": "${data.aws_iam_policy_document.base.json}"
  }}}
}`}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_sqs_queue_policy", "p")))
	require.Equal(t, `{"Statement":[{"Actions":["sqs:*"],"Effect":"Allow","Principals":{"AWS":["*"]},"Sid":"Base"}],"Version":"2012-10-17"}`+"\n", doc["policy"])
}

func TestDataReadingDataThroughLocal(t *testing.T) {
	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": `
locals {
  base = data.aws_iam_policy_document.base.json
}

data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}

data "aws_iam_policy_document" "combined" {
  source_policy_documents = [local.base]
}

resource "aws_sqs_queue_policy" "p" {
  queue_url = "u"
  policy    = data.aws_iam_policy_document.combined.json
}
`}, callChild)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_sqs_queue_policy", "p")))
	require.Contains(t, doc["policy"], `"Sid":"Base"`)
}

func TestDataReadingResourcesReachesOutputs(t *testing.T) {
	resources := evaluateWithChild(t, New(), map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
}

data "aws_iam_policy_document" "p" {
  statement {
    resources = ["arn:aws:s3:::${aws_s3_bucket.b.bucket}"]
  }
}

output "j" {
  value = data.aws_iam_policy_document.p.json
}
`}, callChild+`
resource "aws_s3_bucket_policy" "r" {
  bucket = "x"
  policy = module.c.j
}
`)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_s3_bucket_policy", "r")))
	require.Contains(t, doc["policy"], `arn:aws:s3:::mybucket`)
}

func TestDataReadingModuleOutputs(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "inner", map[string]string{"main.tf": `
output "arn" {
  value = "arn:aws:sqs:us-east-1:1:q"
}
`})
	writeModule(t, root, "child", map[string]string{"main.tf": `
module "inner" {
  source = "../inner"
}

data "aws_iam_policy_document" "p" {
  statement {
    resources = [module.inner.arn]
  }
}

resource "aws_sqs_queue_policy" "p" {
  queue_url = "u"
  policy    = data.aws_iam_policy_document.p.json
}
`})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": callChild})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_sqs_queue_policy", "p")))
	require.Contains(t, doc["policy"], `arn:aws:sqs:us-east-1:1:q`)
}

func TestDataInstancesDoNotChargeBudget(t *testing.T) {
	e := New()
	e.SetMaxInstantiated(3)
	resources := evaluateWithChild(t, e, map[string]string{"main.tf": `
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "b" {}
data "aws_region" "r" {}
data "aws_caller_identity" "c" {}
`}, callChild)
	findResource(t, resources, "aws_s3_bucket", "a")
	findResource(t, resources, "aws_s3_bucket", "b")
	require.Equal(t, 2, e.InstantiatedCount())
}

func findData(t *testing.T, data []ResolvedResource, typ, name string) ResolvedResource {
	t.Helper()
	for _, r := range data {
		if r.Type == typ && r.Name == name {
			return r
		}
	}
	t.Fatalf("data %s.%s not found", typ, name)
	return ResolvedResource{}
}

func ptr[T any](v T) *T { return &v }
