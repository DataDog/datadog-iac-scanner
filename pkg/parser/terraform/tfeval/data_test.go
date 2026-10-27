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
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
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

// TestDataExpansionSkippedWhenBudgetExhausted evaluates a module whose child
// exhausts the instantiation budget exactly: the module is discarded either
// way, and only the evaluation count shows the avoided data expansion. The
// child's charge stays once a budget refusal happened, so the siblings after it
// stop in evaluationStop instead of redoing the refused work.
func TestDataExpansionSkippedWhenBudgetExhausted(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "heavy", map[string]string{"main.tf": `
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "b" {}

output "out" {
  value = "arn:aws:sqs:us-east-1:1:q"
}
`})
	writeModule(t, root, "consumer", map[string]string{"main.tf": `
module "heavy" {
  source = "../heavy"
}

resource "aws_s3_bucket" "r" {}

data "aws_region" "big" {
  count = 1000
  name  = module.heavy.out
}
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "consumer" {
  source = "../consumer"
}
`})

	e := New()
	e.SetMaxInstantiated(2)
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	// The consumer module is discarded either way: heavy's charge exhausted the
	// budget, and the consumer's own resource cannot fit the zero remainder.
	require.Equal(t, 1, len(e.NotEvaluatedDirs()))
	require.True(t, e.BudgetExceeded())
	// The refusal stands, so the consumer's discarded evaluation does not hand
	// the budget back: heavy's charge stays and bounds what follows.
	require.Equal(t, 2, e.InstantiatedCount())
	require.Empty(t, resources)
	// Only the initial expansion ran: the refresh against module.heavy.out saw
	// the exhausted budget and skipped the data expansion.
	require.Equal(t, 1, e.DataBlockEvaluations())
}

// TestBudgetFailureDoesNotRepeatForEverySibling pins Nathan's repro shape: a
// leaf of two resources fed var.in, a mid with one own resource and count=50 on
// the leaf, and a stack with count=50 on the mid, under a budget of 100. The
// first mid's leaves fill the budget exactly and its own resource is refused;
// restoring for that refusal would restart every remaining mid with the full
// budget, re-evaluating 50 leaves per mid (2500 cached evaluations at two
// wrapper levels, more at deeper fan-out). With the refusal left standing the
// remaining instances stop in evaluationStop, so the leaf evaluations done
// once — 50 distinct inputs, one cache entry each — are all there are.
func TestBudgetFailureDoesNotRepeatForEverySibling(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "in" {}

resource "aws_s3_bucket" "a" {
  bucket = var.in
}

resource "aws_s3_bucket" "b" {
  bucket = var.in
}
`})
	writeModule(t, root, "mid", map[string]string{"main.tf": `
variable "in" {}

module "leaf" {
  count  = 50
  source = "../leaf"
  in     = "${var.in}-${count.index}"
}

resource "aws_s3_bucket" "own" {
  bucket = var.in
}
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "mid" {
  count  = 50
  source = "../mid"
  in     = count.index
}
`})

	e := New()
	e.SetMaxInstantiated(100)
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	// The leaves of the first mid were evaluated and charged before its own
	// resource was refused; their charges stay, and nothing re-evaluates them.
	require.Equal(t, 100, e.InstantiatedCount())
	require.Equal(t, 50, len(e.cache))
	require.True(t, e.BudgetExceeded())
	require.Contains(t, e.NotEvaluatedDirs(), filepath.Join(root, "mid"))
	require.Empty(t, resources)
}

// TestBudgetFailureDoesNotRepeatInPrepass runs the same shape through the
// speculative sibling prepass, which shares the refusal handling through
// currentInstantiationCount: two calls give the stack a prepass, and the
// refusal of the first mid's own resource must stop the prepass instances
// rather than hand the speculative budget back to each of them.
func TestBudgetFailureDoesNotRepeatInPrepass(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "in" {}

resource "aws_s3_bucket" "a" {
  bucket = var.in
}

resource "aws_s3_bucket" "b" {
  bucket = var.in
}
`})
	writeModule(t, root, "mid", map[string]string{"main.tf": `
variable "in" {}

module "leaf" {
  count  = 50
  source = "../leaf"
  in     = "${var.in}-${count.index}"
}

resource "aws_s3_bucket" "own" {
  bucket = var.in
}
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "mid_a" {
  count  = 50
  source = "../mid"
  in     = count.index
}

module "mid_b" {
  count  = 50
  source = "../mid"
  in     = count.index
}
`})

	e := New()
	e.SetMaxInstantiated(100)
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	// Both calls share the leaf inputs (in = count.index of each call), so the
	// leaves of the first prepass instance are the whole eval cache: 50
	// entries, not one batch of 50 per retried instance.
	require.Equal(t, 100, e.InstantiatedCount())
	require.Equal(t, 50, len(e.cache))
	require.True(t, e.BudgetExceeded())
	require.Empty(t, resources)
}

// TestDataDisabledBudgetStillEvaluatesData pins that a disabled instantiation
// budget disables the data expansion pre-check too: remainingInstantiationBudget
// reports -1 for it, which must not read as exhausted.
func TestDataDisabledBudgetStillEvaluatesData(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "mod", map[string]string{"main.tf": `
resource "aws_s3_bucket" "r" {}

data "aws_region" "cur" {
  name = "us-east-1"
}

output "region" {
  value = data.aws_region.cur.name
}
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "mod" {
  source = "../mod"
}
`})

	e := New()
	e.SetMaxInstantiated(0)
	_, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.False(t, e.BudgetExceeded())
	// The module evaluated as usual and its data block expanded.
	require.Positive(t, e.DataBlockEvaluations())
	require.Empty(t, e.NotEvaluatedDirs())
}

// TestDataCacheInvalidatesPerSource changes one data source after the blocks
// settled: only the block reading it re-evaluates, and the control — where a
// second block reads it too — must re-evaluate both.
func TestDataCacheInvalidatesPerSource(t *testing.T) {
	const inner = `output "arn" { value = "arn:aws:sqs:us-east-1:1:q" }`
	dataEvals := func(stack string) ([]ResolvedResource, int) {
		root := t.TempDir()
		writeModule(t, root, "inner", map[string]string{"main.tf": inner})
		dir := writeModule(t, root, "stack", map[string]string{"main.tf": stack})
		e := New()
		resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		return resources, e.DataBlockEvaluations()
	}
	target := `
module "inner" { source = "../inner" }

data "aws_ami" "stable" {
  most_recent = true
}

data "aws_ami" "a" {
  owners = [data.aws_ami.stable.most_recent]
}

data "aws_ami" "b" {
  name = module.inner.arn
}
`
	resources, evals := dataEvals(target)
	// stable evaluates once, a twice (before and after data.* first carries
	// stable), b twice (before and after the module output arrives).
	require.Equal(t, 5, evals)
	b := findData(t, dataInstances(resources), "aws_ami", "b")
	require.Equal(t, "arn:aws:sqs:us-east-1:1:q", AttributesToDocument(&b)["name"])
	a := findData(t, dataInstances(resources), "aws_ami", "a")
	require.NotContains(t, fmt.Sprint(AttributesToDocument(&a)["owners"]), "${")

	_, controlEvals := dataEvals(`
module "inner" { source = "../inner" }

data "aws_ami" "stable" {
  most_recent = true
  name        = module.inner.arn
}

data "aws_ami" "a" {
  owners = [data.aws_ami.stable.most_recent]
}

data "aws_ami" "b" {
  name = module.inner.arn
}
`)
	// Here stable reads the output too, so its slice changes and a must
	// re-evaluate with it: two more expansions than the target.
	require.Equal(t, 7, controlEvals)
}

// TestDataCacheInvalidatesPerLocalAndModule pins per-reference invalidation
// for the local and module roots: a block reading local.a stays cached while
// local.b changes, and the control re-evaluates both.
func TestDataCacheInvalidatesPerLocalAndModule(t *testing.T) {
	const inner = `output "arn" { value = "arn:aws:sqs:us-east-1:1:q" }`
	evals := func(stack string) int {
		root := t.TempDir()
		writeModule(t, root, "inner", map[string]string{"main.tf": inner})
		dir := writeModule(t, root, "stack", map[string]string{"main.tf": stack})
		e := New()
		_, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		return e.DataBlockEvaluations()
	}
	target := evals(`
module "inner" { source = "../inner" }

locals {
  a = "stable"
  b = module.inner.arn
}

data "aws_ami" "x" {
  name = local.a
}

data "aws_ami" "y" {
  name = local.b
}
`)
	// x evaluates once (local.a never changes), y twice (before and after the
	// module output arrives). Whole-local invalidation would re-evaluate x too.
	require.Equal(t, 3, target)

	control := evals(`
module "inner" { source = "../inner" }

locals {
  a = module.inner.arn
  b = module.inner.arn
}

data "aws_ami" "x" {
  name = local.a
}

data "aws_ami" "y" {
  name = local.b
}
`)
	// Here local.a changes as well, so both blocks re-evaluate.
	require.Equal(t, 4, control)
}

// TestDataZeroInstanceDataLeavesEmptyObject scans a module whose only data
// block expands to zero instances: evaluation completes with an empty data
// object.
func TestDataZeroInstanceDataLeavesEmptyObject(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": `
data "aws_region" "off" {
  count = 0
  name  = "us-east-1"
}

output "region" {
  value = "arn:aws:sqs:us-east-1:1:q"
}
`})

	e := New()
	require.NotPanics(t, func() {
		_, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
	})
	require.Equal(t, 1, e.DataBlockEvaluations())
}

func dataInstances(resources []ResolvedResource) []ResolvedResource {
	var data []ResolvedResource
	for _, r := range resources {
		if r.Data {
			data = append(data, r)
		}
	}
	return data
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

func TestDataInstancesChargeBudget(t *testing.T) {
	files := map[string]string{"main.tf": `
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "b" {}
data "aws_region" "r" {}
data "aws_caller_identity" "c" {}
`}

	e := New()
	e.SetMaxInstantiated(5)
	resources := evaluateWithChild(t, e, files, callChild)
	findResource(t, resources, "aws_s3_bucket", "a")
	require.Equal(t, 4, e.InstantiatedCount())
	require.False(t, e.BudgetExceeded())

	// A module whose resources and data together exceed the budget is not
	// instantiated, as one whose resources alone do.
	e = New()
	e.SetMaxInstantiated(3)
	resources = evaluateWithChild(t, e, files, callChild)
	for _, r := range resources {
		require.NotEqual(t, "aws_s3_bucket", r.Type)
	}
	require.True(t, e.BudgetExceeded())
}

// TestDataReferenceCycleTerminates evaluates data blocks reading each other
// through a local in a cycle: a reads local.middle, middle reads data b, and b
// reads data a. Evaluation must end within the refresh pass bound, without
// panicking, and reproduce the same instances when run again.
func TestDataReferenceCycleTerminates(t *testing.T) {
	files := map[string]string{"main.tf": `
locals {
  middle = data.aws_iam_policy_document.b.json
}

data "aws_iam_policy_document" "a" {
  source_policy_documents = [local.middle]
}

data "aws_iam_policy_document" "b" {
  source_policy_documents = [data.aws_iam_policy_document.a.json]
}
`}
	dataDocs := func() map[string]interface{} {
		var resources []ResolvedResource
		// evaluateWithChild fails the test if evaluation errors, so reaching the
		// assertion means the cycle ended within the pass bound.
		require.NotPanics(t, func() {
			resources = evaluateWithChild(t, New(), files, callChild)
		})
		docs := map[string]interface{}{}
		for _, r := range resources {
			if r.Data {
				docs[r.Type+"."+r.Name] = AttributesToDocument(&r)
			}
		}
		return docs
	}
	docs := dataDocs()
	require.Len(t, docs, 2)
	require.Contains(t, docs, "aws_iam_policy_document.a")
	require.Contains(t, docs, "aws_iam_policy_document.b")
	require.Equal(t, docs, dataDocs())
}

// TestDataRefreshDoesNotRechargeBudget builds a source_policy_documents chain
// that settles only after several refresh passes. The blocks are charged once:
// with a budget of five, pass-scoped charging (four blocks times the passes)
// would exceed it and leave the module scanned as written.
func TestDataRefreshDoesNotRechargeBudget(t *testing.T) {
	files := map[string]string{"main.tf": `
data "aws_iam_policy_document" "d1" {
  statement {
    sid     = "D1"
    actions = ["sqs:*"]
  }
}

data "aws_iam_policy_document" "d2" {
  source_policy_documents = [data.aws_iam_policy_document.d1.json]
}

data "aws_iam_policy_document" "d3" {
  source_policy_documents = [data.aws_iam_policy_document.d2.json]
}

data "aws_iam_policy_document" "d4" {
  source_policy_documents = [data.aws_iam_policy_document.d3.json]
}
`}
	e := New()
	e.SetMaxInstantiated(5)
	resources := evaluateWithChild(t, e, files, callChild)
	var data int
	for _, r := range resources {
		if r.Data {
			data++
		}
	}
	require.Equal(t, 4, data)
	require.Equal(t, 4, e.InstantiatedCount())
	require.False(t, e.BudgetExceeded())
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

func TestDataPolicyDocumentExpandsDynamicBlocksInModule(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{"main.tf": `
variable "names" {
  type = list(string)
}

variable "suffix" {}

data "aws_iam_policy_document" "d" {
  dynamic "statement" {
    for_each = var.names
    content {
      sid       = statement.value
      actions   = ["s3:GetObject", "${statement.value}:*"]
      resources = ["arn:aws:s3:::${statement.value}/${var.suffix}"]
    }
  }
}

resource "aws_sqs_queue_policy" "p" {
  policy = data.aws_iam_policy_document.d.json
}
`})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": `
module "c" {
  source = "../child"
  names  = ["a", "b"]
  suffix = "x"
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	doc := AttributesToDocument(ptr(findResource(t, resources, "aws_sqs_queue_policy", "p")))
	require.Equal(t, `{"Statement":[`+
		`{"Actions":["s3:GetObject","a:*"],"Effect":"Allow","Resources":["arn:aws:s3:::a/x"],"Sid":"a"},`+
		`{"Actions":["s3:GetObject","b:*"],"Effect":"Allow","Resources":["arn:aws:s3:::b/x"],"Sid":"b"}],`+
		`"Version":"2012-10-17"}`+"\n", doc["policy"])
}

// TestDataJSONEncodeCycleStaysBounded pins a data block reading its own JSON
// through a local and jsonencode. Terraform rejects the cycle. Each refresh
// pass used to nest the previous JSON once more, so its size doubled with
// every pass and every refresh and the evaluation ran out of memory.
func TestDataJSONEncodeCycleStaysBounded(t *testing.T) {
	for _, ref := range []string{
		"data.aws_iam_policy_document.p.json",
		`data.aws_iam_policy_document["p"].json`,
		`data["aws_iam_policy_document"]["p"].json`,
	} {
		t.Run(ref, func(t *testing.T) {
			assertJSONEncodeCycleStaysBounded(t, ref)
		})
	}
}

func assertJSONEncodeCycleStaysBounded(t *testing.T, ref string) {
	t.Helper()
	src := fmt.Sprintf(`
variable "x" {
  default = "x"
}

locals {
  l0 = [%s, var.x]
  l1 = [module.m.out, local.l0]
}

data "aws_iam_policy_document" "p" {
  statement {
    actions = [jsonencode(local.l0)]
  }
}

module "m" {
  source = "../leaf"
  in     = [module.m.out, var.x]
}

resource "aws_s3_bucket" "consumer" {
  bucket = jsonencode(local.l1)
}
`, ref)
	for i := 0; i < 2; i++ {
		src += fmt.Sprintf("locals {\n  alias%d = [%s]\n}\n", i, ref)
	}
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "in" {}
output "out" { value = var.in }
`})
	dir := writeModule(t, root, "child", map[string]string{"main.tf": src})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	for i := range resources {
		raw, err := json.Marshal(AttributesToDocument(&resources[i]))
		require.NoError(t, err)
		require.Less(t, len(raw), 4096, "%s.%s grew: %d bytes", resources[i].Type, resources[i].Name, len(raw))
	}
	findData(t, dataInstances(resources), "aws_iam_policy_document", "p")
	findResource(t, resources, "aws_s3_bucket", "consumer")
}

// An iterator named local hides the module local of that name inside the
// content, so a document that only reads the iterator still resolves.
func TestDynamicIteratorNamedLocalIsNotADataCycle(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "root", map[string]string{"main.tf": `
locals {
  value   = data.aws_iam_policy_document.p.json
  actions = ["s3:GetObject"]
}
data "aws_iam_policy_document" "p" {
  dynamic "statement" {
    for_each = local.actions
    iterator = local
    content {
      actions = [local.value]
    }
  }
}
resource "aws_sqs_queue_policy" "q" {
  policy = data.aws_iam_policy_document.p.json
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	policy := AttributesToDocument(ptr(findResource(t, resources, "aws_sqs_queue_policy", "q")))["policy"]
	require.Contains(t, policy, "s3:GetObject")
}

func TestCyclicDataBlocksFollowsOnlyCycles(t *testing.T) {
	file, diags := hclsyntax.ParseConfig([]byte(`
locals {
  base    = data.aws_iam_policy_document.base.json
  through = local.loop
  loop    = data.aws_iam_policy_document.loop.json
  value   = data.aws_iam_policy_document.shadowed.json
  nested  = data.aws_iam_policy_document.nested.json
}

data "aws_iam_policy_document" "base" {
  statement {
    actions = ["sqs:*"]
  }
}

data "aws_iam_policy_document" "chained" {
  source_policy_documents = [local.base, data.aws_iam_policy_document.base.json]
}

data "aws_iam_policy_document" "loop" {
  dynamic "statement" {
    for_each = [local.through]
    iterator = local
    content {
      actions = [local.value]
    }
  }
}

data "aws_iam_policy_document" "shadowed" {
  dynamic "statement" {
    for_each = ["sqs:SendMessage"]
    iterator = local
    content {
      actions = [local.value]
    }
  }
}

data "aws_iam_policy_document" "self" {
  source_policy_documents = [data.aws_iam_policy_document.self.json]
}

data "aws_iam_policy_document" "nested" {
  dynamic "statement" {
    for_each = ["sqs:SendMessage"]
    iterator = local
    content {
      dynamic "condition" {
        for_each = [local.nested]
        content {
          test = local.nested
        }
      }
    }
  }
}

data "aws_iam_policy_document" "indexed" {
  source_policy_documents = [data.aws_iam_policy_document["indexed"].json]
}

data "aws_iam_policy_document" "bracket" {
  source_policy_documents = [data["aws_iam_policy_document"]["bracket"].json]
}

data "aws_iam_policy_document" "reads_loop" {
  source_policy_documents = [local.loop]
}
`), "main.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	body := file.Body.(*hclsyntax.Body)
	_, localExprs, _, _, _ := collectBlocks([]*hclsyntax.Body{body})
	cyclic := cyclicDataBlocks(collectDataBlocks([]*hclsyntax.Body{body}), localExprs)
	names := map[string]bool{}
	for b := range cyclic {
		names[b.Labels[1]] = true
	}
	require.Equal(t, map[string]bool{"loop": true, "self": true, "indexed": true, "bracket": true}, names)
}
