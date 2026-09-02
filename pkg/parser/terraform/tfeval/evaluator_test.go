/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// writeModule lays down a module directory containing the given files (name ->
// content) under root and returns its path.
func writeModule(t *testing.T, root, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for fname, content := range files {
		if err := os.WriteFile(filepath.Join(dir, fname), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", fname, err)
		}
	}
	return dir
}

// findResource returns the first resolved resource matching type and name.
func findResource(t *testing.T, resources []ResolvedResource, typ, name string) ResolvedResource {
	t.Helper()
	for _, r := range resources {
		if r.Type == typ && r.Name == name {
			return r
		}
	}
	t.Fatalf("resource %s.%s not found in %d resources", typ, name, len(resources))
	return ResolvedResource{}
}

// requireString asserts that the attribute is a known string equal to want.
func requireString(t *testing.T, attrs map[string]cty.Value, key, want string) {
	t.Helper()
	v, ok := attrs[key]
	if !ok {
		t.Fatalf("attribute %q missing", key)
	}
	if !v.IsKnown() {
		t.Fatalf("attribute %q is unknown, want %q", key, want)
	}
	if v.Type() != cty.String {
		t.Fatalf("attribute %q is %s, want string", key, v.Type().FriendlyName())
	}
	if got := v.AsString(); got != want {
		t.Fatalf("attribute %q = %q, want %q", key, got, want)
	}
}

// requireUnknown asserts that the attribute exists and is not known.
func requireUnknown(t *testing.T, attrs map[string]cty.Value, key string) {
	t.Helper()
	v, ok := attrs[key]
	if !ok {
		t.Fatalf("attribute %q missing", key)
	}
	if v.IsKnown() {
		t.Fatalf("attribute %q = %#v, want unknown", key, v)
	}
}

func TestEvaluateModule_InputPropagatedToChildResource(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
}
`,
	})

	inputs := map[string]cty.Value{"bucket_name": cty.StringVal("my-bucket")}
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, inputs)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, r.Attributes, "bucket", "my-bucket")
}

func TestEvaluateModule_DefaultAppliedWhenInputOmitted(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "acl" {
  type    = string
  default = "private"
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, r.Attributes, "acl", "private")
}

func TestEvaluateModule_UnknownWhenNoInputNoDefault(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireUnknown(t, r.Attributes, "acl")
}

func TestEvaluateModule_WrappedInputsResolve(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "name" {
  type = string
}

variable "public" {
  type    = bool
  default = false
}

resource "aws_s3_bucket" "this" {
  bucket    = format("%s-bucket", var.name)
  upper_acl = upper(var.name)
  acl       = var.public ? "public-read" : "private"
}
`,
	})

	inputs := map[string]cty.Value{"name": cty.StringVal("data")}
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, inputs)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, r.Attributes, "bucket", "data-bucket")
	requireString(t, r.Attributes, "upper_acl", "DATA")
	requireString(t, r.Attributes, "acl", "private")
}

func TestEvaluateModule_ChainedLocalsReachFixedPoint(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "env" {
  type    = string
  default = "prod"
}

locals {
  prefix = "app-${var.env}"
  full   = "${local.prefix}-${local.suffix}"
  suffix = upper(var.env)
}

resource "aws_s3_bucket" "this" {
  bucket = local.full
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, r.Attributes, "bucket", "app-prod-PROD")
}

func TestEvaluateModule_NestedLocalModules(t *testing.T) {
	root := t.TempDir()

	// B: leaf module using its input.
	writeModule(t, root, "b", map[string]string{
		"main.tf": `
variable "name" {
  type = string
}

resource "aws_s3_bucket" "leaf" {
  bucket = var.name
}
`,
	})

	// A: passes its input down to B.
	writeModule(t, root, "a", map[string]string{
		"main.tf": `
variable "name" {
  type = string
}

module "b" {
  source = "../b"
  name   = var.name
}
`,
	})

	// root: calls A with a concrete value.
	rootDir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "a" {
  source = "../a"
  name   = "deep-value"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), rootDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "leaf")
	requireString(t, r.Attributes, "bucket", "deep-value")
	if r.ModuleAddress != "module.a.module.b" {
		t.Fatalf("ModuleAddress = %q, want module.a.module.b", r.ModuleAddress)
	}
	if len(r.CallChain) != 2 {
		t.Fatalf("CallChain length = %d, want 2", len(r.CallChain))
	}
}

func TestEvaluateModule_OutputConsumedByCaller(t *testing.T) {
	root := t.TempDir()

	writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "name" {
  type = string
}

output "bucket_name" {
  value = "${var.name}-out"
}
`,
	})

	rootDir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "child" {
  source = "../child"
  name   = "hello"
}

resource "aws_s3_bucket" "this" {
  bucket = module.child.bucket_name
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), rootDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, r.Attributes, "bucket", "hello-out")
}

func TestEvaluateModule_TopLevelOutputsReturned(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "name" {
  type    = string
  default = "x"
}

output "name_out" {
  value = var.name
}
`,
	})

	_, outputs, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	v, ok := outputs["name_out"]
	if !ok {
		t.Fatalf("output name_out not returned")
	}
	if !v.IsKnown() || v.AsString() != "x" {
		t.Fatalf("output name_out = %#v, want \"x\"", v)
	}
}

func TestEvaluateModule_CycleTerminates(t *testing.T) {
	root := t.TempDir()

	// a -> b -> a (cycle). Each also declares a resource so we can confirm we
	// still materialize what we can before stopping.
	writeModule(t, root, "a", map[string]string{
		"main.tf": `
module "b" {
  source = "../b"
}

resource "aws_s3_bucket" "a_bucket" {
  bucket = "a"
}
`,
	})
	writeModule(t, root, "b", map[string]string{
		"main.tf": `
module "a" {
  source = "../a"
}

resource "aws_s3_bucket" "b_bucket" {
  bucket = "b"
}
`,
	})

	aDir := filepath.Join(root, "a")
	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := New().EvaluateModule(context.Background(), aDir, nil)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("EvaluateModule: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("EvaluateModule did not terminate on a cyclic module graph")
	}
}

func TestEvaluateModule_DepthGuardTerminates(t *testing.T) {
	root := t.TempDir()

	// self-referential module: a calls a (same dir). The cycle guard catches
	// this, but it also exercises that recursion is bounded.
	writeModule(t, root, "a", map[string]string{
		"main.tf": `
module "self" {
  source = "./"
}

resource "aws_s3_bucket" "a_bucket" {
  bucket = "a"
}
`,
	})

	aDir := filepath.Join(root, "a")
	resources, _, _, err := New().EvaluateModule(context.Background(), aDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	findResource(t, resources, "aws_s3_bucket", "a_bucket")
}

func TestEvaluateModule_UnresolvedReferenceIsUnknown(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "this" {
  bucket    = data.aws_caller_identity.current.account_id
  other_ref = aws_kms_key.example.arn
  literal   = "ok"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireUnknown(t, r.Attributes, "bucket")
	requireUnknown(t, r.Attributes, "other_ref")
	requireString(t, r.Attributes, "literal", "ok")
}

func TestEvaluateModule_RemoteModuleSkipped(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "remote" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket = "remote-bucket"
}

resource "aws_s3_bucket" "local" {
  bucket = "local-bucket"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	// The remote module is skipped; only the root resource is materialized.
	findResource(t, resources, "aws_s3_bucket", "local")
	for _, r := range resources {
		if r.ModuleAddress != "" {
			t.Fatalf("unexpected resource from remote module: %+v", r)
		}
	}
}

func TestEvaluateModule_ConfinesRemotePackageTraversal(t *testing.T) {
	base := t.TempDir()
	root := writeModule(t, base, "root", map[string]string{
		"main.tf": `
module "remote" {
  source = "example.com/acme/module/aws"
}
`,
	})
	packageRoot := filepath.Join(base, "package")
	selected := writeModule(t, packageRoot, "modules/selected", map[string]string{
		"main.tf": `
resource "test_resource" "selected" {}
module "shared" {
  source = "../shared"
}
module "escape" {
  source = "../../../outside"
}
`,
	})
	writeModule(t, packageRoot, "modules/shared", map[string]string{
		"main.tf": `resource "test_resource" "shared" {}`,
	})
	outside := writeModule(t, base, "outside", map[string]string{
		"main.tf": `resource "test_resource" "outside" {}`,
	})
	if err := os.Symlink(filepath.Join(outside, "main.tf"), filepath.Join(selected, "linked.tf")); err != nil {
		t.Fatal(err)
	}

	evaluator := New()
	evaluator.SetRemoteResolver(func(_, _, _, _ string) (string, string, bool) {
		return selected, packageRoot, true
	})
	resources, _, _, err := evaluator.EvaluateModule(t.Context(), root, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	findResource(t, resources, "test_resource", "selected")
	findResource(t, resources, "test_resource", "shared")
	for _, resource := range resources {
		if resource.Name == "outside" {
			t.Fatalf("resource outside acquired package was evaluated: %+v", resource)
		}
	}
}

func TestEvaluateModule_RepeatedBlocksGroupedIntoTuple(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_security_group" "this" {
  ingress {
    from_port = 80
  }
  ingress {
    from_port = 443
  }
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_security_group", "this")
	ingress, ok := r.Attributes["ingress"]
	if !ok {
		t.Fatalf("ingress block group missing")
	}
	if !ingress.Type().IsTupleType() {
		t.Fatalf("ingress = %s, want tuple", ingress.Type().FriendlyName())
	}
	if got := ingress.LengthInt(); got != 2 {
		t.Fatalf("ingress tuple length = %d, want 2", got)
	}
}

func TestEvaluateModule_SiblingModuleOutputInInput(t *testing.T) {
	root := t.TempDir()

	writeModule(t, root, "naming", map[string]string{
		"main.tf": `
variable "env" { type = string }

output "suffix" {
  value = "-${var.env}"
}
`,
	})

	writeModule(t, root, "bucket", map[string]string{
		"main.tf": `
variable "suffix" { type = string }

resource "aws_s3_bucket" "this" {
  bucket = "logs${var.suffix}"
}
`,
	})

	rootDir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "naming" {
  source = "../naming"
  env    = "prod"
}

module "bucket" {
  source = "../bucket"
  suffix = module.naming.suffix
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), rootDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, r.Attributes, "bucket", "logs-prod")
}

func TestEvaluateModule_CountExpansion(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "this" {
  count  = 3
  bucket = "logs-${count.index}"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	var got []ResolvedResource
	for _, r := range resources {
		if r.Type == "aws_s3_bucket" {
			got = append(got, r)
		}
	}
	if len(got) != 3 {
		t.Fatalf("got %d aws_s3_bucket instances, want 3", len(got))
	}
	names := make(map[string]bool)
	for _, r := range got {
		v := r.Attributes["bucket"]
		if v.IsKnown() && v.Type() == cty.String {
			names[v.AsString()] = true
		}
	}
	for _, want := range []string{"logs-0", "logs-1", "logs-2"} {
		if !names[want] {
			t.Fatalf("bucket %q not found in expanded instances; got %v", want, names)
		}
	}
}

func TestEvaluateModule_CountZeroSkipped(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "this" {
  count  = 0
  bucket = "never"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	for _, r := range resources {
		if r.Type == "aws_s3_bucket" && r.Name == "this" {
			t.Fatal("count=0 resource should not be materialized")
		}
	}
}

func TestEvaluateModule_ForEachExpansion(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "this" {
  for_each = { prod = "prod-bucket", staging = "staging-bucket" }
  bucket   = each.value
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	var got []ResolvedResource
	for _, r := range resources {
		if r.Type == "aws_s3_bucket" {
			got = append(got, r)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d aws_s3_bucket instances, want 2", len(got))
	}
	buckets := make(map[string]bool)
	for _, r := range got {
		if v := r.Attributes["bucket"]; v.IsKnown() && v.Type() == cty.String {
			buckets[v.AsString()] = true
		}
	}
	for _, want := range []string{"prod-bucket", "staging-bucket"} {
		if !buckets[want] {
			t.Fatalf("bucket %q not found; got %v", want, buckets)
		}
	}
}

func TestEvaluateModule_ForEachEmptySkipped(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "this" {
  for_each = {}
  bucket   = each.key
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	for _, r := range resources {
		if r.Type == "aws_s3_bucket" {
			t.Fatal("for_each={} resource should not be materialized")
		}
	}
}

func TestEvaluateModule_CountInChildModuleExpanded(t *testing.T) {
	root := t.TempDir()

	writeModule(t, root, "bucket_mod", map[string]string{
		"main.tf": `
variable "prefix" { type = string }

resource "aws_s3_bucket" "this" {
  count  = 2
  bucket = "${var.prefix}-${count.index}"
}
`,
	})

	rootDir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "buckets" {
  source = "../bucket_mod"
  prefix = "logs"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), rootDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	var childBuckets []ResolvedResource
	for _, r := range resources {
		if r.Type == "aws_s3_bucket" && r.ModuleAddress != "" {
			childBuckets = append(childBuckets, r)
		}
	}
	if len(childBuckets) != 2 {
		t.Fatalf("got %d child aws_s3_bucket instances, want 2", len(childBuckets))
	}
	names := make(map[string]bool)
	for _, r := range childBuckets {
		if v := r.Attributes["bucket"]; v.IsKnown() && v.Type() == cty.String {
			names[v.AsString()] = true
		}
	}
	for _, want := range []string{"logs-0", "logs-1"} {
		if !names[want] {
			t.Fatalf("bucket %q not found in child module instances; got %v", want, names)
		}
	}
}

func TestEvaluateModule_CrossResourceRef(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_kms_key" "key" {
  description = "my-key"
}

resource "aws_s3_bucket" "bucket" {
  kms_description = aws_kms_key.key.description
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "bucket")
	requireString(t, r.Attributes, "kms_description", "my-key")
}

func TestEvaluateModule_CrossResourceRefViaLocal(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_kms_key" "key" {
  description = "via-local"
}

locals {
  kms_desc = aws_kms_key.key.description
}

resource "aws_s3_bucket" "bucket" {
  label = local.kms_desc
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "bucket")
	requireString(t, r.Attributes, "label", "via-local")
}

func TestEvaluateModule_CrossResourceRefCountExpanded(t *testing.T) {
	// A for_each resource that references a count-expanded sibling by index should
	// resolve the attribute from the correct instance.
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_kms_key" "k" {
  count       = 2
  description = "key-${count.index}"
}

resource "aws_s3_bucket" "b" {
  kms_desc = aws_kms_key.k[0].description
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "b")
	requireString(t, r.Attributes, "kms_desc", "key-0")
}

func TestEvaluateModule_CrossResourceRefForEachExpanded(t *testing.T) {
	// A plain resource that references a for_each-expanded sibling by key should
	// resolve the attribute from the correct instance.
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_iam_role" "r" {
  for_each = { dev = "arn:dev", prod = "arn:prod" }
  arn      = each.value
}

resource "aws_s3_bucket" "b" {
  role_arn = aws_iam_role.r["dev"].arn
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "b")
	requireString(t, r.Attributes, "role_arn", "arn:dev")
}

func TestEvaluateModule_OutputResolvedAfterFinalRefPass(t *testing.T) {
	// Output references a 3-hop chain a→b→c; the final ref pass resolves 'a' but
	// the fix ensures that resolved value is in evalCtx before outputs are computed.
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "leaf" "c" {
  value = "resolved"
}

resource "mid" "b" {
  value = leaf.c.value
}

resource "top" "a" {
  value = mid.b.value
}

output "o" { value = top.a.value }
`,
	})

	_, outputs, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	v, ok := outputs["o"]
	if !ok {
		t.Fatal("output 'o' missing")
	}
	if !v.IsKnown() || v.Type() != cty.String || v.AsString() != "resolved" {
		t.Fatalf("output 'o' = %v, want cty.StringVal(\"resolved\")", v)
	}
}

func TestEvaluateModule_FourHopResourceChain(t *testing.T) {
	// A 4-hop dependency chain (a→b→c→d) needs the final evalResourceBlocks pass
	// so that d sees c's value after c was resolved on the last injection pass.
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "r" "a" { value = "x" }
resource "r" "b" { value = r.a.value }
resource "r" "c" { value = r.b.value }
resource "r" "d" { value = r.c.value }
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	for _, want := range []string{"a", "b", "c", "d"} {
		r := findResource(t, resources, "r", want)
		requireString(t, r.Attributes, "value", "x")
	}
}

func TestCanonicalInputsKey_NullTypeDistinct(t *testing.T) {
	// cty.NullVal(cty.String) and cty.NullVal(cty.Number) must produce different
	// cache keys; before the fix both encoded to "x=null\n".
	k1 := canonicalInputsKey(map[string]cty.Value{"x": cty.NullVal(cty.String)})
	k2 := canonicalInputsKey(map[string]cty.Value{"x": cty.NullVal(cty.Number)})
	if k1 == k2 {
		t.Errorf("null(string) and null(number) produced the same cache key: %q", k1)
	}
}

func TestEvaluateLocalModuleBlocksIgnoresNullPreliminaryOutputs(t *testing.T) {
	evalCtx := &hcl.EvalContext{Variables: map[string]cty.Value{
		"module": cty.NullVal(cty.EmptyObject),
	}}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("evaluateLocalModuleBlocks panicked: %v", recovered)
		}
	}()

	_, outputs := New().evaluateLocalModuleBlocks(
		context.Background(), nil, evalCtx, "", "", "", nil, 0, nil, nil,
	)
	if len(outputs) != 0 {
		t.Fatalf("outputs = %#v, want empty", outputs)
	}
}

func TestEvaluateModule_LaterSiblingForwardDepNotDropped(t *testing.T) {
	// Module B (second) references module C (third, forward dep) as input.
	// Module A (first) has no outputs. Without seeding moduleOutputs from the
	// pre-pass, A's first iteration would drop C's pre-pass value from evalCtx,
	// leaving B with an unknown input.
	root := t.TempDir()

	writeModule(t, root, "a", map[string]string{
		"main.tf": `resource "r" "a" { value = "a-only" }`,
	})
	writeModule(t, root, "b", map[string]string{
		"main.tf": `
variable "x" {}
resource "aws_s3_bucket" "r" { bucket = var.x }
`,
	})
	writeModule(t, root, "c", map[string]string{
		"main.tf": `output "val" { value = "concrete" }`,
	})

	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "a" {
  source = "../a"
}
module "b" {
  source = "../b"
  x      = module.c.val
}
module "c" {
  source = "../c"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, "aws_s3_bucket", "r")
	requireString(t, r.Attributes, "bucket", "concrete")
}

func TestEvaluateModule_SiblingModuleForwardDependency(t *testing.T) {
	// Module A inputs reference module C's output (forward dependency).
	// Module B inputs reference module A's output.
	// Without incrementally updating evalCtx in evaluateLocalModuleBlocks, B
	// sees the stale pre-pass value of module.a.val (unknown) and caches a
	// stale result.
	root := t.TempDir()

	writeModule(t, root, "a", map[string]string{
		"main.tf": `
variable "x" {}
output "val" { value = var.x }
`,
	})
	writeModule(t, root, "b", map[string]string{
		"main.tf": `
variable "y" {}
resource "aws_s3_bucket" "r" { bucket = var.y }
`,
	})
	writeModule(t, root, "c", map[string]string{
		"main.tf": `
output "val" { value = "concrete" }
`,
	})

	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "a" {
  source = "../a"
  x      = module.c.val
}
module "b" {
  source = "../b"
  y      = module.a.val
}
module "c" {
  source = "../c"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, "aws_s3_bucket", "r")
	requireString(t, r.Attributes, "bucket", "concrete")
}

func TestEvaluateModule_FourHopOutputResolvesCorrectly(t *testing.T) {
	// The final evalResourceBlocks result must be injected into evalCtx before
	// outputs are computed, otherwise a 4-hop chain's last value is unknown.
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "r" "a" { value = "x" }
resource "r" "b" { value = r.a.value }
resource "r" "c" { value = r.b.value }
resource "r" "d" { value = r.c.value }

output "o" { value = r.d.value }
`,
	})

	_, outputs, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	o, ok := outputs["o"]
	if !ok {
		t.Fatal("output 'o' not found")
	}
	if !o.IsKnown() || o.AsString() != "x" {
		t.Errorf("output 'o' = %s, want 'x'", o.GoString())
	}
}

func TestEvaluateModule_ModuleInputReferenceSiblingResource(t *testing.T) {
	// module "child" { acl = aws_kms_key.key.description } — the module input
	// references a sibling resource. Without the early pre-injection pass the input
	// would evaluate to unknown and the child module's resource would never see it.
	root := t.TempDir()

	writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "acl" { type = string }

resource "aws_s3_bucket_acl" "a" {
  acl = var.acl
}
`,
	})

	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
resource "aws_kms_key" "key" {
  description = "sibling-value"
}

module "child" {
  source = "../child"
  acl    = aws_kms_key.key.description
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket_acl", "a")
	requireString(t, r.Attributes, "acl", "sibling-value")
}

func TestEvaluateModule_LocalResolvesAfterFinalRefPass(t *testing.T) {
	// local.o = top.a.value, which only resolves on the last ref pass (3-hop chain).
	// Without refreshing locals after the final injection, output "o" stays unknown.
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "leaf" "c" { value = "resolved" }
resource "mid"  "b" { value = leaf.c.value }
resource "top"  "a" { value = mid.b.value }

locals {
  o = top.a.value
}

output "o" { value = local.o }
`,
	})

	_, outputs, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	v, ok := outputs["o"]
	if !ok {
		t.Fatal("output 'o' missing")
	}
	if !v.IsKnown() || v.Type() != cty.String || v.AsString() != "resolved" {
		t.Fatalf("output 'o' = %v, want cty.StringVal(\"resolved\")", v)
	}
}

func TestEvaluateModule_MemoizationSiblingPrepassAndMainLoop(t *testing.T) {
	// When module B uses module A's output as an input the evaluator runs a
	// sibling pre-pass and then a main loop. With memoization the pre-pass result
	// is reused by the main loop: each child module is evaluated exactly once.
	root := t.TempDir()

	writeModule(t, root, "shared", map[string]string{
		"main.tf": `
variable "tag" { type = string }

output "label" { value = "tag-${var.tag}" }

resource "aws_s3_bucket" "b" {
  bucket = "shared-${var.tag}"
}
`,
	})

	rootDir := writeModule(t, root, "root", map[string]string{
		"main.tf": `
module "a" {
  source = "../shared"
  tag    = "alpha"
}

module "b" {
  source = "../shared"
  tag    = module.a.label
}
`,
	})

	ev := New()
	resources, _, _, err := ev.EvaluateModule(context.Background(), rootDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	// Two module instances → two aws_s3_bucket resources with known values.
	var buckets []string
	for _, r := range resources {
		if r.Type == "aws_s3_bucket" {
			if v := r.Attributes["bucket"]; v.IsKnown() && v.Type() == cty.String {
				buckets = append(buckets, v.AsString())
			}
		}
	}
	if len(buckets) != 2 {
		t.Fatalf("got %d aws_s3_bucket resources, want 2: %v", len(buckets), buckets)
	}

	// The pre-pass updates evalCtx between siblings, so module.b's inputs are
	// resolved the same way in both the pre-pass and the main loop → 2 child
	// cache entries plus 1 for the root = 3 total. No duplicate evaluations.
	if got := len(ev.cache); got != 3 {
		t.Fatalf("cache size = %d, want 3 (2 child instances + root)", got)
	}
}

func TestEvaluateModule_MemoizationAcrossRoots(t *testing.T) {
	// Two root modules calling the same child with the same inputs share a cache
	// entry; two roots with different inputs get independent correct results.
	root := t.TempDir()

	writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "name" { type = string }

resource "aws_s3_bucket" "b" {
  bucket = var.name
}
`,
	})

	rootA := writeModule(t, root, "rootA", map[string]string{
		"main.tf": `
module "m" {
  source = "../child"
  name   = "bucket-a"
}
`,
	})

	rootB := writeModule(t, root, "rootB", map[string]string{
		"main.tf": `
module "m" {
  source = "../child"
  name   = "bucket-b"
}
`,
	})

	ev := New()

	resA, _, _, err := ev.EvaluateModule(context.Background(), rootA, nil)
	if err != nil {
		t.Fatalf("rootA: %v", err)
	}
	resB, _, _, err := ev.EvaluateModule(context.Background(), rootB, nil)
	if err != nil {
		t.Fatalf("rootB: %v", err)
	}

	findBucket := func(resources []ResolvedResource) string {
		t.Helper()
		for _, r := range resources {
			if r.Type == "aws_s3_bucket" {
				if v := r.Attributes["bucket"]; v.IsKnown() && v.Type() == cty.String {
					return v.AsString()
				}
			}
		}
		t.Fatal("aws_s3_bucket not found")
		return ""
	}

	if got := findBucket(resA); got != "bucket-a" {
		t.Fatalf("rootA bucket = %q, want bucket-a", got)
	}
	if got := findBucket(resB); got != "bucket-b" {
		t.Fatalf("rootB bucket = %q, want bucket-b", got)
	}

	// Two roots with different inputs → 2 child entries (no cross-root collision)
	// plus 2 root entries = 4 cache entries total.
	if got := len(ev.cache); got != 4 {
		t.Fatalf("cache size = %d, want 4 (2 child + 2 root entries)", got)
	}
}

// Nested blocks have to reach a rule in the same shape a parsed Terraform file
// gives them, or a rule written for one will silently skip the other. The
// parser writes a block that appears once as an object and only a repeated one
// as a list, which is why `resource.ingress.cidr_blocks` is how rules are
// written.
func TestEvaluateModule_NestedBlockShapeMatchesParser(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "single" {
  versioning {
    enabled = true
  }
}

resource "aws_security_group" "repeated" {
  ingress {
    from_port = 22
  }

  ingress {
    from_port = 443
  }
}

resource "google_sql_database_instance" "dynamic" {
  dynamic "ip_configuration" {
    for_each = ["private"]
    content {
      private_network = var.private_network
    }
  }

  dynamic "ip_configuration" {
    for_each = ["psc"]
    content {
      ipv4_enabled = false
    }
  }

  dynamic "backup_configuration" {
    for_each = ["enabled"]
    content {
      enabled = true
    }
  }
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	versioning := findResource(t, resources, "aws_s3_bucket", "single").Attributes["versioning"]
	if !versioning.Type().IsObjectType() {
		t.Fatalf("versioning = %s, want an object for a block written once",
			versioning.Type().FriendlyName())
	}
	if enabled := versioning.GetAttr("enabled"); !enabled.True() {
		t.Fatalf("versioning.enabled = %#v, want true", enabled)
	}

	ingress := findResource(t, resources, "aws_security_group", "repeated").Attributes["ingress"]
	if !ingress.Type().IsTupleType() || ingress.LengthInt() != 2 {
		t.Fatalf("ingress = %s (len %d), want a 2-tuple for a repeated block",
			ingress.Type().FriendlyName(), ingress.LengthInt())
	}

	dynamicResource := findResource(t, resources, "google_sql_database_instance", "dynamic")
	dynamic := dynamicResource.Attributes["dynamic"]
	if !dynamic.Type().IsObjectType() {
		t.Fatalf("dynamic = %s, want an object", dynamic.Type().FriendlyName())
	}
	ipConfiguration := dynamic.GetAttr("ip_configuration")
	if !ipConfiguration.Type().IsTupleType() || ipConfiguration.LengthInt() != 2 {
		t.Fatalf("dynamic.ip_configuration = %s (len %d), want a 2-tuple",
			ipConfiguration.Type().FriendlyName(), ipConfiguration.LengthInt())
	}
	if !dynamic.GetAttr("backup_configuration").Type().IsObjectType() {
		t.Fatalf("dynamic.backup_configuration = %s, want an object",
			dynamic.GetAttr("backup_configuration").Type().FriendlyName())
	}

	doc := AttributesToDocument(&dynamicResource)
	dynamicDoc := doc["dynamic"].(map[string]interface{})
	ipConfigurationDoc := dynamicDoc["ip_configuration"].([]interface{})
	firstContent := ipConfigurationDoc[0].(map[string]interface{})["content"].(map[string]interface{})
	if got := firstContent["private_network"]; got != "${var.private_network}" {
		t.Fatalf("private_network = %#v, want source reference", got)
	}
}

func TestReleaseCachesAllowsReuse(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "name" { type = string }
resource "aws_s3_bucket" "this" {
  bucket = var.name
}
`,
	})

	e := New()
	resources1, _, _, err := e.EvaluateModule(context.Background(), dir, map[string]cty.Value{
		"name": cty.StringVal("first"),
	})
	if err != nil {
		t.Fatalf("first EvaluateModule: %v", err)
	}
	if len(resources1) != 1 {
		t.Fatalf("first eval: got %d resources, want 1", len(resources1))
	}

	e.ReleaseCaches()

	resources2, _, _, err := e.EvaluateModule(context.Background(), dir, map[string]cty.Value{
		"name": cty.StringVal("second"),
	})
	if err != nil {
		t.Fatalf("second EvaluateModule after ReleaseCaches: %v", err)
	}
	if len(resources2) != 1 {
		t.Fatalf("second eval: got %d resources, want 1", len(resources2))
	}
	requireString(t, resources2[0].Attributes, "bucket", "second")
}
