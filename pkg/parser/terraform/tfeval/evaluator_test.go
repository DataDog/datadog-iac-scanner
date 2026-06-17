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

func TestEvaluateModule_SingleNestedBlockIsSingletonTuple(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "this" {
  versioning {
    enabled = true
  }
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	versioning, ok := r.Attributes["versioning"]
	if !ok {
		t.Fatalf("versioning block missing")
	}
	if !versioning.Type().IsTupleType() || versioning.LengthInt() != 1 {
		t.Fatalf("versioning = %s (len %d), want 1-tuple", versioning.Type().FriendlyName(), versioning.LengthInt())
	}
	block := versioning.Index(cty.NumberIntVal(0))
	if !block.Type().IsObjectType() {
		t.Fatalf("versioning[0] = %s, want object", block.Type().FriendlyName())
	}
	enabled := block.GetAttr("enabled")
	if !enabled.True() {
		t.Fatalf("versioning[0].enabled = %#v, want true", enabled)
	}
}
