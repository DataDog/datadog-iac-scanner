/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
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

func TestEvaluateModule_JSONConfigInputPropagated(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf.json": `{
  "variable": {
    "bucket_name": { "type": "string" }
  },
  "locals": {
    "prefixed": "${var.bucket_name}-json"
  },
  "resource": {
    "aws_s3_bucket": {
      "this": {
        "bucket": "${local.prefixed}"
      }
    }
  }
}`,
	})

	inputs := map[string]cty.Value{"bucket_name": cty.StringVal("my-bucket")}
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, inputs)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	r := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, r.Attributes, "bucket", "my-bucket-json")
}

func TestEvaluateModule_JSONNullDefault(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf.json": `{
  "variable": {
    "acl": { "default": null }
  },
  "resource": {
    "aws_s3_bucket": {
      "this": {
        "acl": null
      }
    }
  }
}`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, "aws_s3_bucket", "this")
	v, ok := r.Attributes["acl"]
	if !ok {
		t.Fatal("attribute acl missing")
	}
	if !v.IsNull() {
		t.Fatalf("attribute acl = %#v, want null", v)
	}
}

func TestEvaluateModule_JSONChildModule(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"main.tf.json": `{
  "variable": { "name": { "type": "string" } },
  "resource": { "aws_s3_bucket": { "leaf": { "bucket": "${var.name}" } } }
}`,
	})
	rootDir := writeModule(t, root, "root", map[string]string{
		"main.tf.json": `{
  "module": { "child": { "source": "../child", "name": "from-json" } }
}`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), rootDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, "aws_s3_bucket", "leaf")
	requireString(t, r.Attributes, "bucket", "from-json")
	if r.ModuleAddress != "module.child" {
		t.Fatalf("ModuleAddress = %q, want module.child", r.ModuleAddress)
	}
}

func TestEvaluateModule_TofuJSONShadowsTfJSON(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf.json":   `{"resource":{"aws_s3_bucket":{"shadowed":{"bucket":"from-tf"}}}}`,
		"main.tofu.json": `{"resource":{"aws_s3_bucket":{"live":{"bucket":"from-tofu"}}}}`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1: %#v", len(resources), resources)
	}
	requireString(t, findResource(t, resources, "aws_s3_bucket", "live").Attributes, "bucket", "from-tofu")
}

func TestEvaluateModule_TofuShadowsTf(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "shadowed" {
  bucket = "from-tf"
}
`,
		"main.tofu": `
resource "aws_s3_bucket" "live" {
  bucket = "from-tofu"
}
`,
		"other.tf": `
resource "aws_s3_bucket" "other" {
  bucket = "from-other"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2 (shadowed twin dropped): %#v", len(resources), resources)
	}
	requireString(t, findResource(t, resources, "aws_s3_bucket", "live").Attributes, "bucket", "from-tofu")
	requireString(t, findResource(t, resources, "aws_s3_bucket", "other").Attributes, "bucket", "from-other")
	for _, r := range resources {
		if r.Name == "shadowed" {
			t.Fatal("main.tf resource must not be evaluated next to main.tofu")
		}
	}
}

func TestEvaluateModule_ExcludedTofuTwinKept(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "tf" {
  bucket = "from-tf"
}
`,
		"main.tofu": `
resource "aws_s3_bucket" "tofu" {
  bucket = "from-tofu"
}
`,
	})

	e := New()
	e.SetMergeAllow(map[string]struct{}{
		filepath.ToSlash(filepath.Join(dir, "main.tf")): {},
	})
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1: %#v", len(resources), resources)
	}
	requireString(t, findResource(t, resources, "aws_s3_bucket", "tf").Attributes, "bucket", "from-tf")
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

func TestEvaluateModule_FilesystemContextValues(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"mod.txt": "module",
		"main.tf": `
resource "test_resource" "paths" {
  module_file = file("${path.module}/mod.txt")
  root_file   = file("${path.root}/root.txt")
  cwd         = path.cwd
  workspace   = terraform.workspace
}
`,
	})
	rootDir := writeModule(t, root, "root", map[string]string{
		"root.txt": "root",
		"main.tf": `
module "child" {
  source = "../child"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), rootDir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, "test_resource", "paths")
	requireString(t, r.Attributes, "module_file", "module")
	requireString(t, r.Attributes, "root_file", "root")
	requireString(t, r.Attributes, "cwd", filepath.ToSlash(rootDir))
	requireString(t, r.Attributes, "workspace", "default")
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
		t.Errorf("null(string) and null(number) produced the same cache key: %+v", k1)
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
		context.Background(), nil, nil, evalCtx, nil, nil, "", "", "", "", nil, 0, nil, nil,
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
	if _, ok := dynamicResource.Attributes["dynamic"]; ok {
		t.Fatal("dynamic blocks must be expanded into the blocks they generate")
	}
	ipConfiguration := dynamicResource.Attributes["ip_configuration"]
	if !ipConfiguration.Type().IsTupleType() || ipConfiguration.LengthInt() != 2 {
		t.Fatalf("ip_configuration = %s (len %d), want a 2-tuple",
			ipConfiguration.Type().FriendlyName(), ipConfiguration.LengthInt())
	}
	backup := dynamicResource.Attributes["backup_configuration"]
	if !backup.Type().IsObjectType() || !backup.GetAttr("enabled").True() {
		t.Fatalf("backup_configuration = %#v, want an object with enabled = true", backup)
	}

	doc := AttributesToDocument(&dynamicResource)
	ipConfigurationDoc := doc["ip_configuration"].([]interface{})
	first := ipConfigurationDoc[0].(map[string]interface{})
	if got := first["private_network"]; got != "${var.private_network}" {
		t.Fatalf("private_network = %#v, want source reference", got)
	}
	if got := ipConfigurationDoc[1].(map[string]interface{})["ipv4_enabled"]; got != false {
		t.Fatalf("ipv4_enabled = %#v, want false", got)
	}
}

func TestEvaluateModule_DynamicBlocks(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "rules" {
  default = {
    ssh   = { port = 22, cidr = "0.0.0.0/0" }
    https = { port = 443, cidr = "10.0.0.0/8" }
  }
}
variable "unknown_rules" {}

resource "aws_security_group" "sg" {
  ingress {
    from_port = 80
  }
  dynamic "ingress" {
    for_each = var.rules
    iterator = rule
    content {
      description = rule.key
      from_port   = rule.value.port
      cidr_blocks = [rule.value.cidr]
    }
  }
}

resource "aws_s3_bucket" "nested" {
  dynamic "lifecycle_rule" {
    for_each = ["logs"]
    content {
      prefix = lifecycle_rule.value
      dynamic "transition" {
        for_each = [30, 60]
        content {
          days   = transition.value
          prefix = lifecycle_rule.value
        }
      }
    }
  }
  dynamic "logging" {
    for_each = []
    content {
      target_bucket = "never"
    }
  }
}

resource "aws_security_group" "unknown" {
  dynamic "ingress" {
    for_each = var.unknown_rules
    content {
      from_port = ingress.value.port
      to_port   = 443
    }
  }
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	ingress := findResource(t, resources, "aws_security_group", "sg").Attributes["ingress"]
	if !ingress.Type().IsTupleType() || ingress.LengthInt() != 3 {
		t.Fatalf("ingress = %#v, want the static block and two generated ones", ingress)
	}
	elems := ingress.AsValueSlice()
	if got := elems[0].GetAttr("from_port"); !got.RawEquals(cty.NumberIntVal(80)) {
		t.Fatalf("static ingress from_port = %#v, want 80 first", got)
	}
	https := elems[1]
	if got := https.GetAttr("description"); !got.RawEquals(cty.StringVal("https")) {
		t.Fatalf("generated ingress description = %#v, want https (sorted key order)", got)
	}
	if got := https.GetAttr("cidr_blocks"); !got.RawEquals(cty.TupleVal([]cty.Value{cty.StringVal("10.0.0.0/8")})) {
		t.Fatalf("generated ingress cidr_blocks = %#v", got)
	}

	nested := findResource(t, resources, "aws_s3_bucket", "nested")
	if _, ok := nested.Attributes["logging"]; ok {
		t.Fatal("a dynamic block over an empty collection must generate nothing")
	}
	rule := nested.Attributes["lifecycle_rule"]
	if got := rule.GetAttr("prefix"); !got.RawEquals(cty.StringVal("logs")) {
		t.Fatalf("lifecycle_rule.prefix = %#v, want logs", got)
	}
	transitions := rule.GetAttr("transition")
	if !transitions.Type().IsTupleType() || transitions.LengthInt() != 2 {
		t.Fatalf("transition = %#v, want two generated blocks", transitions)
	}
	second := transitions.AsValueSlice()[1]
	if !second.GetAttr("days").RawEquals(cty.NumberIntVal(60)) ||
		!second.GetAttr("prefix").RawEquals(cty.StringVal("logs")) {
		t.Fatalf("transition[1] = %#v, want days 60 reading the outer iterator", second)
	}

	unknown := findResource(t, resources, "aws_security_group", "unknown")
	if _, ok := unknown.Attributes["ingress"]; ok {
		t.Fatal("a dynamic block over an unknown collection may generate nothing and must be kept as written")
	}
	content := unknown.Attributes["dynamic"].GetAttr("ingress").GetAttr("content")
	if got := content.GetAttr("to_port"); !got.RawEquals(cty.NumberIntVal(443)) {
		t.Fatalf("dynamic.ingress.content.to_port = %#v, want 443", got)
	}
	doc := AttributesToDocument(&unknown)
	rawContent := doc["dynamic"].(map[string]interface{})["ingress"].(map[string]interface{})["content"]
	if got := rawContent.(map[string]interface{})["from_port"]; got != "${ingress.value.port}" {
		t.Fatalf("dynamic.ingress.content.from_port = %#v, want its source reference", got)
	}
}

// A static block next to a dynamic block of the same type that generates none
// still maps back to its own source.
func TestAttributesToDocument_StaticBlockBesideEmptyDynamic(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
  dynamic "ingress" {
    for_each = []
    content {
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	sg := findResource(t, resources, "aws_security_group", "sg")
	doc := AttributesToDocument(&sg)
	ingress, ok := doc["ingress"].(map[string]interface{})
	if !ok {
		t.Fatalf("ingress = %#v, want the static block alone", doc["ingress"])
	}
	cidrs := ingress["cidr_blocks"].([]interface{})
	if len(cidrs) != 1 || cidrs[0] != "${aws_vpc.main.cidr_block}" {
		t.Fatalf("cidr_blocks = %#v, want the static block's source reference", cidrs)
	}
}

// A static block followed by a dynamic block of the same type that generates
// several elements maps every element back to its own source.
func TestAttributesToDocument_StaticBlockBesideExpandedDynamic(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
  dynamic "ingress" {
    for_each = ["a", "b"]
    content {
      cidr_blocks = [aws_vpc.other.cidr_block]
    }
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	sg := findResource(t, resources, "aws_security_group", "sg")
	doc := AttributesToDocument(&sg)
	ingress, ok := doc["ingress"].([]interface{})
	if !ok || len(ingress) != 3 {
		t.Fatalf("ingress = %#v, want the static block and two generated ones", doc["ingress"])
	}
	want := []string{"${aws_vpc.main.cidr_block}", "${aws_vpc.other.cidr_block}", "${aws_vpc.other.cidr_block}"}
	for i, block := range ingress {
		cidrs := block.(map[string]interface{})["cidr_blocks"].([]interface{})
		if len(cidrs) != 1 || cidrs[0] != want[i] {
			t.Fatalf("ingress[%d].cidr_blocks = %#v, want %q", i, cidrs, want[i])
		}
	}
}

// Several dynamic blocks of one type among static blocks map every element to
// the block that generated it, even when the counts add up by coincidence.
func TestAttributesToDocument_SeveralDynamicBlocksMapToTheirOwnSources(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = [aws_vpc.static_one.cidr_block]
  }
  dynamic "ingress" {
    for_each = []
    content {
      cidr_blocks = [aws_vpc.empty.cidr_block]
    }
  }
  ingress {
    cidr_blocks = [aws_vpc.static_two.cidr_block]
  }
  dynamic "ingress" {
    for_each = ["a", "b"]
    content {
      cidr_blocks = [aws_vpc.generated.cidr_block]
    }
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	sg := findResource(t, resources, "aws_security_group", "sg")
	doc := AttributesToDocument(&sg)
	ingress, ok := doc["ingress"].([]interface{})
	if !ok || len(ingress) != 4 {
		t.Fatalf("ingress = %#v, want four blocks", doc["ingress"])
	}
	want := []string{
		"${aws_vpc.static_one.cidr_block}",
		"${aws_vpc.static_two.cidr_block}",
		"${aws_vpc.generated.cidr_block}",
		"${aws_vpc.generated.cidr_block}",
	}
	for i, block := range ingress {
		cidrs := block.(map[string]interface{})["cidr_blocks"].([]interface{})
		if len(cidrs) != 1 || cidrs[0] != want[i] {
			t.Fatalf("ingress[%d].cidr_blocks = %#v, want %q", i, cidrs, want[i])
		}
	}
}

// A nested dynamic block that generates a different number of blocks under each
// element of its parent keeps every generated block mapped to its source.
func TestAttributesToDocument_NestedDynamicWithVaryingCountsKeepsSources(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "b" {
  dynamic "rule" {
    for_each = { one = ["x"], two = ["y", "z"] }
    content {
      dynamic "transition" {
        for_each = rule.value
        content {
          target = aws_vpc.main.id
        }
      }
    }
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	b := findResource(t, resources, "aws_s3_bucket", "b")
	doc := AttributesToDocument(&b)
	rules, ok := doc["rule"].([]interface{})
	if !ok || len(rules) != 2 {
		t.Fatalf("rule = %#v, want two blocks", doc["rule"])
	}
	targets := 0
	for _, r := range rules {
		var transitions []interface{}
		switch tr := r.(map[string]interface{})["transition"].(type) {
		case []interface{}:
			transitions = tr
		case map[string]interface{}:
			transitions = []interface{}{tr}
		}
		for _, tr := range transitions {
			if got := tr.(map[string]interface{})["target"]; got != "${aws_vpc.main.id}" {
				t.Fatalf("transition target = %#v, want its source reference", got)
			}
			targets++
		}
	}
	if targets != 3 {
		t.Fatalf("got %d transitions, want 3", targets)
	}
}

// A dynamic block whose for_each generates more blocks than the expansion cap
// is kept as written instead of silently dropping the later ones.
func TestEvaluateModule_DynamicBlockBeyondCapStaysAsWritten(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": dynamicIngressModule(dynamicblock.MaxExpansion + 1),
	})
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	e := New()
	resources, _, _, err := e.EvaluateModule(ctx, dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	sg := findResource(t, resources, "aws_security_group", "sg")
	if _, expanded := sg.Attributes["ingress"]; expanded {
		t.Fatalf("ingress was expanded in part: %#v", sg.Attributes["ingress"])
	}
	if _, kept := sg.Attributes["dynamic"]; !kept {
		t.Fatalf("attributes = %#v, want the dynamic block kept as written", sg.Attributes)
	}
	if e.ExpansionTruncations() == 0 || e.ExpansionMaxRequested() != dynamicblock.MaxExpansion+1 {
		t.Fatalf("stats = %d truncations, max %d; want the oversized block counted",
			e.ExpansionTruncations(), e.ExpansionMaxRequested())
	}
	for _, want := range []string{
		`"expansion_kind":"dynamic"`,
		`"requested_instances":` + strconv.Itoa(dynamicblock.MaxExpansion+1),
		`"count_expansion_cap":` + strconv.Itoa(dynamicblock.MaxExpansion),
	} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log %q lacks %s", logs.String(), want)
		}
	}
}

// An oversized dynamic block is one truncation of the block, not one per
// instance of its resource or per element of a parent dynamic block.
func TestEvaluateModule_OversizedDynamicBlockIsCountedOncePerBlock(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": fmt.Sprintf(`
resource "aws_security_group" "sg" {
  count = 3
  dynamic "outer" {
    for_each = ["a", "b"]
    content {
      dynamic "ingress" {
        for_each = [%s]
        content {
          from_port = ingress.value
        }
      }
    }
  }
}
`, numberList(dynamicblock.MaxExpansion+1)),
	})
	e := New()
	if _, _, _, err := e.EvaluateModule(context.Background(), dir, nil); err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if got := e.ExpansionTruncations(); got != 1 {
		t.Fatalf("ExpansionTruncations = %d, want 1 for the one oversized block", got)
	}
}

func TestEvaluateModule_DynamicBlockAtTheCapIsExpandedQuietly(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": dynamicIngressModule(dynamicblock.MaxExpansion),
	})
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	e := New()
	resources, _, _, err := e.EvaluateModule(ctx, dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	sg := findResource(t, resources, "aws_security_group", "sg")
	if got := sg.Attributes["ingress"].LengthInt(); got != dynamicblock.MaxExpansion {
		t.Fatalf("expanded %d ingress blocks, want %d", got, dynamicblock.MaxExpansion)
	}
	if e.ExpansionTruncations() != 0 || logs.Len() != 0 {
		t.Fatalf("expansion at the cap warned: %d truncations, log %q", e.ExpansionTruncations(), logs.String())
	}
}

// The blocks of one resource are budgeted together, so several dynamic blocks
// each within the per-block cap cannot add up past the per-resource limit.
func TestEvaluateModule_DynamicBlocksShareTheResourceBudget(t *testing.T) {
	const perBlock = 200
	blocks := dynamicblock.MaxGeneratedPerResource/perBlock + 1
	var sb strings.Builder
	sb.WriteString("resource \"aws_security_group\" \"sg\" {\n")
	for i := 0; i < blocks; i++ {
		fmt.Fprintf(&sb, "  dynamic \"rule%d\" {\n    for_each = [%s]\n    content {\n      from_port = rule%d.value\n    }\n  }\n",
			i, numberList(perBlock), i)
	}
	sb.WriteString("}\n")
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": sb.String()})

	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	e := New()
	resources, _, _, err := e.EvaluateModule(ctx, dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	sg := findResource(t, resources, "aws_security_group", "sg")
	expanded, asWritten := 0, 0
	for i := 0; i < blocks; i++ {
		if _, ok := sg.Attributes[fmt.Sprintf("rule%d", i)]; ok {
			expanded++
		}
	}
	if dyn, ok := sg.Attributes["dynamic"]; ok {
		asWritten = dyn.LengthInt()
	}
	if expanded != dynamicblock.MaxGeneratedPerResource/perBlock || asWritten == 0 {
		t.Fatalf("expanded %d blocks and kept %d as written, want %d expanded and the rest as written",
			expanded, asWritten, dynamicblock.MaxGeneratedPerResource/perBlock)
	}
	if e.ExpansionTruncations() == 0 || !strings.Contains(logs.String(), `"count_expansion_cap":`+strconv.Itoa(dynamicblock.MaxGeneratedPerResource)) {
		t.Fatalf("budget overflow not reported: %d truncations, log %q", e.ExpansionTruncations(), logs.String())
	}
}

// Dynamic content reuses what does not read an iterator, but every expression
// reading its own or an enclosing iterator, or the resource's each, still varies.
func TestEvaluateModule_DynamicContentKeepsIterationValuesWithSharedOnes(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
locals {
  team = upper("platform")
}
resource "aws_s3_bucket" "b" {
  for_each = toset(["x", "y"])
  dynamic "rule" {
    for_each = ["a", "b"]
    content {
      owner    = local.team
      id       = "${each.key}-${rule.value}"
      dynamic "transition" {
        for_each = [1, 2]
        content {
          owner = local.team
          label = "${rule.value}-${transition.value}"
          who   = each.key
        }
      }
    }
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2", len(resources))
	}
	for _, r := range resources {
		key := "x"
		if strings.Contains(r.Name, `"y"`) {
			key = "y"
		}
		rules := r.Attributes["rule"].AsValueSlice()
		if len(rules) != 2 {
			t.Fatalf("%s: %d rules, want 2", r.Name, len(rules))
		}
		for i, rule := range rules {
			value := []string{"a", "b"}[i]
			if got := rule.GetAttr("owner").AsString(); got != "PLATFORM" {
				t.Fatalf("%s rule[%d].owner = %q", r.Name, i, got)
			}
			if got := rule.GetAttr("id").AsString(); got != key+"-"+value {
				t.Fatalf("%s rule[%d].id = %q, want %q", r.Name, i, got, key+"-"+value)
			}
			transitions := rule.GetAttr("transition").AsValueSlice()
			if len(transitions) != 2 {
				t.Fatalf("%s rule[%d]: %d transitions, want 2", r.Name, i, len(transitions))
			}
			for j, tr := range transitions {
				if got := tr.GetAttr("label").AsString(); got != fmt.Sprintf("%s-%d", value, j+1) {
					t.Fatalf("%s rule[%d].transition[%d].label = %q", r.Name, i, j, got)
				}
				if got := tr.GetAttr("who").AsString(); got != key {
					t.Fatalf("%s rule[%d].transition[%d].who = %q, want %q", r.Name, i, j, got, key)
				}
				if got := tr.GetAttr("owner").AsString(); got != "PLATFORM" {
					t.Fatalf("%s transition owner = %q", r.Name, got)
				}
			}
		}
	}
}

func numberList(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = strconv.Itoa(i)
	}
	return strings.Join(items, ", ")
}

func dynamicIngressModule(n int) string {
	return fmt.Sprintf(`
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [%s]
    content {
      from_port = ingress.value
    }
  }
}
`, numberList(n))
}

// A dynamic block with labels maps its generated blocks to their sources like a
// labeled static block does, including when a label equals an attribute name.
func TestAttributesToDocument_LabeledDynamicBlockKeepsSources(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
resource "aws_y" "b" {
  dynamic "setting" {
    for_each = ["k", "other", "k"]
    labels   = [setting.value]
    content {
      k    = aws_vpc.main.id
      name = aws_vpc.other.id
    }
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	b := findResource(t, resources, "aws_y", "b")
	doc := AttributesToDocument(&b)
	settings, ok := doc["setting"].(map[string]interface{})
	if !ok {
		t.Fatalf("setting = %#v, want blocks keyed by label", doc["setting"])
	}
	check := func(block interface{}) {
		t.Helper()
		m := block.(map[string]interface{})
		if m["k"] != "${aws_vpc.main.id}" || m["name"] != "${aws_vpc.other.id}" {
			t.Fatalf("block = %#v, want its source references", m)
		}
	}
	check(settings["other"])
	switch k := settings["k"].(type) {
	case []interface{}:
		for _, block := range k {
			check(block)
		}
	default:
		check(k)
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

func TestIsReportableModuleEvalError(t *testing.T) {
	if isReportableModuleEvalError(fmt.Errorf("reading module: %w", fs.ErrNotExist)) {
		t.Error("a missing local source is already reported by the module parser")
	}
	if isReportableModuleEvalError(fmt.Errorf("x: %w", ErrModuleNotEvaluated)) {
		t.Error("a module that was not evaluated is not an evaluation error")
	}
	if !isReportableModuleEvalError(errors.New("invalid expression")) {
		t.Error("other evaluation errors are reported")
	}
}

func TestEvaluateModule_KeepsScopesForAttribution(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "acl" {}

locals {
  default_acl = "private"
}

resource "aws_s3_bucket" "this" {
  count = 2
  acl   = coalesce(var.acl, local.default_acl)
}

resource "aws_s3_bucket" "single" {
  acl = var.acl
}
`,
	})
	dir := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
locals {
  acl = "public-read"
}

module "bucket" {
  source = "../child"
  acl    = local.acl
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	first := findResource(t, resources, "aws_s3_bucket", "this[0]")
	second := findResource(t, resources, "aws_s3_bucket", "this[1]")
	single := findResource(t, resources, "aws_s3_bucket", "single")
	if first.Scope == nil || first.Scope != single.Scope {
		t.Fatalf("resources of one module evaluation must share its scope")
	}
	if _, ok := first.Scope.Locals["default_acl"]; !ok {
		t.Fatalf("scope locals = %#v, want default_acl", first.Scope.Locals)
	}
	requireString(t, first.Scope.Var.AsValueMap(), "acl", "public-read")
	requireString(t, first.Scope.Local.AsValueMap(), "default_acl", "private")
	if len(first.Scope.Bodies) == 0 {
		t.Fatalf("scope must keep the module's files so referenced blocks can be read")
	}
	if single.Iteration != nil {
		t.Fatalf("a block without count or for_each has no iteration, got %#v", single.Iteration)
	}
	index := func(r ResolvedResource) int64 {
		v, _ := r.Iteration["count"].GetAttr("index").AsBigFloat().Int64()
		return v
	}
	if index(first) != 0 || index(second) != 1 {
		t.Fatalf("iteration indexes = %d, %d, want 0, 1", index(first), index(second))
	}

	if len(first.CallChain) != 1 {
		t.Fatalf("call chain = %d hops, want 1", len(first.CallChain))
	}
	site := first.CallChain[0]
	if site.Body == nil || site.Body.Attributes["acl"] == nil {
		t.Fatalf("call site must keep the module block body")
	}
	if site.Caller == nil || site.Caller.Locals["acl"] == nil {
		t.Fatalf("call site must keep the calling module's scope")
	}
	requireString(t, site.Caller.Local.AsValueMap(), "acl", "public-read")
}

// A dynamic block with a label that does not resolve for one element is kept as
// written rather than expanded without that element's labels.
func TestEvaluateModule_DynamicBlockWithUnresolvedLabelStaysAsWritten(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{
		"main.tf": `
resource "aws_y" "b" {
  dynamic "setting" {
    for_each = [{ name = "a" }, { name = null }, { name = "c" }]
    labels   = [setting.value.name]
    content {
      value = setting.value.name
    }
  }
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	b := findResource(t, resources, "aws_y", "b")
	if _, expanded := b.Attributes["setting"]; expanded {
		t.Fatalf("setting was expanded in part: %#v", b.Attributes["setting"])
	}
	if _, kept := b.Attributes["dynamic"]; !kept {
		t.Fatalf("attributes = %#v, want the dynamic block kept as written", b.Attributes)
	}
}

// A dynamic block in a module call is kept as written, however deeply nested,
// instead of being expanded outside any budget.
func TestEvalBody_ModuleCallKeepsNestedDynamicBlocksAsWritten(t *testing.T) {
	src := `
dynamic "a" {
  for_each = [1, 2, 3]
  content {
    dynamic "b" {
      for_each = [1, 2, 3]
      content {
        x = b.value
      }
    }
  }
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "m.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	out := New().evalBody(file.Body.(*hclsyntax.Body), &hcl.EvalContext{}, nil)
	if _, expanded := out["a"]; expanded {
		t.Fatalf("a was expanded: %#v", out["a"])
	}
	if _, kept := out["dynamic"]; !kept {
		t.Fatalf("out = %#v, want the dynamic block kept as written", out)
	}
}

// Each for_each instance keeps only its own element of the collection, and
// references to an instance do not expose the meta-arguments, as in Terraform.
func TestEvaluateModule_ForEachInstanceKeepsItsOwnElement(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "set" {
  for_each = toset(["a", "b", "c"])
  bucket   = each.key
}
resource "aws_s3_bucket" "map" {
  for_each = { x = "one", y = "two" }
  bucket   = each.value
}
resource "aws_s3_bucket_versioning" "v" {
  for_each = aws_s3_bucket.set
  bucket   = each.value.bucket
  note     = length(aws_s3_bucket.set["a"])
}
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "m" {
  source = "../mod"
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	byName := make(map[string]ResolvedResource)
	for _, r := range resources {
		byName[r.Type+"."+r.Name] = r
	}

	set := byName[`aws_s3_bucket.set["b"]`].Attributes["for_each"]
	require.True(t, set.Type().IsSetType())
	require.True(t, set.RawEquals(cty.SetVal([]cty.Value{cty.StringVal("b")})))

	m := byName[`aws_s3_bucket.map["y"]`].Attributes["for_each"]
	require.True(t, m.RawEquals(cty.ObjectVal(map[string]cty.Value{"y": cty.StringVal("two")})))

	// for_each over a resource still sees every instance, and an instance
	// reference has only the resource's own attributes.
	v := byName[`aws_s3_bucket_versioning.v["c"]`]
	require.Equal(t, cty.StringVal("c"), v.Attributes["bucket"])
	require.Equal(t, cty.NumberIntVal(1), v.Attributes["note"])
	require.Len(t, resources, 8)
}

func TestReferenceAttributesDropsMetaArguments(t *testing.T) {
	attrs := map[string]cty.Value{
		"bucket":   cty.StringVal("b"),
		"for_each": cty.SetVal([]cty.Value{cty.StringVal("b")}),
		"count":    cty.NumberIntVal(2),
	}
	got := referenceAttributes(attrs)
	require.Equal(t, map[string]cty.Value{"bucket": cty.StringVal("b")}, got)
	require.Len(t, attrs, 3, "the instance attributes are left unchanged")

	plain := map[string]cty.Value{"bucket": cty.StringVal("b")}
	require.Equal(t, plain, referenceAttributes(plain))
}

// Siblings reading earlier siblings, directly or through locals, see their
// outputs, and calls nobody reads still reach the module's outputs.
func TestEvaluateModule_SiblingModuleOutputs(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{
		"main.tf": `
variable "name" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.name }
output "id" { value = var.name }
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "m0" {
  source = "../leaf"
  name   = "zero"
}
module "m1" {
  source = "../leaf"
  name   = "one"
}
locals {
  first = module.m0.id
  ids   = [module.m0.id, module.m1.id, module.m2.id]
}
module "m2" {
  source = "../leaf"
  name   = "${local.first}-two"
}
module "m3" {
  source = "../leaf"
  name   = module.m2.id
}
output "ids" { value = local.ids }
`,
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	buckets := map[string]string{}
	for _, r := range resources {
		buckets[r.ModuleAddress] = r.Attributes["bucket"].AsString()
	}
	require.Equal(t, map[string]string{
		"module.m0": "zero", "module.m1": "one", "module.m2": "zero-two", "module.m3": "zero-two",
	}, buckets)
	require.True(t, outputs["ids"].RawEquals(cty.TupleVal([]cty.Value{
		cty.StringVal("zero"), cty.StringVal("one"), cty.StringVal("zero-two"),
	})))
}

// Each call of a chain sees the output of the call before it, read directly,
// through a chain of locals, by index or as part of module.* as a whole, and
// a call reading a later sibling still gets its output from the pre-pass.
func TestEvaluateModule_ChainedSiblingModuleOutputs(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{
		"main.tf": `
variable "in" {}
resource "aws_s3_bucket" "b" { bucket = var.in }
output "out" { value = var.in }
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "m0" {
  source = "../leaf"
  in     = "a"
}
module "m1" {
  source = "../leaf"
  in     = "${module.m0.out}b"
}
locals {
  via   = module.m1.out
  twice = "${local.via}c"
  fixed = "f"
}
module "m2" {
  source = "../leaf"
  in     = "${local.twice}-${local.fixed}"
}
module "m3" {
  source = "../leaf"
  in     = "${module["m2"].out}d"
}
module "m4" {
  source = "../leaf"
  in     = "${length(keys(module))}-${module.m3.out}"
}
module "m5" {
  source = "../leaf"
  in     = "${module.m6.out}-${module.m4.out}"
}
module "m6" {
  source = "../leaf"
  in     = "late"
}
module "m7" {
  source = "../leaf"
  in     = module.missing.out
}
output "last" { value = module.m5.out }
output "via" { value = local.twice }
`,
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	buckets := map[string]cty.Value{}
	for _, r := range resources {
		buckets[r.ModuleAddress] = r.Attributes["bucket"]
	}
	want := map[string]string{
		"module.m0": "a", "module.m1": "ab", "module.m2": "abc-f", "module.m3": "abc-fd",
		"module.m4": "8-abc-fd", "module.m5": "late-8-abc-fd", "module.m6": "late",
	}
	for addr, value := range want {
		require.True(t, buckets[addr].RawEquals(cty.StringVal(value)), "%s = %#v, want %q", addr, buckets[addr], value)
	}
	require.False(t, buckets["module.m7"].IsKnown())
	require.True(t, outputs["last"].RawEquals(cty.StringVal("late-8-abc-fd")))
	require.True(t, outputs["via"].RawEquals(cty.StringVal("abc")))
}

// A local re-resolved because it follows a sibling output keeps the value of a
// local it reads that does not follow one. The call reads only the combined
// local, so that value has to be present during the re-resolution.
func TestEvaluateModule_ReResolvedLocalKeepsStableLocal(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{
		"main.tf": `
variable "in" {}
resource "aws_s3_bucket" "b" { bucket = var.in }
output "out" { value = var.in }
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "m0" {
  source = "../leaf"
  in     = "a"
}
locals {
  fixed = "f"
  via   = module.m0.out
  both  = "${local.via}-${local.fixed}"
}
module "m1" {
  source = "../leaf"
  in     = local.both
}
`,
	})

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	buckets := map[string]cty.Value{}
	for _, r := range resources {
		buckets[r.ModuleAddress] = r.Attributes["bucket"]
	}
	require.True(t, buckets["module.m0"].RawEquals(cty.StringVal("a")))
	require.True(t, buckets["module.m1"].RawEquals(cty.StringVal("a-f")), "module.m1 = %#v", buckets["module.m1"])
}

// nestedBlocks builds the same value addNestedBlock does one block at a time,
// for any mix of unlabeled and labeled blocks and attributes of the same name.
func TestNestedBlocksMatchesAddNestedBlock(t *testing.T) {
	paths := [][]string{{"ingress"}, {"egress"}, {"ingress", "x"}, {"rule", "a"}, {"rule", "a", "b"}, {"rule"}}
	rng := rand.New(rand.NewSource(1))
	for run := 0; run < 2000; run++ {
		want := map[string]cty.Value{}
		got := map[string]cty.Value{}
		if rng.Intn(3) == 0 {
			attr := cty.TupleVal([]cty.Value{cty.StringVal("attr")})
			want["ingress"], got["ingress"] = attr, attr
		}
		blocks := nestedBlocks{out: got}
		for i, n := 0, rng.Intn(12); i < n; i++ {
			path := paths[rng.Intn(len(paths))]
			value := cty.ObjectVal(map[string]cty.Value{"i": cty.NumberIntVal(int64(i))})
			addNestedBlock(want, path, value)
			blocks.add(path, value)
		}
		blocks.flushAll()
		require.Equal(t, len(want), len(got), "run %d", run)
		for k, v := range want {
			require.True(t, v.RawEquals(got[k]), "run %d key %s: %#v != %#v", run, k, v, got[k])
		}
	}
}

func evaluateRoot(t *testing.T, ctx context.Context, src string) map[string]ResolvedResource {
	t.Helper()
	stack := writeModule(t, t.TempDir(), "stack", map[string]string{"main.tf": src})
	resources, _, _, err := New().EvaluateModule(ctx, stack, nil)
	require.NoError(t, err)
	return resourcesByAddress(resources)
}

// chainSource declares l0 = start and each lN reading l(N-1), in reverse so
// declaration order does not help.
func chainSource(length int, start string) string {
	var b strings.Builder
	b.WriteString("locals {\n")
	for l := length - 1; l > 0; l-- {
		fmt.Fprintf(&b, "  l%d = \"${local.l%d}x\"\n", l, l-1)
	}
	fmt.Fprintf(&b, "  l0 = %s\n}\n", start)
	return b.String()
}

// A chain of locals longer than any number of passes resolves, whatever its
// start reads: a constant, a resource, a module output, data, or a variable
// of each instance of a module loop.
func TestResolveLocals_LongChainResolves(t *testing.T) {
	const length = 60
	suffix := strings.Repeat("x", length-1)
	reader := fmt.Sprintf("resource \"aws_sqs_queue\" \"q\" { name = local.l%d }\n", length-1)
	t.Run("constant", func(t *testing.T) {
		byAddr := evaluateRoot(t, context.Background(), chainSource(length, `"v"`)+reader)
		requireString(t, byAddr["/aws_sqs_queue.q"].Attributes, "name", "v"+suffix)
	})
	t.Run("resource attribute", func(t *testing.T) {
		byAddr := evaluateRoot(t, context.Background(), chainSource(length, "aws_s3_bucket.src.bucket")+
			"resource \"aws_s3_bucket\" \"src\" { bucket = \"b\" }\n"+reader)
		requireString(t, byAddr["/aws_sqs_queue.q"].Attributes, "name", "b"+suffix)
	})
	t.Run("module output", func(t *testing.T) {
		root := t.TempDir()
		writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "in" {}
output "out" { value = var.in }
`})
		stack := writeModule(t, root, "stack", map[string]string{"main.tf": chainSource(length, "module.m.out") +
			"module \"m\" {\n  source = \"../leaf\"\n  in     = \"m\"\n}\n" + reader})
		resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
		require.NoError(t, err)
		requireString(t, resourcesByAddress(resources)["/aws_sqs_queue.q"].Attributes, "name", "m"+suffix)
	})
	t.Run("data", func(t *testing.T) {
		byAddr := evaluateRoot(t, context.Background(), chainSource(length, "data.aws_iam_policy_document.p.json")+`
data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sqs:SendMessage"]
  }
}
`+reader)
		name := byAddr["/aws_sqs_queue.q"].Attributes["name"]
		require.True(t, name.IsKnown())
		require.Contains(t, name.AsString(), "sqs:SendMessage")
		require.True(t, strings.HasSuffix(name.AsString(), suffix))
	})
	t.Run("module loop", func(t *testing.T) {
		root := t.TempDir()
		writeModule(t, root, "leaf", map[string]string{"main.tf": "variable \"name\" { type = string }\n" +
			chainSource(length, "var.name") + reader})
		stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "leaf" {
  source   = "../leaf"
  for_each = toset(["a", "b"])
  name     = each.key
}
`})
		resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
		require.NoError(t, err)
		byAddr := resourcesByAddress(resources)
		for _, key := range []string{"a", "b"} {
			requireString(t, byAddr[fmt.Sprintf("module.leaf[%q]/aws_sqs_queue.q", key)].Attributes, "name", key+suffix)
		}
	})
}

// A module call reading a local that follows an earlier call's output through
// a long chain declared out of order sees the chain resolved against that
// output, without the outputs being published before the call.
func TestResolveLocals_SiblingReadsLongChainOfModuleOutput(t *testing.T) {
	const length = 30
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "in" {}
resource "aws_s3_bucket" "b" { bucket = var.in }
output "out" { value = var.in }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": chainSource(length, "module.m0.out") + `
locals {
  fixed = "f"
}
module "m0" {
  source = "../leaf"
  in     = "a"
}
module "m1" {
  source = "../leaf"
  in     = "${local.l` + strconv.Itoa(length-1) + `}-${local.fixed}"
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	byAddr := resourcesByAddress(resources)
	requireString(t, byAddr["module.m1/aws_s3_bucket.b"].Attributes, "bucket", "a"+strings.Repeat("x", length-1)+"-f")
}

// try and can over a local declared later see that local's value, not its
// absence.
func TestResolveLocals_TryAndCanReadLaterLocal(t *testing.T) {
	byAddr := evaluateRoot(t, context.Background(), `
locals {
  a     = try(local.z, "fallback")
  known = can(local.z) ? "yes" : "no"
  z     = "real"
}
resource "aws_sqs_queue" "q" { tags = { a = local.a, known = local.known } }
`)
	tags := byAddr["/aws_sqs_queue.q"].Attributes["tags"]
	require.Equal(t, "real", tags.GetAttr("a").AsString())
	require.Equal(t, "yes", tags.GetAttr("known").AsString())
}

func TestResolveLocals_UnknownLocalStaysUnknownToReaders(t *testing.T) {
	byAddr := evaluateRoot(t, context.Background(), `
variable "unset" {}
locals {
  unknown  = var.unset
  fallback = try(local.unknown, "fallback")
  partial  = { known = "k", unknown = local.unknown }
}
resource "aws_sqs_queue" "q" {
  name = local.fallback
  tags = local.partial
}
`)
	attrs := byAddr["/aws_sqs_queue.q"].Attributes
	require.False(t, attrs["name"].IsKnown())
	require.Equal(t, "k", attrs["tags"].GetAttr("known").AsString())
	require.False(t, attrs["tags"].GetAttr("unknown").IsKnown())
}

// Terraform rejects a cycle among locals. Its locals, even one with a
// fallback, and the locals reading them are unknown; the others resolve, and
// each cycle is reported once per directory on one evaluator, however many
// instances reach it.
func TestResolveLocals_CyclesAreUnknownAndWarnedOnce(t *testing.T) {
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "n" {}
locals {
  a    = "${local.b}-a"
  b    = "${local.a}-b"
  self = "${local.self}-s"
  x    = try(local.y, "xs")
  y    = local.x
  ok   = "fine-${var.n}"
  next = "${local.a}-${local.ok}"
}
resource "aws_sqs_queue" "q" {
  name = local.ok
  tags = { a = local.a, self = local.self, next = local.next, x = local.x }
}
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `
module "leaf" {
  source   = "../leaf"
  for_each = toset(["a", "b", "c"])
  n        = each.key
}
`})
	e := New()
	for range 2 {
		resources, _, _, err := e.EvaluateModule(ctx, stack, nil)
		require.NoError(t, err)
		attrs := resourcesByAddress(resources)[`module.leaf["a"]/aws_sqs_queue.q`].Attributes
		requireString(t, attrs, "name", "fine-a")
		for _, name := range []string{"a", "self", "next", "x"} {
			require.False(t, attrs["tags"].GetAttr(name).IsKnown(), name)
		}
	}
	require.Equal(t, 3, strings.Count(logs.String(), "cycle among locals"), logs.String())
	require.Contains(t, logs.String(), `"locals":["local.a","local.b"]`)
	require.Contains(t, logs.String(), `"locals":["local.self"]`)
	require.Contains(t, logs.String(), `"locals":["local.x","local.y"]`)
}

// A directory with a cycle among its locals and a data block reading its own
// result through a local reports both, once.
func TestResolveLocals_LocalAndDataCyclesWarnedTogether(t *testing.T) {
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	stack := writeModule(t, t.TempDir(), "stack", map[string]string{"main.tf": `
locals {
  a    = local.b
  b    = local.a
  loop = data.aws_iam_policy_document.p.json
}
data "aws_iam_policy_document" "p" {
  source_policy_documents = [local.loop]
}
`})
	e := New()
	for range 2 {
		_, _, _, err := e.EvaluateModule(ctx, stack, nil)
		require.NoError(t, err)
	}
	require.Equal(t, 1, strings.Count(logs.String(), "cycle among locals"), logs.String())
	require.Equal(t, 1, strings.Count(logs.String(), "data reference cycle"), logs.String())
}

// A read of local as a whole sees the locals that do not read it back, and
// is not a cycle with a local reading its result.
func TestResolveLocals_WholeLocalRead(t *testing.T) {
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	byAddr := evaluateRoot(t, ctx, `
locals {
  pick = lookup(local, "real", "d")
  real = "r"
  next = local.pick
  z    = "zz"
  y    = keys(local)
  b    = [length(local), local.y]
}
resource "aws_sqs_queue" "q" { name = local.next }
resource "aws_sqs_queue" "keys" { name = join(",", local.b[1]) }
`)
	requireString(t, byAddr["/aws_sqs_queue.q"].Attributes, "name", "r")
	requireString(t, byAddr["/aws_sqs_queue.keys"].Attributes, "name", "real,z")
	require.NotContains(t, logs.String(), "cycle among locals")
}

func parseLocals(t *testing.T, src string) *localGraph {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	bodies := []*hclsyntax.Body{file.Body.(*hclsyntax.Body)}
	_, localExprs, _, resourceBlocks, _ := collectBlocks(bodies)
	return newLocalGraph(localExprs, declaredResourceTypes(resourceBlocks), collectDataBlocks(bodies))
}

func TestLocalGraph(t *testing.T) {
	g := parseLocals(t, `
locals {
  d     = "${local.c}${local.b}"
  c     = local.b
  b     = local.a
  a     = aws_s3_bucket.x.id
  e     = "${local.f}${local.a}"
  f     = local.e
  g     = local["a"]
  h     = local.undeclared
  m     = module.x.out
  n     = [local.m, local.h]
  p     = data.aws_iam_policy_document.p.json
  q     = local.p
  whole = keys(local)
  other = "x"
}
resource "aws_s3_bucket" "x" {}
data "aws_iam_policy_document" "p" {}
`)
	for v, reads := range g.reads {
		for _, w := range reads {
			if !g.cyclic[v] {
				require.Less(t, g.rank[w], g.rank[v], "%s reads %s", g.names[v], g.names[w])
			}
		}
	}
	require.Equal(t, [][]string{{"local.e", "local.f"}}, g.cycles)
	for _, name := range []string{"other", "a", "b", "c", "d", "g", "h", "m", "n", "p", "q"} {
		require.Less(t, g.rank[g.index[name]], g.rank[g.index["whole"]], "whole waits for %s", name)
	}
	following := func(pick func(localDeps) bool) []string {
		var out []string
		for v, deps := range g.deps {
			if pick(deps) {
				out = append(out, g.names[v])
			}
		}
		return out
	}
	require.Equal(t, []string{"a", "b", "c", "d", "e", "f", "g", "whole"}, following(func(d localDeps) bool { return d.resources }))
	require.Equal(t, []string{"m", "n", "whole"}, following(func(d localDeps) bool { return d.modules }))
	require.Equal(t, map[string]bool{"p": true, "q": true, "whole": true}, g.dataLocals)
	require.Equal(t, []int{g.index["p"], g.index["q"], g.index["whole"]}, g.dataOrder)
	require.True(t, g.readsResources)
	require.True(t, g.readsModules)
	require.Equal(t, []string{"x"}, g.siblings[g.index["m"]].modules)
	require.True(t, g.siblings[g.index["whole"]].opaque)
	require.True(t, g.siblings[g.index["p"]].opaque)
	require.Empty(t, g.cyclicData)
}

// numberChainSource declares n0 = 0 and each nN = n(N-1) + 1, in reverse, with
// a resource reading the last: every local is the same size, so evaluating
// the module costs the same per local whatever the chain's length.
func numberChainSource(length int) string {
	var b strings.Builder
	b.WriteString("locals {\n")
	for l := length - 1; l > 0; l-- {
		fmt.Fprintf(&b, "  n%d = local.n%d + 1\n", l, l-1)
	}
	fmt.Fprintf(&b, "  n0 = 0\n}\nresource \"aws_sqs_queue\" \"q\" { delay_seconds = local.n%d }\n", length-1)
	return b.String()
}

// Resolving a chain of locals declared out of order costs the same per local
// whatever its length: ns/local stays flat as the chain doubles.
func BenchmarkResolveLocalsChain(b *testing.B) {
	for _, length := range []int{50, 100, 200, 400, 800} {
		stack := filepath.Join(b.TempDir(), "stack")
		if err := os.MkdirAll(stack, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stack, "main.tf"), []byte(numberChainSource(length)), 0o644); err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("locals=%d", length), func(b *testing.B) {
			for b.Loop() {
				resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
				if err != nil || len(resources) != 1 {
					b.Fatalf("resources = %d, err = %v", len(resources), err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(length), "ns/local")
		})
	}
}

// Ephemeral resource blocks expand and are addressed like resources, with the
// instance suffix, so their instances never collapse onto the bare block.
func TestExpandBlock_EphemeralInstancesAreExpanded(t *testing.T) {
	root := t.TempDir()
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
ephemeral "aws_secretsmanager_secret" "login" {
  for_each = toset(["a", "b"])
  name     = each.key
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, 2)
	for i := range resources {
		require.Equal(t, "aws_secretsmanager_secret", resources[i].Type)
	}
	require.ElementsMatch(t, []string{
		`login["a"]`,
		`login["b"]`,
	}, []string{resources[0].Name, resources[1].Name})
}
