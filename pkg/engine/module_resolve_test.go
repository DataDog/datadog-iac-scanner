/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// writeFile creates dir/name with content and returns the absolute path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func fileMeta(id, path string) *model.FileMetadata {
	return &model.FileMetadata{ID: id, FilePath: path, Document: model.Document{}}
}

func TestResolveModuleDocuments_InstantiatesAndSuppresses(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")

	rootFile := writeFile(t, rootDir, "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "prod-logs"
}
`)
	modFile := writeFile(t, modDir, "main.tf", `
variable "name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.name
}
`)

	files := model.FileMetadatas{
		fileMeta("root-id", rootFile),
		fileMeta("mod-id", modFile),
	}

	extra, suppressed, _, ok := resolveModuleDocuments(context.Background(), files, root)
	if !ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(extra) != 1 {
		t.Fatalf("expected 1 instantiated resource document, got %d: %#v", len(extra), extra)
	}
	doc := extra[0]
	if doc["id"] != "mod-id" {
		t.Fatalf("instantiated doc id = %v, want mod-id (resource definition file)", doc["id"])
	}

	resource, _ := doc["resource"].(map[string]interface{})
	bucketType, _ := resource["aws_s3_bucket"].(map[string]interface{})
	this, _ := bucketType["this"].(map[string]interface{})
	if this["bucket"] != "prod-logs" {
		t.Fatalf("instantiated bucket = %#v, want prod-logs", this["bucket"])
	}

	// The module body must be suppressed (so it isn't scanned standalone), but
	// the root file must still be scanned.
	if !suppressed["mod-id"] {
		t.Fatalf("module file should be suppressed")
	}
	if suppressed["root-id"] {
		t.Fatalf("root file should not be suppressed")
	}
}

func TestResolveModuleDocuments_RelativeFilePaths(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")

	writeFile(t, rootDir, "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "prod-logs"
}
`)
	writeFile(t, modDir, "main.tf", `
variable "name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.name
}
`)

	// FilePath is repo-relative (not cwd-absolute), as many callers provide.
	files := model.FileMetadatas{
		fileMeta("root-id", filepath.Join("stack", "main.tf")),
		fileMeta("mod-id", filepath.Join("modules", "bucket", "main.tf")),
	}

	extra, suppressed, _, ok := resolveModuleDocuments(context.Background(), files, root)
	if !ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(extra) != 1 {
		t.Fatalf("expected 1 instantiated resource document, got %d: %#v", len(extra), extra)
	}
	if doc := extra[0]; doc["id"] != "mod-id" {
		t.Fatalf("instantiated doc id = %v, want mod-id", doc["id"])
	}
	if !suppressed["mod-id"] || suppressed["root-id"] {
		t.Fatalf("unexpected suppression map: %#v", suppressed)
	}
}

func TestResolveModuleDocuments_TwoRootsSameChildDifferentVars(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "bucket")
	if err := os.MkdirAll(filepath.Join(root, "stack-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "stack-b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(root, "stack-a"), "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "from-a"
}
`)
	writeFile(t, filepath.Join(root, "stack-b"), "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "from-b"
}
`)
	modFile := writeFile(t, modDir, "main.tf", `
variable "name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.name
}
`)

	files := model.FileMetadatas{
		fileMeta("a-root", filepath.Join(root, "stack-a", "main.tf")),
		fileMeta("b-root", filepath.Join(root, "stack-b", "main.tf")),
		fileMeta("mod-id", modFile),
	}

	extra, suppressed, _, ok := resolveModuleDocuments(context.Background(), files, root)
	if !ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}
	if len(extra) != 2 {
		t.Fatalf("want 2 instantiated bucket docs (one per root), got %d: %#v", len(extra), extra)
	}
	names := make(map[string]int)
	for _, doc := range extra {
		if doc["id"] != "mod-id" {
			t.Fatalf("doc id = %v, want mod-id", doc["id"])
		}
		res, _ := doc["resource"].(map[string]interface{})
		bt, _ := res["aws_s3_bucket"].(map[string]interface{})
		th, _ := bt["this"].(map[string]interface{})
		b, _ := th["bucket"].(string)
		names[b]++
	}
	if names["from-a"] != 1 || names["from-b"] != 1 {
		t.Fatalf("bucket values = %#v, want one from-a and one from-b", names)
	}
	if !suppressed["mod-id"] {
		t.Fatalf("shared module file should be suppressed")
	}
}

func TestResolveModuleDocuments_AllRootsFailEvalNoSuppression(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	writeFile(t, stackDir, "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "x"
}
`)
	if err := os.RemoveAll(stackDir); err != nil {
		t.Fatal(err)
	}

	// Only the missing root stack is in the scan input so no other directory
	// is misclassified as an unevaluated "root" when CalledLocalDirs cannot run.
	files := model.FileMetadatas{
		fileMeta("root-id", filepath.Join("stack", "main.tf")),
	}

	extra, suppressed, _, ok := resolveModuleDocuments(context.Background(), files, root)
	if ok {
		t.Fatalf("resolveModuleDocuments ok = true, want false when all roots fail")
	}
	if len(extra) != 0 {
		t.Fatalf("want no instantiation when root eval fails, got %#v", extra)
	}
	if len(suppressed) != 0 {
		t.Fatalf("want no suppression when all root evals fail, got %#v", suppressed)
	}
}

func TestResolveModuleDocuments_OrphanModuleNotSuppressed(t *testing.T) {
	root := t.TempDir()
	// A module directory that nothing calls: it should keep being scanned
	// standalone (not suppressed) and produce no instantiated documents.
	orphan := filepath.Join(root, "orphan")
	orphanFile := writeFile(t, orphan, "main.tf", `
variable "name" { type = string }

resource "aws_s3_bucket" "this" {
  bucket = var.name
}
`)

	files := model.FileMetadatas{fileMeta("orphan-id", orphanFile)}

	extra, suppressed, _, ok := resolveModuleDocuments(context.Background(), files, root)
	if !ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true for orphan root")
	}
	if len(extra) != 0 {
		t.Fatalf("orphan module should not instantiate resources, got %#v", extra)
	}
	if suppressed["orphan-id"] {
		t.Fatalf("orphan module should not be suppressed")
	}
}

func TestResolveModuleDocuments_NestedModules(t *testing.T) {
	root := t.TempDir()

	rootFile := writeFile(t, filepath.Join(root, "stack"), "main.tf", `
module "a" {
  source = "../a"
  name   = "deep"
}
`)
	writeFile(t, filepath.Join(root, "a"), "main.tf", `
variable "name" { type = string }

module "b" {
  source = "../b"
  name   = var.name
}
`)
	leafFile := writeFile(t, filepath.Join(root, "b"), "main.tf", `
variable "name" { type = string }

resource "aws_s3_bucket" "leaf" {
  bucket = var.name
}
`)

	files := model.FileMetadatas{
		fileMeta("root-id", rootFile),
		fileMeta("a-id", filepath.Join(root, "a", "main.tf")),
		fileMeta("leaf-id", leafFile),
	}

	extra, suppressed, _, ok := resolveModuleDocuments(context.Background(), files, root)
	if !ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(extra) != 1 {
		t.Fatalf("expected 1 instantiated resource, got %d: %#v", len(extra), extra)
	}
	doc := extra[0]
	if doc["id"] != "leaf-id" {
		t.Fatalf("doc id = %v, want leaf-id", doc["id"])
	}
	resource, _ := doc["resource"].(map[string]interface{})
	bucketType, _ := resource["aws_s3_bucket"].(map[string]interface{})
	leaf, _ := bucketType["leaf"].(map[string]interface{})
	if leaf["bucket"] != "deep" {
		t.Fatalf("leaf bucket = %#v, want deep", leaf["bucket"])
	}

	if !suppressed["a-id"] || !suppressed["leaf-id"] {
		t.Fatalf("intermediate and leaf module files should be suppressed: %#v", suppressed)
	}
	if suppressed["root-id"] {
		t.Fatalf("root file should not be suppressed")
	}
}

func TestInstantiateLocalModules_NoMutationWhenResolveFails(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	writeFile(t, stackDir, "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "x"
}
`)
	if err := os.RemoveAll(stackDir); err != nil {
		t.Fatal(err)
	}

	rootFM := &model.FileMetadata{
		ID:       "root-id",
		FilePath: filepath.Join("stack", "main.tf"),
		Document: model.Document{
			"module": map[string]interface{}{
				"bucket": map[string]interface{}{"source": "../modules/bucket"},
			},
		},
	}
	files := model.FileMetadatas{rootFM}

	ins := newTestInspector(t, inspectorOpts{
		repoPath: root,
	})
	if docs := ins.instantiateLocalModules(context.Background(), files); docs != nil {
		t.Fatalf("instantiateLocalModules = %#v, want nil when resolve aborts", docs)
	}
	if _, has := rootFM.Document["module"]; !has {
		t.Fatalf("expected module block preserved on root when evaluation failed")
	}
}
