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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// docFileID is the prefix of synthetic doc ids: fileID\x00callChain\x00name.
func docFileID(id interface{}) string {
	s, _ := id.(string)
	return strings.SplitN(s, "\x00", 2)[0]
}

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

	res := resolveModuleDocuments(context.Background(), files, root)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(res.docs) != 1 {
		t.Fatalf("expected 1 instantiated resource document, got %d: %#v", len(res.docs), res.docs)
	}
	doc := res.docs[0]
	if got := docFileID(doc["id"]); got != "mod-id" {
		t.Fatalf("instantiated doc id prefix = %v, want mod-id (resource definition file)", got)
	}

	// A synthetic file backs the document under the same id and carries the call chain.
	if len(res.syntheticFiles) != 1 {
		t.Fatalf("expected 1 synthetic file, got %d", len(res.syntheticFiles))
	}
	if res.syntheticFiles[0].ID != doc["id"] {
		t.Fatalf("synthetic file id = %v, want doc id %v", res.syntheticFiles[0].ID, doc["id"])
	}
	if res.syntheticFiles[0].ModuleCallChain == "" {
		t.Fatalf("synthetic file should carry a non-empty module call chain")
	}
	if len(res.syntheticFiles[0].Document) != 0 {
		t.Fatalf("synthetic file Document must be empty so Combine skips it")
	}

	resource, _ := doc["resource"].(map[string]interface{})
	bucketType, _ := resource["aws_s3_bucket"].(map[string]interface{})
	this, _ := bucketType["this"].(map[string]interface{})
	if this["bucket"] != "prod-logs" {
		t.Fatalf("instantiated bucket = %#v, want prod-logs", this["bucket"])
	}

	// The module body must be suppressed (so it isn't scanned standalone), but
	// the root file must still be scanned.
	if !res.suppressed["mod-id"] {
		t.Fatalf("module file should be suppressed")
	}
	if res.suppressed["root-id"] {
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

	res := resolveModuleDocuments(context.Background(), files, root)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(res.docs) != 1 {
		t.Fatalf("expected 1 instantiated resource document, got %d: %#v", len(res.docs), res.docs)
	}
	if doc := res.docs[0]; docFileID(doc["id"]) != "mod-id" {
		t.Fatalf("instantiated doc id prefix = %v, want mod-id", docFileID(doc["id"]))
	}
	if !res.suppressed["mod-id"] || res.suppressed["root-id"] {
		t.Fatalf("unexpected suppression map: %#v", res.suppressed)
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

	res := resolveModuleDocuments(context.Background(), files, root)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}
	if len(res.docs) != 2 {
		t.Fatalf("want 2 instantiated bucket docs (one per root), got %d: %#v", len(res.docs), res.docs)
	}
	names := make(map[string]int)
	docIDs := make(map[string]bool)
	for _, doc := range res.docs {
		if got := docFileID(doc["id"]); got != "mod-id" {
			t.Fatalf("doc id prefix = %v, want mod-id", got)
		}
		docIDs[doc["id"].(string)] = true
		docRes, _ := doc["resource"].(map[string]interface{})
		bt, _ := docRes["aws_s3_bucket"].(map[string]interface{})
		th, _ := bt["this"].(map[string]interface{})
		b, _ := th["bucket"].(string)
		names[b]++
	}
	if names["from-a"] != 1 || names["from-b"] != 1 {
		t.Fatalf("bucket values = %#v, want one from-a and one from-b", names)
	}
	// The two callers must produce distinct document ids and distinct call chains
	// so their findings get distinct fingerprints instead of collapsing.
	if len(docIDs) != 2 {
		t.Fatalf("want 2 distinct per-caller doc ids, got %d: %#v", len(docIDs), docIDs)
	}
	chains := make(map[string]bool)
	for _, sf := range res.syntheticFiles {
		chains[sf.ModuleCallChain] = true
	}
	if len(chains) != 2 {
		t.Fatalf("want 2 distinct module call chains (one per root), got %d: %#v", len(chains), chains)
	}
	if !res.suppressed["mod-id"] {
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

	res := resolveModuleDocuments(context.Background(), files, root)
	if res.ok {
		t.Fatalf("resolveModuleDocuments ok = true, want false when all roots fail")
	}
	if len(res.docs) != 0 {
		t.Fatalf("want no instantiation when root eval fails, got %#v", res.docs)
	}
	if len(res.suppressed) != 0 {
		t.Fatalf("want no suppression when all root evals fail, got %#v", res.suppressed)
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

	res := resolveModuleDocuments(context.Background(), files, root)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true for orphan root")
	}
	if len(res.docs) != 0 {
		t.Fatalf("orphan module should not instantiate resources, got %#v", res.docs)
	}
	if res.suppressed["orphan-id"] {
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

	res := resolveModuleDocuments(context.Background(), files, root)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(res.docs) != 1 {
		t.Fatalf("expected 1 instantiated resource, got %d: %#v", len(res.docs), res.docs)
	}
	doc := res.docs[0]
	if got := docFileID(doc["id"]); got != "leaf-id" {
		t.Fatalf("doc id prefix = %v, want leaf-id", got)
	}
	resource, _ := doc["resource"].(map[string]interface{})
	bucketType, _ := resource["aws_s3_bucket"].(map[string]interface{})
	leaf, _ := bucketType["leaf"].(map[string]interface{})
	if leaf["bucket"] != "deep" {
		t.Fatalf("leaf bucket = %#v, want deep", leaf["bucket"])
	}

	if !res.suppressed["a-id"] || !res.suppressed["leaf-id"] {
		t.Fatalf("intermediate and leaf module files should be suppressed: %#v", res.suppressed)
	}
	if res.suppressed["root-id"] {
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
	if docs, synthetic, extras := ins.instantiateLocalModules(context.Background(), files); docs != nil || synthetic != nil || extras != nil {
		t.Fatalf("instantiateLocalModules = (%#v, %#v, %#v), want nil when resolve aborts", docs, synthetic, extras)
	}
	if _, has := rootFM.Document["module"]; !has {
		t.Fatalf("expected module block preserved on root when evaluation failed")
	}
}
