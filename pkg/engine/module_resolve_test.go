/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/rs/zerolog"
)

// docFileID is the prefix of synthetic doc ids: fileID\x00callChain.
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

func TestBuildRemoteResolverUsesVersion(t *testing.T) {
	repoPath := t.TempDir()
	callerFile := filepath.Join(repoPath, "stack", "main.tf")
	root := filepath.Dir(callerFile)
	inspector := &Inspector{
		repoPath: repoPath,
		remoteModuleDirs: map[string]string{
			RemoteModuleKey(root, "terraform-aws-modules/vpc/aws", "1.0.0"):                             "/cache/v1",
			RemoteModuleKey(root, "terraform-aws-modules/vpc/aws", "2.0.0"):                             "/cache/v2",
			RemoteModuleKey(filepath.Join(repoPath, "other"), "terraform-aws-modules/vpc/aws", "2.0.0"): "/cache/other",
		},
	}

	resolver := inspector.buildRemoteResolver()
	got, ok := resolver("terraform-aws-modules/vpc/aws", "2.0.0", callerFile, "vpc")
	if !ok {
		t.Fatal("expected resolver hit")
	}
	if got != "/cache/v2" {
		t.Fatalf("resolved dir = %q, want /cache/v2", got)
	}

	metaResolver := inspector.buildModuleMetadataResolver()
	got, err := metaResolver.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:   "terraform-aws-modules/vpc/aws",
		Version:  "1.0.0",
		FileName: callerFile,
	})
	if err != nil {
		t.Fatalf("metadata Resolve: %v", err)
	}
	if got != "/cache/v1" {
		t.Fatalf("metadata resolved dir = %q, want /cache/v1", got)
	}
}

func TestBuildRemoteResolverPrefersCallSpecificMapping(t *testing.T) {
	repoPath := t.TempDir()
	callerFile := filepath.Join(repoPath, "main.tf")
	inspector := &Inspector{
		repoPath: repoPath,
		remoteModuleDirs: map[string]string{
			RemoteModuleKey(repoPath, "same/source/aws", "1.0.0"):             "/cache/generic",
			RemoteModuleCallKey(repoPath, "same/source/aws", "1.0.0", "call"): "/cache/call",
		},
	}

	resolver := inspector.buildRemoteResolver()
	got, ok := resolver("same/source/aws", "1.0.0", callerFile, "call")
	if !ok {
		t.Fatal("expected resolver hit")
	}
	if got != "/cache/call" {
		t.Fatalf("resolved dir = %q, want /cache/call", got)
	}
}

func TestStripModuleCallsRemovesResolvedRemoteCallSites(t *testing.T) {
	root := t.TempDir()
	rootFile := filepath.Join(root, "main.tf")
	doc := model.Document{
		"module": map[string]interface{}{
			"remote": map[string]interface{}{
				"source":  "terraform-aws-modules/vpc/aws",
				"version": "1.0.0",
			},
		},
	}
	calledDirs := map[string]bool{"/cache/vpc": true}

	stripModuleCalls(doc, rootFile, root, calledDirs, func(source, version, callerFile, moduleName string) (string, bool) {
		if source == "terraform-aws-modules/vpc/aws" && version == "1.0.0" && callerFile == rootFile && moduleName == "remote" {
			return "/cache/vpc", true
		}
		return "", false
	})

	if _, ok := doc["module"]; ok {
		t.Fatalf("expected resolved remote module call to be stripped")
	}
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

	res := resolveModuleDocuments(context.Background(), files, root, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil)
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

// Two roots, identical module inputs: one OPA doc, second caller in extras.
func TestResolveModuleDocuments_CrossRootIdenticalContentDeduped(t *testing.T) {
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

	// Both roots pass the same value so content dedup merges them.
	writeFile(t, filepath.Join(root, "stack-a"), "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "shared"
}
`)
	writeFile(t, filepath.Join(root, "stack-b"), "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "shared"
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

	res := resolveModuleDocuments(context.Background(), files, root, nil)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(res.docs) != 1 {
		t.Fatalf("want 1 deduplicated bucket doc, got %d: %#v", len(res.docs), res.docs)
	}
	primaryID, _ := res.docs[0]["id"].(string)
	if primaryID == "" {
		t.Fatalf("primary doc has no id: %#v", res.docs[0])
	}

	if len(res.extras) != 1 {
		t.Fatalf("want extras for exactly 1 primary doc, got %d: %#v", len(res.extras), res.extras)
	}
	dupes := res.extras[primaryID]
	if len(dupes) != 1 {
		t.Fatalf("want 1 deduplicated caller recorded in extras, got %d: %#v", len(dupes), dupes)
	}

	if len(res.syntheticFiles) != 1 {
		t.Fatalf("want 1 synthetic file for the primary doc, got %d", len(res.syntheticFiles))
	}

	if dupes[0].docID == primaryID {
		t.Fatalf("deduplicated caller must have a distinct doc id from the primary")
	}
	if dupes[0].callChain == res.syntheticFiles[0].ModuleCallChain {
		t.Fatalf("deduplicated caller must have a distinct call chain from the primary")
	}
	if dupes[0].callChain == "" {
		t.Fatalf("deduplicated caller must carry a non-empty call chain")
	}
}

func TestNewInstanceFileMetadata_LineInfoDocumentNotAliased(t *testing.T) {
	fm := &model.FileMetadata{
		ID: "mod-id",
		LineInfoDocument: map[string]interface{}{
			"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{"this": map[string]interface{}{}},
			},
		},
	}
	synth := newInstanceFileMetadata(fm, "synth-id", "stack|module.x")
	delete(fm.LineInfoDocument, "resource")
	if _, ok := synth.LineInfoDocument["resource"]; !ok {
		t.Fatal("synthetic LineInfoDocument must keep resource after suppression on parent")
	}
}

func TestResolveModuleDocuments_DifferentSourcesSameAttrsNotDeduped(t *testing.T) {
	root := t.TempDir()
	modA := filepath.Join(root, "modules", "bucket-a")
	modB := filepath.Join(root, "modules", "bucket-b")
	if err := os.MkdirAll(filepath.Join(root, "stack-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "stack-b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(modA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(modB, 0o755); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(root, "stack-a"), "main.tf", `
module "bucket" {
  source = "../modules/bucket-a"
  name   = "shared"
}
`)
	writeFile(t, filepath.Join(root, "stack-b"), "main.tf", `
module "bucket" {
  source = "../modules/bucket-b"
  name   = "shared"
}
`)
	modAFile := writeFile(t, modA, "main.tf", `
variable "name" { type = string }
resource "aws_s3_bucket" "this" { bucket = var.name }
`)
	modBFile := writeFile(t, modB, "main.tf", `
variable "name" { type = string }
resource "aws_s3_bucket" "this" { bucket = var.name }
`)

	files := model.FileMetadatas{
		fileMeta("a-root", filepath.Join(root, "stack-a", "main.tf")),
		fileMeta("b-root", filepath.Join(root, "stack-b", "main.tf")),
		fileMeta("mod-a", modAFile),
		fileMeta("mod-b", modBFile),
	}

	res := resolveModuleDocuments(context.Background(), files, root, nil)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}
	if len(res.docs) != 2 {
		t.Fatalf("want 2 docs (different module sources), got %d: %#v", len(res.docs), res.docs)
	}
	if len(res.extras) != 0 {
		t.Fatalf("want no dedup extras for distinct module sources, got %#v", res.extras)
	}
	docIDs := make(map[string]bool)
	for _, doc := range res.docs {
		docIDs[doc["id"].(string)] = true
	}
	if len(docIDs) != 2 {
		t.Fatalf("want 2 distinct doc ids, got %d: %#v", len(docIDs), docIDs)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil)
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
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())
	if docs, synthetic, extras := ins.instantiateLocalModules(ctx, files); docs != nil || synthetic != nil || extras != nil {
		t.Fatalf("instantiateLocalModules = (%#v, %#v, %#v), want nil when resolve aborts", docs, synthetic, extras)
	}
	if _, has := rootFM.Document["module"]; !has {
		t.Fatalf("expected module block preserved on root when evaluation failed")
	}
	if !strings.Contains(logs.String(), `"module_resources_instantiated":0`) {
		t.Fatalf("expected zero instantiated resources in structured log, got %q", logs.String())
	}
}

func TestInstantiatedModuleResourceCountIncludesDeduplicatedCallers(t *testing.T) {
	res := moduleResolutionResult{
		docs: []model.Document{{}, {}},
		extras: map[string][]extraCallerInfo{
			"first":  {{}, {}},
			"second": {{}},
		},
	}

	if got := instantiatedModuleResourceCount(&res); got != 5 {
		t.Fatalf("instantiatedModuleResourceCount() = %d, want 5", got)
	}
}

func TestCalledModuleDirsFromDocuments_LocalModule(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "bucket")
	rootFile := filepath.Join(root, "stack", "main.tf")

	dirs, ok := calledModuleDirsFromDocuments(model.FileMetadatas{
		{
			ID:       "root-id",
			FilePath: rootFile,
			Document: model.Document{
				"module": map[string]interface{}{
					"bucket": map[string]interface{}{
						"source": "../modules/bucket",
					},
				},
			},
		},
	}, root, nil)
	if !ok {
		t.Fatal("expected document-based discovery")
	}
	want := filepath.Clean(modDir)
	if len(dirs) != 1 || dirs[0] != want {
		t.Fatalf("dirs = %#v, want [%q]", dirs, want)
	}
}

func TestDiscoverCalledModuleDirs_UsesParsedDocument(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "bucket")
	rootFile := filepath.Join(root, "stack", "main.tf")

	evaluator := tfeval.New()
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())

	dirs := discoverCalledModuleDirs(ctx, evaluator, model.FileMetadatas{
		{
			ID:       "root-id",
			FilePath: rootFile,
			Document: model.Document{
				"module": map[string]interface{}{
					"bucket": map[string]interface{}{
						"source": "../modules/bucket",
					},
				},
			},
		},
	}, root, nil, filepath.Join(root, "stack"))

	want := filepath.Clean(modDir)
	if len(dirs) != 1 || dirs[0] != want {
		t.Fatalf("dirs = %#v, want [%q]", dirs, want)
	}
	if strings.Contains(logs.String(), "falling back") {
		t.Fatalf("did not expect fallback log, got %q", logs.String())
	}
}

func TestDiscoverCalledModuleDirs_FallsBackWhenDocumentEmpty(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "bucket")
	writeFile(t, modDir, "main.tf", `resource "test" "x" {}`)
	rootFile := writeFile(t, filepath.Join(root, "stack"), "main.tf", `
module "bucket" {
  source = "../modules/bucket"
}
`)

	evaluator := tfeval.New()
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())

	dirs := discoverCalledModuleDirs(ctx, evaluator, model.FileMetadatas{
		fileMeta("root-id", rootFile),
	}, root, nil, filepath.Dir(rootFile))

	want := filepath.Clean(modDir)
	if len(dirs) != 1 || dirs[0] != want {
		t.Fatalf("dirs = %#v, want [%q]", dirs, want)
	}
	if !strings.Contains(logs.String(), "falling back to directory parse") {
		t.Fatalf("expected fallback debug log, got %q", logs.String())
	}
}

func TestShouldInstantiateLocalModules(t *testing.T) {
	tests := []struct {
		name      string
		platforms []string
		files     model.FileMetadatas
		want      bool
	}{
		{
			name:      "Terraform configuration",
			platforms: []string{"Terraform"},
			files:     model.FileMetadatas{{FilePath: "main.tf"}},
			want:      true,
		},
		{
			name:      "mixed platforms",
			platforms: []string{"Dockerfile", "Terraform"},
			files:     model.FileMetadatas{{FilePath: "main.tf"}},
			want:      true,
		},
		{
			name:      "case insensitive",
			platforms: []string{"terraform"},
			files:     model.FileMetadatas{{FilePath: "main.tf"}},
			want:      true,
		},
		{
			name:      "Terraform plan JSON",
			platforms: []string{"Terraform"},
			files:     model.FileMetadatas{{FilePath: "plan.json"}},
			want:      false,
		},
		{
			name:      "other platform",
			platforms: []string{"Kubernetes"},
			files:     model.FileMetadatas{{FilePath: "main.tf"}},
			want:      false,
		},
		{name: "empty", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldInstantiateLocalModules(tt.platforms, tt.files); got != tt.want {
				t.Fatalf(
					"shouldInstantiateLocalModules(%v, %v) = %t, want %t",
					tt.platforms,
					tt.files,
					got,
					tt.want,
				)
			}
		})
	}
}
