/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
	successfulRoots := map[string]bool{root: true}

	stripModuleCalls(doc, rootFile, root, calledDirs, successfulRoots, newRootIndex([]string{root}), func(source, version, callerFile, moduleName string) (string, bool) {
		if source == "terraform-aws-modules/vpc/aws" && version == "1.0.0" && callerFile == rootFile && moduleName == "remote" {
			return "/cache/vpc", true
		}
		return "", false
	})

	if _, ok := doc["module"]; ok {
		t.Fatalf("expected resolved remote module call to be stripped")
	}
}

func TestStripModuleCalls_SkipsFailedRoot(t *testing.T) {
	root := t.TempDir()
	stackA := filepath.Join(root, "stack-a")
	stackB := filepath.Join(root, "stack-b")
	rootFileB := writeFile(t, stackB, "main.tf", `
module "bucket" {
  source = "../modules/bucket"
}
`)
	doc := model.Document{
		"module": map[string]interface{}{
			"bucket": map[string]interface{}{
				"source": "../modules/bucket",
			},
		},
	}
	calledDirs := map[string]bool{filepath.Join(root, "modules", "bucket"): true}
	successfulRoots := map[string]bool{stackA: true} // stack-b eval failed

	stripModuleCalls(doc, rootFileB, root, calledDirs, successfulRoots, newRootIndex([]string{stackA, stackB}), nil)

	if _, ok := doc["module"]; !ok {
		t.Fatal("module call under a failed root must not be stripped")
	}
}

func TestInstantiatedDocs_DoesNotDuplicateStaticResourcesAcrossExpansionLayers(t *testing.T) {
	root := t.TempDir()
	modulePath := writeFile(t, filepath.Join(root, "modules", "app"), "main.tf", `
resource "aws_s3_bucket" "shared" {
  bucket = "shared"
}

resource "aws_s3_bucket" "replica" {
  count  = 2
  bucket = "replica-${count.index}"
}
`)
	fm := fileMeta("mod-id", modulePath)
	resources := []tfeval.ResolvedResource{
		{Type: "aws_s3_bucket", Name: "shared", DefinedIn: modulePath, ModuleAddress: "module.app"},
		{Type: "aws_s3_bucket", Name: "replica[0]", DefinedIn: modulePath, ModuleAddress: "module.app"},
		{Type: "aws_s3_bucket", Name: "replica[1]", DefinedIn: modulePath, ModuleAddress: "module.app"},
	}

	docs, _, _ := instantiatedDocs(
		resources,
		map[string]*model.FileMetadata{absPath(modulePath, root): fm},
		root,
		nil,
		make(map[docContentKey]string),
		make(map[string][]extraCallerInfo),
		make(instantiatedIndex),
	)

	if len(docs) != 2 {
		t.Fatalf("expected one document per expansion layer, got %d", len(docs))
	}
	var shared, replicas int
	for _, doc := range docs {
		byType, ok := asStringMap(docAsMap(doc["resource"])["aws_s3_bucket"])
		if !ok {
			t.Fatalf("resource document has unexpected shape: %#v", doc)
		}
		if _, ok := byType["shared"]; ok {
			shared++
		}
		if _, ok := byType["replica"]; ok {
			replicas++
		}
	}
	if shared != 1 {
		t.Fatalf("static resource appears %d times, want exactly once", shared)
	}
	if replicas != 2 {
		t.Fatalf("expanded resource appears %d times, want one per instance", replicas)
	}
}

func TestResolveModuleDocuments_PartialRootFailureKeepsModuleBody(t *testing.T) {
	root := t.TempDir()
	stackA := filepath.Join(root, "stack-a")
	stackB := filepath.Join(root, "stack-b")
	modDir := filepath.Join(root, "modules", "bucket")

	rootFileA := writeFile(t, stackA, "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "a"
}
`)
	writeFile(t, stackB, "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  name   = "b"
}
`)
	writeFile(t, stackB, "broken.tf", `resource "bad" {`) // unreadable root dir fails eval
	modFile := writeFile(t, modDir, "main.tf", `
variable "name" { type = string }
resource "aws_s3_bucket" "this" { bucket = var.name }
`)

	bRootPath := filepath.Join(stackB, "main.tf")
	files := model.FileMetadatas{
		fileMeta("a-root", rootFileA),
		fileMeta("mod-id", modFile),
	}
	bRoot := fileMeta("b-root", bRootPath)
	bRoot.Document = model.Document{
		"module": map[string]interface{}{
			"bucket": map[string]interface{}{
				"source": "../modules/bucket",
				"name":   "b",
			},
		},
	}
	files = append(files, bRoot)

	// Remove stack-b from disk so root evaluation fails reliably (chmod 000 is
	// ignored for root users in CI). Module discovery for the failed root uses
	// the parsed document still held in memory.
	if err := os.RemoveAll(stackB); err != nil {
		t.Fatalf("remove stack-b: %v", err)
	}

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
	if !res.ok {
		t.Fatal("expected partial module resolution to succeed")
	}
	if len(res.suppressed["mod-id"]) != 0 {
		t.Fatalf("shared module must not be suppressed when another root failed eval: %#v", res.suppressed)
	}
}

func TestResolveModuleDocuments_PartialRootFailureKeepsTransitiveModuleBody(t *testing.T) {
	root := t.TempDir()
	successfulRoot := filepath.Join(root, "successful")
	failedRoot := filepath.Join(root, "failed")
	middleDir := filepath.Join(root, "modules", "middle")
	leafDir := filepath.Join(root, "modules", "leaf")

	successfulFile := writeFile(t, successfulRoot, "main.tf", `
module "leaf" {
  source = "../modules/leaf"
}
`)
	failedFile := writeFile(t, failedRoot, "main.tf", `
module "middle" {
  source = "../modules/middle"
}
`)
	middleFile := writeFile(t, middleDir, "main.tf", `
module "leaf" {
  source = "../leaf"
}
`)
	leafFile := writeFile(t, leafDir, "main.tf", `
resource "aws_s3_bucket" "this" {
  bucket = "logs"
}
`)

	files := model.FileMetadatas{
		fileMeta("successful-root", successfulFile),
		fileMeta("middle-id", middleFile),
		fileMeta("leaf-id", leafFile),
	}
	failed := fileMeta("failed-root", failedFile)
	failed.Document = model.Document{
		"module": map[string]interface{}{
			"middle": map[string]interface{}{"source": "../modules/middle"},
		},
	}
	files = append(files, failed)

	// Preserve the parsed root document but make its on-disk evaluation fail.
	if err := os.RemoveAll(failedRoot); err != nil {
		t.Fatalf("remove failed root: %v", err)
	}

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
	if !res.ok {
		t.Fatal("expected the other root to evaluate successfully")
	}
	if len(res.suppressed["leaf-id"]) != 0 {
		t.Fatalf("transitive module beneath failed root must not be suppressed: %#v", res.suppressed)
	}
}

func TestResolveModuleDocuments_TruncatedCountKeepsSourceBlock(t *testing.T) {
	root := t.TempDir()
	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "buckets")

	rootFile := writeFile(t, rootDir, "main.tf", `
module "buckets" {
  source = "../modules/buckets"
}
`)
	modFile := writeFile(t, modDir, "main.tf", `
resource "aws_s3_bucket" "replica" {
  count  = 12
  bucket = "bucket-${count.index}"
}
`)

	files := model.FileMetadatas{
		fileMeta("root-id", rootFile),
		fileMeta("mod-id", modFile),
	}

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
	if !res.ok {
		t.Fatal("expected module resolution to succeed")
	}
	if len(res.docs) != 10 {
		t.Fatalf("expected 10 instantiated docs for truncated count, got %d", len(res.docs))
	}
	if len(res.suppressed["mod-id"]["aws_s3_bucket"]) != 0 {
		t.Fatalf("truncated expansion must not suppress the source block: %#v", res.suppressed)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
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
	if len(res.suppressed["mod-id"]) == 0 {
		t.Fatalf("module file should be suppressed")
	}
	if len(res.suppressed["root-id"]) != 0 {
		t.Fatalf("root file should not be suppressed")
	}
}

// Only the blocks that came back instantiated may be dropped from the file they
// are written in. Dropping the whole file would lose the coverage the scanner
// has today for everything else in it.
func TestRemoveInstantiatedResources(t *testing.T) {
	newDoc := func() model.Document {
		return model.Document{
			"resource": model.Document{
				"aws_s3_bucket": model.Document{
					"replaced": model.Document{"bucket": "x"},
					"kept":     model.Document{"bucket": "y"},
				},
				"aws_sqs_queue": model.Document{
					"untouched": model.Document{"name": "q"},
				},
				"_dd_lines": map[string]model.LineObject{},
			},
			"variable": model.Document{"name": model.Document{}},
		}
	}

	t.Run("removes only the instantiated block", func(t *testing.T) {
		doc := newDoc()
		removeInstantiatedResources(doc, map[string]map[string]bool{
			"aws_s3_bucket": {"replaced": true},
		})

		resources, _ := asStringMap(doc["resource"])
		buckets, _ := asStringMap(resources["aws_s3_bucket"])
		if _, gone := buckets["replaced"]; gone {
			t.Fatalf("instantiated block must not be scanned in place too: %#v", buckets)
		}
		if _, kept := buckets["kept"]; !kept {
			t.Fatalf("a block that produced no instance must keep its coverage: %#v", buckets)
		}
		if _, kept := resources["aws_sqs_queue"]; !kept {
			t.Fatalf("untouched resource types must remain: %#v", resources)
		}
		if _, kept := doc["variable"]; !kept {
			t.Fatalf("non-resource blocks must never be dropped")
		}
	})

	t.Run("drops the resource key once nothing is left under it", func(t *testing.T) {
		doc := newDoc()
		removeInstantiatedResources(doc, map[string]map[string]bool{
			"aws_s3_bucket": {"replaced": true, "kept": true},
			"aws_sqs_queue": {"untouched": true},
		})

		if _, still := doc["resource"]; still {
			t.Fatalf("only parser line metadata was left, so resource should be gone: %#v", doc)
		}
	})

	t.Run("drops a nameless block's whole type", func(t *testing.T) {
		doc := model.Document{
			"resource": model.Document{
				"aws_lb": []interface{}{model.Document{"name": "one"}},
			},
		}
		removeInstantiatedResources(doc, map[string]map[string]bool{"aws_lb": {"": true}})

		if _, still := doc["resource"]; still {
			t.Fatalf("a nameless block has no name to match, so its type must go: %#v", doc)
		}
	})
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true")
	}

	if len(res.docs) != 1 {
		t.Fatalf("expected 1 instantiated resource document, got %d: %#v", len(res.docs), res.docs)
	}
	if doc := res.docs[0]; docFileID(doc["id"]) != "mod-id" {
		t.Fatalf("instantiated doc id prefix = %v, want mod-id", docFileID(doc["id"]))
	}
	if len(res.suppressed["mod-id"]) == 0 || len(res.suppressed["root-id"]) != 0 {
		t.Fatalf("unexpected suppression map: %#v", res.suppressed)
	}
}

// writeFanOut builds a repository where roots roots all call one module. The
// module spans two files and declares three resources, so the fixture also
// covers grouping. When vary is set each root passes a different value, so
// nothing can be shared between them.
func writeFanOut(t *testing.T, roots int, vary bool) (string, model.FileMetadatas) {
	t.Helper()
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "app")

	writeFile(t, modDir, "buckets.tf", `
variable "name" { type = string }

resource "aws_s3_bucket" "primary" {
  bucket = var.name
}

resource "aws_s3_bucket" "backup" {
  bucket = "${var.name}-backup"
}
`)
	writeFile(t, modDir, "queue.tf", `
resource "aws_sqs_queue" "events" {
  name = var.name
}
`)

	files := model.FileMetadatas{
		fileMeta("mod-buckets", filepath.Join(modDir, "buckets.tf")),
		fileMeta("mod-queue", filepath.Join(modDir, "queue.tf")),
	}
	for i := range roots {
		name := "shared"
		if vary {
			name = fmt.Sprintf("root-%d", i)
		}
		dir := filepath.Join(root, fmt.Sprintf("stack-%d", i))
		writeFile(t, dir, "main.tf", fmt.Sprintf(`
module "app" {
  source = "../modules/app"
  name   = %q
}
`, name))
		files = append(files, fileMeta(fmt.Sprintf("root-%d", i), filepath.Join(dir, "main.tf")))
	}
	return root, files
}

// The payload has to stay proportional to the configuration. Roots that call a
// module with the same inputs resolve to the same content and must share
// documents; only genuinely different content may add any.
func TestResolveModuleDocuments_DocumentsDoNotGrowWithCallSites(t *testing.T) {
	const modFiles = 2

	for _, roots := range []int{1, 4, 32} {
		repo, files := writeFanOut(t, roots, false)
		res := resolveModuleDocuments(context.Background(), files, repo, nil, nil)
		if !res.ok {
			t.Fatalf("roots=%d: resolveModuleDocuments ok = false", roots)
		}
		if len(res.docs) != modFiles {
			t.Fatalf("roots=%d: %d documents, want %d — identical calls must share documents",
				roots, len(res.docs), modFiles)
		}
		// Every call site still has to be reported, through cloned findings.
		if got := deduplicatedCallerCount(&res); got != (roots-1)*modFiles {
			t.Fatalf("roots=%d: %d deduplicated callers, want %d", roots, got, (roots-1)*modFiles)
		}
		if got := len(res.syntheticFiles); got != modFiles {
			t.Fatalf("roots=%d: %d synthetic files, want one per document", roots, got)
		}
	}

	// Different inputs genuinely produce different content, so those do scale.
	repo, files := writeFanOut(t, 8, true)
	res := resolveModuleDocuments(context.Background(), files, repo, nil, nil)
	if len(res.docs) != 8*modFiles {
		t.Fatalf("%d documents for 8 differing roots, want %d", len(res.docs), 8*modFiles)
	}
}

// A module file reaches Rego the way any other Terraform file does: one
// document holding that file's resources, and nothing else.
func TestResolveModuleDocuments_DocumentMirrorsItsFile(t *testing.T) {
	repo, files := writeFanOut(t, 1, false)
	res := resolveModuleDocuments(context.Background(), files, repo, nil, nil)
	if !res.ok {
		t.Fatal("resolveModuleDocuments ok = false")
	}

	byFile := map[string]model.Document{}
	for _, doc := range res.docs {
		byFile[docFileID(doc["id"])] = doc
	}
	if len(byFile) != 2 {
		t.Fatalf("expected one document per module file, got %#v", byFile)
	}

	buckets, _ := asStringMap(byFile["mod-buckets"]["resource"])
	byName, _ := asStringMap(buckets["aws_s3_bucket"])
	if len(buckets) != 1 || len(byName) != 2 {
		t.Fatalf("both resources of buckets.tf belong in one document: %#v", buckets)
	}
	if _, leaked := buckets["aws_sqs_queue"]; leaked {
		t.Fatalf("a document must not carry another file's resources: %#v", buckets)
	}
	for _, doc := range res.docs {
		for key := range doc {
			if key != "id" && key != "file" && key != "resource" {
				t.Fatalf("unexpected key %q: a document must look like a parsed file", key)
			}
		}
	}
}

// Document ids feed finding fingerprints, so the same repository must always
// produce the same ones. Roots are discovered by walking a map, so nothing but
// an explicit ordering keeps the same caller owning a shared document.
func TestResolveModuleDocuments_DocumentIDsAreStable(t *testing.T) {
	// All roots resolve identically, so every document but one is deduplicated
	// and something has to decide which caller owns it.
	repo, files := writeFanOut(t, 8, false)

	snapshot := func() ([]string, map[string][]string) {
		res := resolveModuleDocuments(context.Background(), files, repo, nil, nil)
		ids := make([]string, 0, len(res.docs))
		for _, doc := range res.docs {
			ids = append(ids, doc["id"].(string))
		}
		extras := map[string][]string{}
		for primary, callers := range res.extras {
			for _, c := range callers {
				extras[primary] = append(extras[primary], c.docID)
			}
			sort.Strings(extras[primary])
		}
		return ids, extras
	}

	wantIDs, wantExtras := snapshot()
	for run := range 3 {
		ids, extras := snapshot()
		if !reflect.DeepEqual(ids, wantIDs) {
			t.Fatalf("run %d: documents changed between runs:\n%v\n%v", run, ids, wantIDs)
		}
		if !reflect.DeepEqual(extras, wantExtras) {
			t.Fatalf("run %d: deduplicated callers changed between runs:\n%v\n%v", run, extras, wantExtras)
		}
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
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
	if len(res.suppressed["mod-id"]) == 0 {
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
	if !res.ok {
		t.Fatalf("resolveModuleDocuments ok = false, want true for orphan root")
	}
	if len(res.docs) != 0 {
		t.Fatalf("orphan module should not instantiate resources, got %#v", res.docs)
	}
	if len(res.suppressed["orphan-id"]) != 0 {
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

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)
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

	if !res.suppressed["leaf-id"]["aws_s3_bucket"]["leaf"] {
		t.Fatalf("the instantiated leaf resource should be replaced: %#v", res.suppressed)
	}
	// The intermediate module only calls another module, so it has no resource
	// block to replace and nothing about it should be dropped.
	if len(res.suppressed["a-id"]) != 0 {
		t.Fatalf("intermediate module declares no resources, nothing to replace: %#v", res.suppressed)
	}
	if len(res.suppressed["root-id"]) != 0 {
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
	if docs, synthetic, extras := ins.instantiateLocalModules(ctx, files, nil); docs != nil || synthetic != nil || extras != nil {
		t.Fatalf("instantiateLocalModules = (%#v, %#v, %#v), want nil when resolve aborts", docs, synthetic, extras)
	}
	if _, has := rootFM.Document["module"]; !has {
		t.Fatalf("expected module block preserved on root when evaluation failed")
	}
	if !strings.Contains(logs.String(), `"module_resources_instantiated":0`) {
		t.Fatalf("expected zero instantiated resources in structured log, got %q", logs.String())
	}
}

func TestDeduplicatedCallerCount(t *testing.T) {
	res := moduleResolutionResult{
		docs: []model.Document{{}, {}},
		extras: map[string][]extraCallerInfo{
			"first":  {{}, {}},
			"second": {{}},
		},
	}

	if got := deduplicatedCallerCount(&res); got != 3 {
		t.Fatalf("deduplicatedCallerCount() = %d, want 3", got)
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
