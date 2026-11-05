/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// docFileID is the file-id field of a synthetic doc id
// (rootModule\x00fileID\x00moduleAddress\x00layer).
func docFileID(id interface{}) string {
	s, _ := id.(string)
	parts := strings.SplitN(s, "\x00", 3)
	if len(parts) == 3 {
		return parts[1]
	}
	return s
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
		remoteModuleDirs: map[string]RemoteModuleDirectory{
			RemoteModuleKey(root, "terraform-aws-modules/vpc/aws", "1.0.0"): {
				Path: "/cache/v1", PackageRoot: "/cache",
			},
			RemoteModuleKey(root, "terraform-aws-modules/vpc/aws", "2.0.0"): {
				Path: "/cache/v2", PackageRoot: "/cache",
			},
			RemoteModuleKey(filepath.Join(repoPath, "other"), "terraform-aws-modules/vpc/aws", "2.0.0"): {
				Path: "/cache/other", PackageRoot: "/cache",
			},
		},
	}

	resolver := inspector.buildRemoteResolver()
	got, packageRoot, ok := resolver("terraform-aws-modules/vpc/aws", "2.0.0", callerFile, "vpc")
	if !ok {
		t.Fatal("expected resolver hit")
	}
	if got != "/cache/v2" {
		t.Fatalf("resolved dir = %q, want /cache/v2", got)
	}
	if packageRoot != "/cache" {
		t.Fatalf("package root = %q, want /cache", packageRoot)
	}
}

func TestBuildRemoteResolverPrefersCallSpecificMapping(t *testing.T) {
	repoPath := t.TempDir()
	callerFile := filepath.Join(repoPath, "main.tf")
	inspector := &Inspector{
		repoPath: repoPath,
		remoteModuleDirs: map[string]RemoteModuleDirectory{
			RemoteModuleKey(repoPath, "same/source/aws", "1.0.0"): {
				Path: "/cache/generic", PackageRoot: "/cache",
			},
			RemoteModuleCallKey(repoPath, "same/source/aws", "1.0.0", "call"): {
				Path: "/cache/call", PackageRoot: "/cache",
			},
		},
	}

	resolver := inspector.buildRemoteResolver()
	got, _, ok := resolver("same/source/aws", "1.0.0", callerFile, "call")
	if !ok {
		t.Fatal("expected resolver hit")
	}
	if got != "/cache/call" {
		t.Fatalf("resolved dir = %q, want /cache/call", got)
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
		{Type: "aws_s3_bucket", Name: "shared", BaseName: "shared", DefinedIn: modulePath, ModuleAddress: "module.app"},
		{Type: "aws_s3_bucket", Name: "replica[0]", BaseName: "replica", Key: tfeval.InstanceKey{Kind: tfeval.IntKey, Int: 0}, DefinedIn: modulePath, ModuleAddress: "module.app"},
		{Type: "aws_s3_bucket", Name: "replica[1]", BaseName: "replica", Key: tfeval.InstanceKey{Kind: tfeval.IntKey, Int: 1}, DefinedIn: modulePath, ModuleAddress: "module.app"},
	}

	docs, _, _ := instantiatedDocs(
		resources,
		map[string]*model.FileMetadata{evaluatorPath(nil, absPath(modulePath, root)): fm},
		nil,
		root,
		func(dir string) string { return repoRelativeDir(dir, root, nil) },
		nil,
		make(map[docContentKey]string),
		make(map[string][]extraCallerInfo),
		make(instantiatedIndex),
		nil,
		newModuleAttributionCache(),
		make(writtenBlocks),
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
	if !res.ok {
		t.Fatal("expected the other root to evaluate successfully")
	}
	if len(res.suppressed["leaf-id"]) != 0 {
		t.Fatalf("transitive module beneath failed root must not be suppressed: %#v", res.suppressed)
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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
	if res.syntheticFiles[0].TerraformScope == nil || res.syntheticFiles[0].TerraformScope.ModuleAddress == "" {
		t.Fatalf("synthetic file should carry its module instance scope")
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

// Data blocks inside a module are instantiated per call like resources, so data
// rules see the values the call passes in and their findings land on the call.
func TestResolveModuleDocuments_InstantiatesDataBlocks(t *testing.T) {
	root := t.TempDir()
	rootFile := writeFile(t, filepath.Join(root, "stack"), "main.tf", `
module "queue" {
  source    = "../modules/queue"
  principal = "*"
}
`)
	modFile := writeFile(t, filepath.Join(root, "modules", "queue"), "main.tf", `
variable "principal" {}

data "aws_ami" "ubuntu" {
  most_recent = true
}

data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sqs:*"]
    principals {
      type        = "AWS"
      identifiers = [var.principal]
    }
  }
}

resource "aws_sqs_queue_policy" "this" {
  queue_url = "q"
  policy    = data.aws_iam_policy_document.p.json
}
`)
	files := model.FileMetadatas{fileMeta("root-id", rootFile), fileMeta("mod-id", modFile)}

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
	require.True(t, res.ok)
	require.Len(t, res.docs, 1)
	doc := res.docs[0]

	data, _ := doc["data"].(map[string]interface{})
	policyDoc, _ := data["aws_iam_policy_document"].(map[string]interface{})
	p, _ := policyDoc["p"].(map[string]interface{})
	statement, _ := p["statement"].([]interface{})[0].(map[string]interface{})
	principals, _ := statement["principals"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, []interface{}{"*"}, principals["identifiers"])
	ami, _ := data["aws_ami"].(map[string]interface{})
	require.Contains(t, ami, "ubuntu")

	resource, _ := doc["resource"].(map[string]interface{})
	policies, _ := resource["aws_sqs_queue_policy"].(map[string]interface{})
	this, _ := policies["this"].(map[string]interface{})
	require.Equal(t,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Principal":{"AWS":"*"}}]}`+"\n", this["policy"])

	require.True(t, res.suppressed["mod-id"]["data.aws_ami"]["ubuntu"])
	require.True(t, res.suppressed["mod-id"]["data.aws_iam_policy_document"]["p"])
	require.Contains(t, res.syntheticFiles[0].ModuleAttributions, moduleAttributionKey("data.aws_ami", 4, 1))
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

	t.Run("keeps a written block named like the metadata key", func(t *testing.T) {
		doc := model.Document{"resource": model.Document{"aws_s3_bucket": model.Document{
			"replaced": model.Document{"bucket": "a"},
			ddMetaKey:  model.Document{"bucket": "b"},
		}}}
		removeInstantiatedResources(doc, map[string]map[string]bool{"aws_s3_bucket": {"replaced": true}})

		resources, _ := asStringMap(doc["resource"])
		buckets, _ := asStringMap(resources["aws_s3_bucket"])
		require.Contains(t, buckets, ddMetaKey)
	})

	t.Run("removes instantiated data blocks", func(t *testing.T) {
		doc := model.Document{
			"data": model.Document{
				"aws_ami": model.Document{
					"replaced": model.Document{"most_recent": true},
					"kept":     model.Document{"most_recent": true},
				},
				"aws_iam_policy_document": model.Document{"p": model.Document{}},
			},
			"resource": model.Document{"aws_ami": model.Document{"replaced": model.Document{}}},
		}
		removeInstantiatedResources(doc, map[string]map[string]bool{
			"data.aws_ami":                 {"replaced": true},
			"data.aws_iam_policy_document": {"p": true},
		})

		data, _ := asStringMap(doc["data"])
		require.NotContains(t, data, "aws_iam_policy_document")
		amis, _ := asStringMap(data["aws_ami"])
		require.NotContains(t, amis, "replaced")
		require.Contains(t, amis, "kept")
		resources, _ := asStringMap(doc["resource"])
		require.Contains(t, resources, "aws_ami", "a resource of the same type is a different block")
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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
		res := resolveModuleDocuments(context.Background(), files, repo, relDirForTest(repo), nil, nil, nil, nil, nil, nil)
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
	res := resolveModuleDocuments(context.Background(), files, repo, relDirForTest(repo), nil, nil, nil, nil, nil, nil)
	if len(res.docs) != 8*modFiles {
		t.Fatalf("%d documents for 8 differing roots, want %d", len(res.docs), 8*modFiles)
	}
}

// A module file reaches Rego the way any other Terraform file does: one
// document holding that file's resources, and nothing else.
func TestResolveModuleDocuments_DocumentMirrorsItsFile(t *testing.T) {
	repo, files := writeFanOut(t, 1, false)
	res := resolveModuleDocuments(context.Background(), files, repo, relDirForTest(repo), nil, nil, nil, nil, nil, nil)
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
		res := resolveModuleDocuments(context.Background(), files, repo, relDirForTest(repo), nil, nil, nil, nil, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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
	// The two callers must produce distinct document ids and distinct root
	// modules so their findings get distinct fingerprints instead of collapsing.
	if len(docIDs) != 2 {
		t.Fatalf("want 2 distinct per-caller doc ids, got %d: %#v", len(docIDs), docIDs)
	}
	roots := make(map[string]bool)
	for _, sf := range res.syntheticFiles {
		if sf.TerraformScope == nil {
			t.Fatalf("synthetic file %v carries no Terraform scope", sf.ID)
		}
		roots[sf.TerraformScope.RootModule] = true
	}
	if len(roots) != 2 {
		t.Fatalf("want 2 distinct root modules (one per root), got %d: %#v", len(roots), roots)
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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
	if dupes[0].rootModule == "" {
		t.Fatalf("deduplicated caller must carry its root module directory")
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
	synth := newInstanceFileMetadata(&docGroup{fm: fm, rootModule: "stack", moduleAddress: "module.x", layer: 0})
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
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
	if docs, synthetic, extras, moduleFiles, _ := ins.instantiateLocalModules(ctx, files, nil); docs != nil || synthetic != nil || extras != nil || moduleFiles != nil {
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

func TestCalledModuleDirsFromDocuments_MergedEnvironmentLayout(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "mod", "helpers")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(root, "mod", "environments", "prod", "main.tf")

	dirs, ok := calledModuleDirsFromDocuments(t.Context(), vfs.DiskFS{}, model.FileMetadatas{
		{
			ID:       "env-id",
			FilePath: envFile,
			Document: model.Document{
				"module": map[string]interface{}{
					"helpers": map[string]interface{}{"source": "./helpers"},
				},
			},
		},
	}, root, nil)
	if !ok || !reflect.DeepEqual(dirs, []string{pathKey(modDir)}) {
		t.Fatalf("calledModuleDirsFromDocuments() = %v, %v; want [%s]", dirs, ok, pathKey(modDir))
	}
}

func TestCalledModuleDirsFromDocuments_LocalModule(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "bucket")
	rootFile := filepath.Join(root, "stack", "main.tf")

	dirs, ok := calledModuleDirsFromDocuments(t.Context(), nil, model.FileMetadatas{
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
	want := pathKey(modDir)
	if len(dirs) != 1 || dirs[0] != want {
		t.Fatalf("dirs = %#v, want [%q]", dirs, want)
	}
}

func TestResolveModuleTargetDirDoesNotFetchSkippedLocal(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "linked", "./missing")
	remote := func(_, _, _, _ string) (string, string, bool) {
		t.Error("skipped local source reached the remote resolver")
		return root, root, true
	}
	dir, ok := resolveModuleTargetDir(t.Context(), vfs.DiskFS{}, root, root, "./linked", "", "", "", remote)
	require.False(t, ok)
	require.Empty(t, dir)
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

	want := pathKey(modDir)
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

	want := pathKey(modDir)
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

// A build system merges environments/<name> into its module before running
// Terraform, so a relative source in an environment file is relative to the
// module. The called module must be instantiated from there, and its body not
// also scanned as a standalone root.
func TestResolveModuleDocuments_MergedEnvironmentLayout(t *testing.T) {
	root := t.TempDir()
	envFile := writeFile(t, filepath.Join(root, "svc", "environments", "prod"), "main.tf", `
module "bucket" {
  source = "./modules/bucket"
  name   = "prod-logs"
}
`)
	modFile := writeFile(t, filepath.Join(root, "svc", "modules", "bucket"), "main.tf", `
variable "name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.name
}
`)

	files := model.FileMetadatas{fileMeta("env-id", envFile), fileMeta("mod-id", modFile)}
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, vfs.DiskFS{}, nil)
	if !res.ok || len(res.docs) != 1 {
		t.Fatalf("expected the module instantiated once, got ok=%v docs=%#v", res.ok, res.docs)
	}
	resource, _ := res.docs[0]["resource"].(map[string]interface{})
	bucketType, _ := resource["aws_s3_bucket"].(map[string]interface{})
	this, _ := bucketType["this"].(map[string]interface{})
	if this["bucket"] != "prod-logs" {
		t.Fatalf("instantiated bucket = %#v, want the caller's prod-logs", this["bucket"])
	}
	if len(res.suppressed["mod-id"]) == 0 {
		t.Fatal("the called module must not also be scanned as a root")
	}
}

type readDirRecorder struct {
	vfs.FS
	dirs []string
}

func (r *readDirRecorder) ReadDir(name string) ([]fs.DirEntry, error) {
	r.dirs = append(r.dirs, name)
	return r.FS.ReadDir(name)
}

func noTargetFile(withModuleCall bool) *model.FileMetadata {
	file := fileMeta("main-id", "/ws/infra/main.tf")
	file.Document = model.Document{
		"resource": map[string]interface{}{
			"aws_s3_bucket": map[string]interface{}{"b": map[string]interface{}{"bucket": "x"}},
		},
	}
	if withModuleCall {
		file.Document["module"] = map[string]interface{}{
			"net": map[string]interface{}{"source": "../modules/net"},
		}
	}
	return file
}

func TestResolveModuleDocumentsReadsCalledDirWhenNothingIsEvaluated(t *testing.T) {
	memfs := vfs.NewMemFS(nil)
	targets := &ruleTargets{types: map[string]bool{"aws_instance": true}}
	files := model.FileMetadatas{noTargetFile(true)}

	res := resolveModuleDocuments(
		context.Background(), files, "/ws", relDirForTest("/ws"), nil, targets, nil, nil, memfs, nil,
	)

	require.False(t, res.ok)
	require.Equal(t, []string{"/ws/modules/net"}, memfs.MissingFiles())
}

func TestResolveModuleDocumentsSkipsDiscoveryWithoutModuleCalls(t *testing.T) {
	recorder := &readDirRecorder{FS: vfs.NewMemFS(nil)}
	targets := &ruleTargets{types: map[string]bool{"aws_instance": true}}
	files := model.FileMetadatas{noTargetFile(false)}

	res := resolveModuleDocuments(
		context.Background(), files, "/ws", relDirForTest("/ws"), nil, targets, nil, nil, recorder, nil,
	)

	require.False(t, res.ok)
	require.Empty(t, recorder.dirs)
}

func blocksDoc(section string, blocks map[string][]string) model.Document {
	byType := map[string]interface{}{}
	for typ, names := range blocks {
		byName := map[string]interface{}{}
		for _, name := range names {
			byName[name] = map[string]interface{}{"bucket": name}
		}
		byType[typ] = byName
	}
	return model.Document{section: byType}
}

func blockNames(doc map[string]interface{}, section, typ string) []string {
	var names []string
	for name := range docAsMap(docAsMap(doc[section])[typ]) {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func zeroInstanceRoot(t *testing.T, targets *ruleTargets) *model.FileMetadata {
	t.Helper()
	root := t.TempDir()
	fm := parseTerraform(t, writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  count  = 0
  bucket = "gone"
}

resource "aws_s3_bucket" "kept" {
  bucket = "kept"
}
`))[0]
	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), model.FileMetadatas{fm}, targets)
	return fm
}

func TestZeroInstanceBlockIsLeftOut(t *testing.T) {
	for _, targets := range []*ruleTargets{
		{types: map[string]bool{"aws_s3_bucket": true}},
		{types: map[string]bool{"aws_instance": true}},
	} {
		fm := zeroInstanceRoot(t, targets)
		require.Equal(t, []string{"kept"}, blockNames(fm.Document, "resource", "aws_s3_bucket"))
		require.Equal(t, []string{"kept"}, blockNames(fm.LineInfoDocument, "resource", "aws_s3_bucket"))
	}
}

func TestZeroInThisCallInstancesInAnother(t *testing.T) {
	root := t.TempDir()
	rootFile := writeFile(t, filepath.Join(root, "stack"), "main.tf", `
module "none" {
  source = "../modules/bucket"
  n      = 0
}

module "two" {
  source = "../modules/bucket"
  n      = 2
}
`)
	modFile := writeFile(t, filepath.Join(root, "modules", "bucket"), "main.tf", `
variable "n" {}

resource "aws_s3_bucket" "b" {
  count  = var.n
  bucket = "b-${count.index}"
}
`)
	files := model.FileMetadatas{fileMeta("root-id", rootFile), fileMeta("mod-id", modFile)}

	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
	require.True(t, res.ok)
	instances := 0
	for _, doc := range res.docs {
		instances += len(blockNames(doc, "resource", "aws_s3_bucket"))
	}
	require.Equal(t, 2, instances)
	require.True(t, res.suppressed["mod-id"]["aws_s3_bucket"]["b"])
}

func TestDataAndEphemeralEmptyBlocksDropIndependently(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, root, "main.tf", `
resource "aws_x" "same" {
  count = 1
}

data "aws_x" "same" {
  count = 0
}

ephemeral "aws_x" "same" {
  count = 0
}
`)
	fm := parseTerraform(t, path)[0]
	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), model.FileMetadatas{fm}, &ruleTargets{types: map[string]bool{"aws_y": true}})

	for _, doc := range []map[string]interface{}{fm.Document, fm.LineInfoDocument} {
		require.Equal(t, []string{"same"}, blockNames(doc, "resource", "aws_x"))
		require.Empty(t, blockNames(doc, "data", "aws_x"))
		require.Empty(t, blockNames(doc, ephemeralSection, "aws_x"))
	}
}

func TestUnresolvedDirKeepsEmptyBlocks(t *testing.T) {
	root := t.TempDir()
	stackA := filepath.Join(root, "stack-a")
	stackB := filepath.Join(root, "stack-b")
	call := `
module "bucket" {
  source = "../modules/bucket"
}
`
	rootA := writeFile(t, stackA, "main.tf", call)
	modFile := writeFile(t, filepath.Join(root, "modules", "bucket"), "main.tf", `
resource "aws_s3_bucket" "gone" {
  count = 0
}
`)
	mod := fileMeta("mod-id", modFile)
	mod.Document = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"gone"}})
	mod.LineInfoDocument = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"gone"}})
	rootB := fileMeta("b-root", filepath.Join(stackB, "main.tf"))
	rootB.Document = model.Document{
		"module": map[string]interface{}{"bucket": map[string]interface{}{"source": "../modules/bucket"}},
	}
	files := model.FileMetadatas{fileMeta("a-root", rootA), mod, rootB}

	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), files, nil)

	require.Equal(t, []string{"gone"}, blockNames(mod.Document, "resource", "aws_s3_bucket"))
	require.Equal(t, []string{"gone"}, blockNames(mod.LineInfoDocument, "resource", "aws_s3_bucket"))
}

func TestListShapedTypeKeepsItsEmptyBlocks(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  count = 0
}

resource "aws_s3_bucket" "kept" {}

resource "aws_instance" "i" {}
`)
	list := func() model.Document {
		return model.Document{"resource": map[string]interface{}{
			"aws_s3_bucket": []interface{}{
				map[string]interface{}{"count": 0},
				map[string]interface{}{"bucket": "kept"},
			},
			"aws_instance": map[string]interface{}{"i": map[string]interface{}{}},
		}}
	}
	fm := fileMeta("main-id", path)
	fm.Document = list()
	fm.LineInfoDocument = list()
	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), model.FileMetadatas{fm}, &ruleTargets{types: map[string]bool{"aws_instance": true}})

	for _, doc := range []map[string]interface{}{fm.Document, fm.LineInfoDocument} {
		require.Equal(t, list()["resource"].(map[string]interface{})["aws_s3_bucket"], docAsMap(doc["resource"])["aws_s3_bucket"])
	}
}

func TestEmptyInOneRootInstantiatedInAnotherIsKept(t *testing.T) {
	root := t.TempDir()
	rootA := writeFile(t, filepath.Join(root, "stack-a"), "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  n      = 0
}
`)
	rootB := writeFile(t, filepath.Join(root, "stack-b"), "main.tf", `
module "bucket" {
  source = "../modules/bucket"
  n      = 1
}
`)
	modFile := writeFile(t, filepath.Join(root, "modules", "bucket"), "main.tf", `
variable "n" {}

resource "aws_s3_bucket" "b" {
  count = var.n
}
`)
	mod := fileMeta("mod-id", modFile)
	mod.Document = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"b"}})
	docAsMap(docAsMap(mod.Document["resource"])["aws_s3_bucket"])["b"].(map[string]interface{})["count"] = "${var.n}"
	mod.LineInfoDocument = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"b"}})
	call := model.Document{"module": map[string]interface{}{"bucket": map[string]interface{}{"source": "../modules/bucket"}}}
	a, b := fileMeta("a-root", rootA), fileMeta("b-root", rootB)
	a.Document, b.Document = call, call
	files := model.FileMetadatas{a, b, mod}

	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), files, &ruleTargets{types: map[string]bool{"aws_instance": true}})

	require.Equal(t, []string{"b"}, blockNames(mod.Document, "resource", "aws_s3_bucket"))
	require.Equal(t, []string{"b"}, blockNames(mod.LineInfoDocument, "resource", "aws_s3_bucket"))
}

func TestDroppingLastBlockLeavesWellFormedDocument(t *testing.T) {
	for _, section := range []string{"resource", "data", ephemeralSection} {
		t.Run(section, func(t *testing.T) {
			root := t.TempDir()
			path := writeFile(t, root, "main.tf", fmt.Sprintf(`
%s "aws_x" "gone" {
  count = 0
}

variable "v" {}
`, section))
			newDoc := func() model.Document {
				doc := blocksDoc(section, map[string][]string{"aws_x": {"gone"}})
				doc["variable"] = map[string]interface{}{"v": map[string]interface{}{}}
				return doc
			}
			fm := fileMeta("main-id", path)
			fm.Document = newDoc()
			docAsMap(docAsMap(fm.Document[section])["aws_x"])["gone"].(map[string]interface{})["count"] = 0
			fm.LineInfoDocument = newDoc()
			ins := newTestInspector(t, inspectorOpts{repoPath: root})
			// Target aws_x so count=0 is evaluated and stripped; unrelated types
			// no longer force a full module walk.
			ins.instantiateLocalModules(context.Background(), model.FileMetadatas{fm}, &ruleTargets{types: map[string]bool{"aws_x": true}})

			want := model.Document{"variable": map[string]interface{}{"v": map[string]interface{}{}}}
			require.Equal(t, want, fm.Document)
			require.Equal(t, map[string]interface{}(want), fm.LineInfoDocument)
		})
	}
}

func TestAddDroppedBlocksSkipsFailedRootDirectory(t *testing.T) {
	repo := t.TempDir()
	failed := filepath.Join(repo, "failed")
	path := filepath.Join(failed, "main.tf")
	fm := fileMeta("failed-id", path)
	fm.Document = blocksDoc("resource", map[string][]string{"aws_x": {"gone"}})
	instantiated := make(instantiatedIndex)

	addDroppedBlocks(instantiated,
		[]tfeval.EmptyBlock{{Type: "aws_x", Name: "gone", DefinedIn: path}},
		map[string]bool{}, map[string]bool{pathKey(failed): true},
		map[string]*model.FileMetadata{pathKey(path): fm}, nil, repo)

	require.Empty(t, instantiated)
}

func metaOf(t *testing.T, doc model.Document, section, typ, name string) map[string]interface{} {
	t.Helper()
	block := docAsMap(docAsMap(docAsMap(doc[section])[typ])[name])
	meta, ok := block[ddMetaKey].(map[string]interface{})
	require.True(t, ok, "%s.%s.%s has no _dd_meta: %#v", section, typ, name, block)
	return meta
}

func scopeOfDoc(t *testing.T, res moduleResolutionResult, doc model.Document) *model.FileMetadata {
	t.Helper()
	for _, sf := range res.syntheticFiles {
		if sf.ID == doc["id"] {
			return sf
		}
	}
	t.Fatalf("no synthetic file for doc %v", doc["id"])
	return nil
}

func resolveModuleFixture(t *testing.T, calls map[string]string, moduleBody string) (moduleResolutionResult, string) {
	t.Helper()
	root := t.TempDir()
	modFile := writeFile(t, filepath.Join(root, "modules", "m"), "main.tf", moduleBody)
	files := model.FileMetadatas{fileMeta("mod-id", modFile)}
	for dir, body := range calls {
		files = append(files, fileMeta(dir+"-root", writeFile(t, filepath.Join(root, dir), "main.tf", body)))
	}
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
	require.True(t, res.ok)
	return res, root
}

func TestInstantiatedDocCarriesMeta(t *testing.T) {
	res, _ := resolveModuleFixture(t, map[string]string{"envs": `
module "m" {
  source = "../modules/m"
}
`}, `
resource "aws_s3_bucket" "b" {
  bucket = "x"
}

data "aws_iam_policy_document" "p" {
  statement {
    actions = ["s3:*"]
  }
}
`)
	require.Len(t, res.docs, 1)
	doc := res.docs[0]
	fm := scopeOfDoc(t, res, doc)

	bucket := metaOf(t, doc, "resource", "aws_s3_bucket", "b")
	policy := metaOf(t, doc, "data", "aws_iam_policy_document", "p")
	require.Equal(t, "module.m.aws_s3_bucket.b", bucket["address"])
	require.Equal(t, "module.m.data.aws_iam_policy_document.p", policy["address"])
	require.NotContains(t, bucket, "root_modules")

	id, ok := terraformIdentityFor(fm, "aws_s3_bucket", "b")
	require.True(t, ok)
	require.Equal(t, id.ResourceID, bucket["address"])
	id, ok = terraformIdentityFor(fm, "data.aws_iam_policy_document", "p")
	require.True(t, ok)
	require.Equal(t, id.ResourceID, policy["address"])
}

func TestInstantiatedDocMetaInstanceAddresses(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		res, _ := resolveModuleFixture(t, map[string]string{"envs": `
module "m" {
  source = "../modules/m"
}
`}, `
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "x"
}
`)
		require.Len(t, res.docs, 2)
		var got []string
		for _, doc := range res.docs {
			addr, _ := metaOf(t, doc, "resource", "aws_s3_bucket", "b")["address"].(string)
			got = append(got, addr)
			id, ok := terraformIdentityFor(scopeOfDoc(t, res, doc), "aws_s3_bucket", "b")
			require.True(t, ok)
			require.Equal(t, id.ResourceID, addr)
		}
		sort.Strings(got)
		require.Equal(t, []string{"module.m.aws_s3_bucket.b[0]", "module.m.aws_s3_bucket.b[1]"}, got)
	})

	t.Run("for_each", func(t *testing.T) {
		res, _ := resolveModuleFixture(t, map[string]string{"envs": `
module "m" {
  source = "../modules/m"
}
`}, `
resource "aws_s3_bucket" "b" {
  for_each = {"a$b" = 1}
  bucket   = "x"
}
`)
		require.Len(t, res.docs, 1)
		want := "module.m.aws_s3_bucket.b" + address.InstanceSuffix(cty.StringVal("a$b"))
		got := metaOf(t, res.docs[0], "resource", "aws_s3_bucket", "b")["address"]
		require.Equal(t, want, got)
		id, ok := terraformIdentityFor(scopeOfDoc(t, res, res.docs[0]), "aws_s3_bucket", "b")
		require.True(t, ok)
		require.Equal(t, id.ResourceID, got)
	})
}

const sharedModuleBody = `
variable "name" {
  type = string
}

resource "aws_s3_bucket" "b" {
  bucket = var.name
}

data "aws_iam_policy_document" "p" {
  statement {
    actions = [var.name]
  }
}
`

func twoRootCalls(nameA, nameB string) map[string]string {
	call := func(name string) string {
		return `
module "m" {
  source = "../../modules/m"
  name   = "` + name + `"
}
`
	}
	return map[string]string{"envs/a": call(nameA), "envs/b": call(nameB)}
}

func TestSharedDocListsEveryRoot(t *testing.T) {
	t.Run("identical inputs share one document", func(t *testing.T) {
		res, _ := resolveModuleFixture(t, twoRootCalls("same", "same"), sharedModuleBody)
		require.Len(t, res.docs, 1)
		require.NotContains(t, metaOf(t, res.docs[0], "resource", "aws_s3_bucket", "b"), "root_modules")
		var roots []string
		for _, fm := range res.syntheticFiles {
			roots = append(roots, fm.TerraformScope.RootModule)
		}
		for _, ex := range res.extras[res.docs[0]["id"].(string)] {
			roots = append(roots, ex.rootModule)
		}
		sort.Strings(roots)
		require.Equal(t, []string{"envs/a", "envs/b"}, roots)
	})

	t.Run("different inputs keep one root each", func(t *testing.T) {
		res, _ := resolveModuleFixture(t, twoRootCalls("one", "two"), sharedModuleBody)
		require.Len(t, res.docs, 2)
		var roots []string
		for _, fm := range res.syntheticFiles {
			require.NotContains(t, metaOf(t, res.docs[0], "resource", "aws_s3_bucket", "b"), "root_modules")
			roots = append(roots, fm.TerraformScope.RootModule)
		}
		sort.Strings(roots)
		require.Equal(t, []string{"envs/a", "envs/b"}, roots)
	})
}

func TestMetaDoesNotSplitDedup(t *testing.T) {
	res, _ := resolveModuleFixture(t, twoRootCalls("same", "same"), sharedModuleBody)
	require.Len(t, res.docs, 1)
	require.Len(t, res.syntheticFiles, 1)
}

func TestInstantiatedRootModuleDocMeta(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, filepath.Join(root, "envs"), "main.tf", `
resource "aws_s3_bucket" "b" {
  count = 2
}
`)
	res := resolveModuleDocuments(context.Background(), model.FileMetadatas{fileMeta("root-id", path)},
		root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
	require.True(t, res.ok)
	require.Len(t, res.docs, 2)
	var got []string
	for _, doc := range res.docs {
		meta := metaOf(t, doc, "resource", "aws_s3_bucket", "b")
		addr, _ := meta["address"].(string)
		got = append(got, addr)
		require.NotContains(t, meta, "root_modules")
		require.Equal(t, "envs", scopeOfDoc(t, res, doc).TerraformScope.RootModule)
		id, ok := terraformIdentityFor(scopeOfDoc(t, res, doc), "aws_s3_bucket", "b")
		require.True(t, ok)
		require.Equal(t, id.ResourceID, addr)
	}
	sort.Strings(got)
	require.Equal(t, []string{"aws_s3_bucket.b[0]", "aws_s3_bucket.b[1]"}, got)
}

func TestLayerDocumentsHoldDistinctTopLevelMaps(t *testing.T) {
	shared := map[string]interface{}{"bucket": "x"}
	entries := []instantiatedResource{{typ: "aws_s3_bucket", baseName: "b", attrs: shared}}
	fm := &model.FileMetadata{ID: "f", FilePath: "main.tf"}
	first := groupDocument(&docGroup{fm: fm, layer: 0, entries: entries, rootModule: "envs"})
	second := groupDocument(&docGroup{fm: fm, layer: 1, entries: entries, rootModule: "envs"})

	a := docAsMap(docAsMap(first["resource"])["aws_s3_bucket"])["b"].(map[string]interface{})
	b := docAsMap(docAsMap(second["resource"])["aws_s3_bucket"])["b"].(map[string]interface{})
	require.NotEqual(t, reflect.ValueOf(a).Pointer(), reflect.ValueOf(b).Pointer())
	require.NotContains(t, shared, ddMetaKey)
}

func unresolvedDirFixture(
	t *testing.T, callers map[string]string, extra ...string,
) (mod *model.FileMetadata, res moduleResolutionResult, modDir string, docRoots map[string][]string) {
	t.Helper()
	root := t.TempDir()
	modDir = filepath.Join(root, "modules", "m")
	modFile := writeFile(t, modDir, "main.tf", `resource "aws_s3_bucket" "b" {}`)
	mod = fileMeta("mod-id", modFile)
	mod.Document = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"b"}})
	mod.TerraformScope = &model.TerraformScope{RootModule: "modules/m"}
	stampWrittenMeta(mod.Document)
	files := model.FileMetadatas{mod}
	for dir, source := range callers {
		f := fileMeta(dir+"-root", filepath.Join(root, dir, "main.tf"))
		f.Document = model.Document{"module": map[string]interface{}{
			"m": map[string]interface{}{"source": source},
		}}
		files = append(files, f)
	}
	for _, dir := range extra {
		f := fileMeta(dir+"-root", writeFile(t, filepath.Join(root, dir), "main.tf", `resource "aws_s3_bucket" "ok" {}`))
		f.Document = blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"ok"}})
		files = append(files, f)
	}
	res = resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, nil, nil, nil, nil, nil)
	require.True(t, res.ok)
	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	_, _, _, _, docRoots = ins.instantiateLocalModules(context.Background(), files, nil)
	return mod, res, modDir, docRoots
}

func TestUnresolvedDirListsCallerRoots(t *testing.T) {
	mod, res, modDir, docRoots := unresolvedDirFixture(t, map[string]string{
		"envs/a": "../../modules/m", "envs/b": "../../modules/m",
	}, "ok")
	require.True(t, res.unresolvedModuleDirs[pathKey(modDir)])
	meta := metaOf(t, mod.Document, "resource", "aws_s3_bucket", "b")
	require.NotContains(t, meta, "root_modules")
	require.Equal(t, "aws_s3_bucket.b", meta["address"])
	require.Equal(t, []string{"envs/a", "envs/b", "modules/m"}, docRoots["mod-id"])
}

func TestUnresolvedDirRootsUnionCallersAndOwn(t *testing.T) {
	mod, res, modDir, docRoots := unresolvedDirFixture(t, map[string]string{"envs/a": "../../modules/m"}, "ok")
	require.True(t, res.unresolvedModuleDirs[pathKey(modDir)])
	require.NotContains(t, metaOf(t, mod.Document, "resource", "aws_s3_bucket", "b"), "root_modules")
	require.Equal(t, []string{"envs/a", "modules/m"}, docRoots["mod-id"])
}

func TestUnresolvedDirReachedThroughOpaqueCall(t *testing.T) {
	mod, res, modDir, docRoots := unresolvedDirFixture(t, map[string]string{
		"envs/a": "../../modules/m", "envs/c": "${var.src}",
	}, "ok")
	require.True(t, res.unresolvedModuleDirs[pathKey(modDir)])
	require.NotContains(t, metaOf(t, mod.Document, "resource", "aws_s3_bucket", "b"), "root_modules")
	require.Equal(t, []string{"envs/a", "envs/c", "modules/m"}, docRoots["mod-id"])
}

func TestUncalledDirKeepsOwnRoot(t *testing.T) {
	mod, res, modDir, docRoots := unresolvedDirFixture(t, map[string]string{"envs/a": "../../modules/other"}, "ok")
	require.False(t, res.unresolvedModuleDirs[pathKey(modDir)])
	require.NotContains(t, metaOf(t, mod.Document, "resource", "aws_s3_bucket", "b"), "root_modules")
	require.Equal(t, []string{"modules/m"}, docRoots["mod-id"])
}

func TestReachingRootsByDir(t *testing.T) {
	identity := func(d string) string { return d }
	unresolved := func(dirs ...string) map[string]bool {
		out := map[string]bool{}
		for _, d := range dirs {
			out[d] = true
		}
		return out
	}
	t.Run("a chain reaches the outermost root", func(t *testing.T) {
		graph := staticCallGraph{calls: map[string][]string{"root": {"mid"}, "mid": {"m"}}}
		require.Equal(t, map[string][]string{"m": {"root"}, "mid": {"root"}},
			reachingRootsByDir([]string{"root"}, graph, unresolved("m", "mid"), identity))
	})
	t.Run("a cycle terminates and still reaches the root", func(t *testing.T) {
		graph := staticCallGraph{calls: map[string][]string{"root": {"n"}, "m": {"n"}, "n": {"m"}}}
		require.Equal(t, map[string][]string{"m": {"root"}, "n": {"root"}},
			reachingRootsByDir([]string{"root"}, graph, unresolved("m", "n"), identity))
	})
	t.Run("roots come out sorted whatever their order", func(t *testing.T) {
		graph := staticCallGraph{calls: map[string][]string{"z": {"m"}, "a": {"m"}, "k": {"m"}}}
		require.Equal(t, map[string][]string{"m": {"a", "k", "z"}},
			reachingRootsByDir([]string{"z", "a", "k"}, graph, unresolved("m"), identity))
	})
	t.Run("roots sharing a relative path are listed once", func(t *testing.T) {
		graph := staticCallGraph{calls: map[string][]string{"/x/env": {"m"}, "/y/env": {"m"}}}
		strip := func(d string) string { return filepath.Base(d) }
		require.Equal(t, map[string][]string{"m": {"env"}},
			reachingRootsByDir([]string{"/x/env", "/y/env"}, graph, unresolved("m"), strip))
	})
	t.Run("a directory no root reaches is left out", func(t *testing.T) {
		graph := staticCallGraph{calls: map[string][]string{"root": {"other"}}}
		require.Empty(t, reachingRootsByDir([]string{"root"}, graph, unresolved("m"), identity))
	})
	t.Run("a root with an opaque call reaches every directory", func(t *testing.T) {
		graph := staticCallGraph{
			calls:  map[string][]string{"r1": {"m"}, "r2": nil},
			opaque: map[string]bool{"r2": true},
		}
		require.Equal(t, map[string][]string{"m": {"r1", "r2"}},
			reachingRootsByDir([]string{"r1", "r2"}, graph, unresolved("m"), identity))
	})
}

func TestUnresolvedDirKeepsCallRootsOfExternalModuleFile(t *testing.T) {
	scope := &model.TerraformScope{RootModule: "lib"}
	file := &model.FileMetadata{ID: "mod", FilePath: "/repo/lib/main.tf", TerraformScope: scope,
		Document: blocksDoc("resource", map[string][]string{"aws_s3_bucket": {"b"}})}
	stampWrittenMeta(file.Document)
	mf := &moduleFileCalls{
		scope: scope, keepWritten: true,
		calls: []moduleCall{{moduleAddress: "module.m", rootModule: "envs/b"}, {moduleAddress: "module.m", rootModule: "envs/a"}},
	}
	files := model.FileMetadatas{file}
	routeModuleFileRoots(files, map[string]*moduleFileCalls{"mod": mf})
	require.NotContains(t, metaOf(t, file.Document, "resource", "aws_s3_bucket", "b"), "root_modules")
	docRoots := documentRoots(files, &moduleResolutionResult{
		moduleFiles:     map[string]*moduleFileCalls{"mod": mf},
		unresolvedRoots: map[string][]string{moduleFileDir(file.FilePath, "/repo"): {"envs/c"}},
	}, "/repo")
	require.Equal(t, []string{"envs/a", "envs/b", "envs/c", "lib"}, docRoots["mod"])
}

const netModuleBody = `
resource "aws_subnet" "s" {
  count      = 2
  cidr_block = "10.0.0.0/24"
}

resource "aws_route_table_association" "a" {
  count     = 2
  subnet_id = aws_subnet.s[count.index].id
}
`

func netCall() map[string]string {
	return map[string]string{"envs": `
module "net" {
  source = "../modules/m"
}
`}
}

func TestInstantiatedDocCarriesReferences(t *testing.T) {
	res, _ := resolveModuleFixture(t, netCall(), netModuleBody)
	addresses := map[string]bool{}
	var refs map[string]interface{}
	for _, doc := range res.docs {
		for typ, name := range map[string]string{"aws_subnet": "s", "aws_route_table_association": "a"} {
			if _, ok := docAsMap(docAsMap(doc["resource"])[typ])[name]; !ok {
				continue
			}
			meta := metaOf(t, doc, "resource", typ, name)
			addresses[meta["address"].(string)] = true
			if meta["address"] == "module.net.aws_route_table_association.a[0]" {
				refs, _ = meta[referencesKey].(map[string]interface{})
			}
		}
	}
	require.Equal(t, map[string]interface{}{"subnet_id": []interface{}{"module.net.aws_subnet.s[0]"}}, refs)
	for _, addr := range refs["subnet_id"].([]interface{}) {
		require.True(t, addresses[addr.(string)], "%s is no document's address", addr)
	}
}

func TestReferencesNameUntargetedTypes(t *testing.T) {
	root := t.TempDir()
	files := parseTerraform(t, writeFile(t, filepath.Join(root, "modules", "m"), "main.tf", netModuleBody))
	files = append(files, parseTerraform(t, writeFile(t, filepath.Join(root, "envs"), "main.tf", netCall()["envs"]))...)
	targets := &ruleTargets{types: map[string]bool{"aws_route_table_association": true}}
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.True(t, res.ok)
	var got []interface{}
	for _, doc := range res.docs {
		require.Empty(t, docAsMap(doc["resource"])["aws_subnet"])
		meta := metaOf(t, doc, "resource", "aws_route_table_association", "a")
		if meta["address"] == "module.net.aws_route_table_association.a[1]" {
			got = meta[referencesKey].(map[string]interface{})["subnet_id"].([]interface{})
		}
	}
	require.Equal(t, []interface{}{"module.net.aws_subnet.s[1]"}, got)
}

func TestWrittenRootBlockCarriesReferences(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, filepath.Join(root, "envs"), "main.tf", `
resource "aws_subnet" "s" {
  cidr_block = "10.0.0.0/24"
}

resource "aws_route_table_association" "a" {
  subnet_id = aws_subnet.s.id
}

variable "unset" {}

locals {
  u = { a = var.unset, b = "b" }
}

resource "aws_s3_bucket" "t" {
  tags = merge(var.unset, { a = "b" })
  labels = coalesce(local.u, {})
}
`)
	files := writtenRootFiles(t, root, path)

	meta := metaOf(t, files[0].Document, "resource", "aws_route_table_association", "a")
	require.Equal(t, "aws_route_table_association.a", meta["address"])
	require.Equal(t, map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.s"}}, meta[referencesKey])
	require.Equal(t, map[string]interface{}{"subnet_id": true}, meta[unknownKey])
	subnet := metaOf(t, files[0].Document, "resource", "aws_subnet", "s")
	require.Equal(t, map[string]interface{}{"cidr_block": []interface{}{}}, subnet[referencesKey])
	require.NotContains(t, subnet, unknownKey)
	require.Equal(t, map[string]interface{}{"tags": true, "labels": true}, metaOf(t, files[0].Document, "resource", "aws_s3_bucket", "t")[unknownKey])
}

// writtenRootFiles parses paths as files of the root envs, stamped as a scan
// does, keeps an independent copy of each document as its line-info document,
// and runs module instantiation on them.
func writtenRootFiles(t *testing.T, root string, paths ...string) model.FileMetadatas {
	t.Helper()
	files := stampedRootFiles(t, paths...)
	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), files, nil)
	return files
}

func stampedRootFiles(t *testing.T, paths ...string) model.FileMetadatas {
	t.Helper()
	var files model.FileMetadatas
	for _, p := range paths {
		files = append(files, parseTerraform(t, p)...)
	}
	scope := &model.TerraformScope{RootModule: "envs"}
	for _, f := range files {
		f.TerraformScope = scope
		stampWrittenMeta(f.Document)
		f.LineInfoDocument = jsonCopy(t, f.Document)
	}
	return files
}

func blockOf(doc map[string]interface{}, typ, name string) map[string]interface{} {
	return docAsMap(docAsMap(docAsMap(doc["resource"])[typ])[name])
}

func jsonCopy(t *testing.T, v map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func asList(v interface{}) []interface{} {
	list, _ := v.([]interface{})
	return list
}

func jsonOf(t *testing.T, v interface{}) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}

const configModule = `
output "env" {
  value = "prod"
}

output "rules" {
  value = [{ port = 1 }, { port = 2 }]
}
`

func TestWrittenRootBlockCarriesEvaluatedValues(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "envs")
	writeFile(t, filepath.Join(root, "modules", "cfg"), "main.tf", configModule)
	writeFile(t, dir, "terraform.tfvars", "name = \"prod\"\n")
	path := writeFile(t, dir, "main.tf", `
variable "name" {}

module "cfg" {
  source = "../modules/cfg"
}

resource "aws_s3_bucket" "b" {
  bucket = var.name
  tags = {
    env = module.cfg.env
  }
  versioning {
    enabled = module.cfg.env == "prod"
  }
}
`)
	files := parseTerraform(t, path)
	require.Len(t, files, 1)
	before := blockOf(files[0].Document, "aws_s3_bucket", "b")
	require.Equal(t, "${module.cfg.env}", docAsMap(before["tags"])["env"])
	wantLines := jsonOf(t, before["_dd_lines"])
	wantNestedLines := jsonOf(t, docAsMap(asList(before["versioning"])[0])["_dd_lines"])

	files = writtenRootFiles(t, root, path)
	written := blockOf(files[0].Document, "aws_s3_bucket", "b")
	require.Equal(t, "prod", written["bucket"])
	require.Equal(t, "prod", docAsMap(written["tags"])["env"])
	require.Equal(t, true, docAsMap(asList(written["versioning"])[0])["enabled"])
	require.Equal(t, wantLines, jsonOf(t, written["_dd_lines"]))
	require.Equal(t, wantNestedLines, jsonOf(t, docAsMap(asList(written["versioning"])[0])["_dd_lines"]))
	meta := metaOf(t, files[0].Document, "resource", "aws_s3_bucket", "b")
	require.Equal(t, "aws_s3_bucket.b", meta["address"])
	require.NotContains(t, meta, "root_modules")
	require.NotContains(t, meta, unknownKey)

	lineInfo := blockOf(files[0].LineInfoDocument, "aws_s3_bucket", "b")
	require.Equal(t, "${module.cfg.env}", docAsMap(lineInfo["tags"])["env"])
}

func TestWrittenRootKeepsSinkResolvedFilter(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, filepath.Join(root, "envs"), "main.tf", `
resource "aws_cloudwatch_log_metric_filter" "f" {
  name    = "f"
  pattern = "{ $.eventName = \"CreateTrail\" }"
}
`)
	files := stampedRootFiles(t, path)
	require.Len(t, files, 1)
	resolved := `{"_dd_filter_expr":{"_selector":"$.eventName","_op":"=","_value":"CreateTrail"}}` + "\n"
	blockOf(files[0].Document, "aws_cloudwatch_log_metric_filter", "f")["pattern"] = resolved

	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), files, nil)

	block := blockOf(files[0].Document, "aws_cloudwatch_log_metric_filter", "f")
	require.Equal(t, resolved, block["pattern"])
	require.Equal(t, "f", block["name"])
}

func TestMergeEvaluatedKeepsSinkResolvedFilter(t *testing.T) {
	resolved := `{"_dd_filter_expr":{"_selector":"$.a","_op":"=","_value":"b"}}`
	asMap := map[string]interface{}{"_dd_filter_expr": map[string]interface{}{"_op": "="}}
	dst := map[string]interface{}{"pattern": resolved, "object": asMap, "plain": "${var.x}"}
	mergeEvaluated(dst, map[string]interface{}{"pattern": "raw", "object": "raw", "plain": "x"}, false)
	require.Equal(t, map[string]interface{}{"pattern": resolved, "object": asMap, "plain": "x"}, dst)
}

func TestParseKeepsDataReferenceText(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, filepath.Join(root, "envs"), "main.tf", `
data "aws_iam_policy_document" "p" {
  statement {
    actions = ["s3:GetObject"]
  }
}

resource "aws_iam_policy" "b" {
  policy = data.aws_iam_policy_document.p.json
}
`)
	files := parseTerraform(t, path)
	require.Len(t, files, 1)
	require.Equal(t, "${data.aws_iam_policy_document.p.json}", blockOf(files[0].Document, "aws_iam_policy", "b")["policy"])

	files = writtenRootFiles(t, root, path)
	require.Equal(t,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`+"\n",
		blockOf(files[0].Document, "aws_iam_policy", "b")["policy"])
}

func TestWrittenRootNonResourceBlocksEvaluated(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "envs")
	modulePath := writeFile(t, filepath.Join(root, "modules", "m"), "main.tf", `
variable "env" {}

locals {
  inner = var.env
}
`)
	writeFile(t, dir, "terraform.tfvars", "region = \"eu-west-1\"\nenv = \"prod\"\n")
	path := writeFile(t, dir, "main.tf", `
variable "region" {}
variable "env" {}

provider "aws" {
  region = var.region
}

provider "aws" {
  alias  = "b"
  region = var.region
}

locals {
  env = var.env
}

locals {
  name = "${local.env}-x"
}

output "o" {
  value = local.env
}

module "m" {
  source = "../modules/m"
  env    = local.env
}
`)
	other := filepath.Join(root, "other")
	writeFile(t, other, "terraform.tfvars", "env = \"dev\"\n")
	otherPath := writeFile(t, other, "main.tf", `
variable "env" {}

locals {
  env = var.env
}

output "p" {
  value = local.env
}
`)
	before := stampedRootFiles(t, path, modulePath)
	wantRootLines := jsonOf(t, before[0].Document["_dd_lines"])
	wantModuleDoc := jsonOf(t, before[1].Document)
	wantProviderLines := jsonOf(t, docAsMap(docAsMap(before[0].Document["provider"])["aws"].([]interface{})[1])["_dd_lines"])
	wantCallLines := jsonOf(t, docAsMap(docAsMap(before[0].Document["module"])["m"])["_dd_lines"])
	require.Equal(t, "${var.env}", docAsMap(before[1].Document["locals"])["inner"])

	files := writtenRootFiles(t, root, path, modulePath, otherPath)
	require.Equal(t, "dev", docAsMap(docAsMap(files[2].Document["output"])["p"])["value"])
	doc := files[0].Document
	providers, ok := docAsMap(doc["provider"])["aws"].([]interface{})
	require.True(t, ok)
	require.Len(t, providers, 2)
	require.Equal(t, "eu-west-1", docAsMap(providers[0])["region"])
	require.Equal(t, "eu-west-1", docAsMap(providers[1])["region"])
	require.Equal(t, "b", docAsMap(providers[1])["alias"])
	require.Equal(t, wantProviderLines, jsonOf(t, docAsMap(providers[1])["_dd_lines"]))
	locals, ok := doc["locals"].([]interface{})
	require.True(t, ok)
	require.Equal(t, "prod", docAsMap(locals[0])["env"])
	require.Equal(t, "prod-x", docAsMap(locals[1])["name"])
	require.Equal(t, "prod", docAsMap(docAsMap(doc["output"])["o"])["value"])
	call := docAsMap(docAsMap(doc["module"])["m"])
	require.Equal(t, "prod", call["env"])
	require.Equal(t, "../modules/m", call["source"])
	require.Equal(t, wantCallLines, jsonOf(t, call["_dd_lines"]))
	require.Equal(t, wantRootLines, jsonOf(t, doc["_dd_lines"]))
	require.Equal(t, wantModuleDoc, jsonOf(t, files[1].Document))
}

func TestMergeEvaluatedKeepsBookkeeping(t *testing.T) {
	lines := func(n int) map[string]interface{} {
		return map[string]interface{}{"_dd__default": map[string]interface{}{"_dd_line": n}}
	}
	dst := map[string]interface{}{
		"_dd_lines": lines(1),
		"_dd_meta":  map[string]interface{}{"address": "t.n"},
		"name":      "${var.name}",
		"kept":      "converter",
		"nested": map[string]interface{}{
			"_dd_lines": lines(2),
			"value":     "${var.v}",
		},
		"rule": []interface{}{
			map[string]interface{}{"_dd_lines": lines(3), "port": "${var.p}"},
			map[string]interface{}{"_dd_lines": lines(4), "port": 2},
		},
		"ports": []interface{}{"${var.p}"},
		"grown": []interface{}{map[string]interface{}{"_dd_lines": lines(5), "port": "${var.p}"}},
	}
	mergeEvaluated(dst, map[string]interface{}{
		"_dd_meta": "evaluated",
		"name":     "n",
		"nested":   map[string]interface{}{"value": "v"},
		"rule": []interface{}{
			map[string]interface{}{"port": json.Number("1")},
			map[string]interface{}{"port": json.Number("2")},
		},
		"ports": []interface{}{json.Number("1"), json.Number("2")},
		"grown": []interface{}{map[string]interface{}{"port": json.Number("1")}, map[string]interface{}{"port": json.Number("2")}},
		"added": true,
	}, false)
	require.Equal(t, map[string]interface{}{
		"_dd_lines": lines(1),
		"_dd_meta":  map[string]interface{}{"address": "t.n"},
		"name":      "n",
		"kept":      "converter",
		"nested":    map[string]interface{}{"_dd_lines": lines(2), "value": "v"},
		"rule": []interface{}{
			map[string]interface{}{"_dd_lines": lines(3), "port": json.Number("1")},
			map[string]interface{}{"_dd_lines": lines(4), "port": json.Number("2")},
		},
		"ports": []interface{}{json.Number("1"), json.Number("2")},
		"grown": []interface{}{map[string]interface{}{"port": json.Number("1")}, map[string]interface{}{"port": json.Number("2")}},
		"added": true,
	}, dst)
}

func TestWrittenDynamicBlockLengthDiffers(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "modules", "cfg"), "main.tf", configModule)
	path := writeFile(t, filepath.Join(root, "envs"), "main.tf", `
module "cfg" {
  source = "../modules/cfg"
}

resource "aws_security_group" "g" {
  ingress {
    from_port = 0
  }
  dynamic "ingress" {
    for_each = module.cfg.rules
    content {
      from_port = ingress.value.port
    }
  }
}
`)
	files := parseTerraform(t, path)
	before := blockOf(files[0].Document, "aws_security_group", "g")
	require.Len(t, asList(before["ingress"]), 1)
	wantLines := jsonOf(t, before["_dd_lines"])
	require.Contains(t, wantLines, `"_dd_ingress":{"_dd_line":7}`)
	require.Contains(t, before, "dynamic")

	files = writtenRootFiles(t, root, path)
	g := blockOf(files[0].Document, "aws_security_group", "g")
	require.Equal(t, []interface{}{
		map[string]interface{}{"from_port": json.Number("0")},
		map[string]interface{}{"from_port": json.Number("1")},
		map[string]interface{}{"from_port": json.Number("2")},
	}, g["ingress"])
	require.Equal(t, wantLines, jsonOf(t, g["_dd_lines"]))
	require.NotContains(t, g, "dynamic")
}

func TestWrittenEmptyDynamicBlockDropsTemplate(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "modules", "cfg"), "main.tf", configModule)
	path := writeFile(t, filepath.Join(root, "envs"), "main.tf", `
module "cfg" {
  source = "../modules/cfg"
}

resource "aws_security_group" "g" {
  name = "g"
  dynamic "ingress" {
    for_each = [for r in module.cfg.rules : r if false]
    content {
      from_port = ingress.value.port
    }
  }
}
`)
	before := blockOf(parseTerraform(t, path)[0].Document, "aws_security_group", "g")
	require.Contains(t, before, "dynamic")

	g := blockOf(writtenRootFiles(t, root, path)[0].Document, "aws_security_group", "g")
	require.NotContains(t, g, "ingress")
	require.NotContains(t, g, "dynamic")
}

func TestWrittenFailedRootKeepsText(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "envs")
	writeFile(t, filepath.Join(root, "modules", "cfg"), "main.tf", configModule)
	path := writeFile(t, dir, "main.tf", `
module "cfg" {
  source = "../modules/cfg"
}

resource "aws_s3_bucket" "b" {
  bucket = var.x
  tags = {
    env = module.cfg.env
  }
}
`)
	files := stampedRootFiles(t, path)
	want := jsonOf(t, files[0].Document)
	require.NoError(t, os.RemoveAll(dir))

	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), files, nil)
	require.Equal(t, want, jsonOf(t, files[0].Document))
	require.Equal(t, "${module.cfg.env}", docAsMap(blockOf(files[0].Document, "aws_s3_bucket", "b")["tags"])["env"])
	require.Equal(t, "${var.x}", blockOf(files[0].Document, "aws_s3_bucket", "b")["bucket"])
	meta := metaOf(t, files[0].Document, "resource", "aws_s3_bucket", "b")
	require.NotContains(t, meta, referencesKey)
	require.Equal(t, map[string]interface{}{"bucket": true, "tags": map[string]interface{}{"env": true}}, meta[unknownKey])
}

func TestWrittenRootEvaluatedValueIsNotUnknown(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, filepath.Join(root, "envs"), "main.tf", `
variable "x" {
  default = "b"
}

resource "aws_s3_bucket" "b" {
  bucket = var.x
}
`)
	files := stampedRootFiles(t, path)
	require.Equal(t, map[string]interface{}{"bucket": true}, metaOf(t, files[0].Document, "resource", "aws_s3_bucket", "b")[unknownKey])

	ins := newTestInspector(t, inspectorOpts{repoPath: root})
	ins.instantiateLocalModules(context.Background(), files, nil)
	require.Equal(t, "b", blockOf(files[0].Document, "aws_s3_bucket", "b")["bucket"])
	require.NotContains(t, metaOf(t, files[0].Document, "resource", "aws_s3_bucket", "b"), unknownKey)
}

func TestWrittenJSONRootBlockCarriesEvaluatedValues(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "envs")
	writeFile(t, filepath.Join(root, "modules", "cfg"), "main.tf", configModule)
	writeFile(t, dir, "main.tf", `
module "cfg" {
  source = "../modules/cfg"
}
`)
	path := writeFile(t, dir, "main.tf.json", `{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "bucket": "${module.cfg.env}"
      }
    }
  }
}
`)
	files := parseTerraform(t, path)
	require.Len(t, files, 1)
	wantLines := jsonOf(t, blockOf(files[0].Document, "aws_s3_bucket", "b")["_dd_lines"])

	files = writtenRootFiles(t, root, path)
	b := blockOf(files[0].Document, "aws_s3_bucket", "b")
	require.Equal(t, "prod", b["bucket"])
	require.Equal(t, wantLines, jsonOf(t, b["_dd_lines"]))
	require.Equal(t, "aws_s3_bucket.b", metaOf(t, files[0].Document, "resource", "aws_s3_bucket", "b")["address"])
}

func TestPatchWrittenBlocksSkipsListShapedTypes(t *testing.T) {
	listed := []interface{}{map[string]interface{}{"n": map[string]interface{}{ddMetaKey: map[string]interface{}{}, "v": "text"}}}
	file := &model.FileMetadata{ID: "f", Document: model.Document{"resource": map[string]interface{}{"t": listed}}}
	want := jsonOf(t, file.Document)
	patchWrittenBlocks(model.FileMetadatas{file}, writtenBlocks{
		resolvedBlockKey("f", "t", "n"): {attrs: map[string]interface{}{"v": "evaluated"}},
	})
	require.Equal(t, want, jsonOf(t, file.Document))
}

// Every root block written once is patched in its written file, targeted or
// not, so its _dd_meta does not depend on the rules loaded.
func TestWrittenBlocksHoldEverySingleRootBlock(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "envs")
	writeFile(t, dir, "terraform.tfvars", "name = \"prod\"\n")
	files := parseTerraform(t, writeFile(t, dir, "expanded.tf", `
resource "aws_s3_bucket" "e" {
  count  = 2
  bucket = var.name
}

resource "aws_s3_bucket" "sibling" {
  bucket = var.name
}
`))
	files = append(files, parseTerraform(t, writeFile(t, dir, "main.tf", `
variable "name" {}

resource "aws_s3_bucket" "w" {
  bucket = var.name
}

resource "aws_iam_role" "u" {
  name = var.name
}
`))...)
	targets := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.True(t, res.ok)
	keys := make([]string, 0, len(res.written))
	for k := range res.written {
		keys = append(keys, k)
	}
	require.ElementsMatch(t, []string{
		resolvedBlockKey(files[0].ID, "aws_s3_bucket", "sibling"),
		resolvedBlockKey(files[1].ID, "aws_s3_bucket", "w"),
		resolvedBlockKey(files[1].ID, "aws_iam_role", "u"),
	}, keys)
}

func TestInstantiatedDocCarriesUnknown(t *testing.T) {
	res, _ := resolveModuleFixture(t, map[string]string{"envs": `
module "m" {
  source = "../modules/m"
}
`}, `
variable "unset" {}

locals {
  u = { a = var.unset, b = "b" }
}

resource "aws_s3_bucket" "b" {
  bucket = var.unset
}

resource "aws_s3_bucket" "c" {
  bucket = "c"
}
`)
	require.Len(t, res.docs, 1)
	require.Equal(t, map[string]interface{}{"bucket": true}, metaOf(t, res.docs[0], "resource", "aws_s3_bucket", "b")[unknownKey])
	require.NotContains(t, metaOf(t, res.docs[0], "resource", "aws_s3_bucket", "c"), unknownKey)
}

func TestRootRewriteKeepsReferences(t *testing.T) {
	refs := map[string]interface{}{"subnet_id": []interface{}{"aws_subnet.s"}}
	extras := blockMetaExtras{references: refs, unknown: map[string]interface{}{"subnet_id": true}}
	newDoc := func(id string) model.Document {
		return model.Document{"id": id, "resource": map[string]interface{}{"aws_x": map[string]interface{}{
			"n": map[string]interface{}{ddMetaKey: resourceMeta("aws_x.n", extras)},
		}}}
	}
	scope := &model.TerraformScope{RootModule: "lib"}
	file := &model.FileMetadata{ID: "mod", FilePath: "/repo/lib/main.tf", TerraformScope: scope, Document: newDoc("mod")}
	mf := &moduleFileCalls{scope: scope, keepWritten: true, calls: []moduleCall{{moduleAddress: "module.m", rootModule: "envs/a"}}}
	files := model.FileMetadatas{file}
	routeModuleFileRoots(files, map[string]*moduleFileCalls{"mod": mf})
	meta := metaOf(t, file.Document, "resource", "aws_x", "n")
	require.NotContains(t, meta, "root_modules")
	require.Equal(t, refs, meta[referencesKey])
	require.Equal(t, extras.unknown, meta[unknownKey])
}
