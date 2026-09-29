/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
)

// rootEvaluationOutcome is everything evaluateRootModules produces.
type rootEvaluationOutcome struct {
	Docs, SyntheticFiles, Seen, Extras, Instantiated string
	Successful, Unresolved, Called                   map[string]bool
	ResourceCount                                    int
	RootEvalOK, BudgetExceeded                       bool
	InstantiatedCount                                int
	NotEvaluated                                     []string
}

func evaluateRootsWith(t *testing.T, workers, budget int, root string, roots []string, files model.FileMetadatas) rootEvaluationOutcome {
	t.Helper()
	previous := rootEvalWorkers
	rootEvalWorkers = workers
	defer func() { rootEvalWorkers = previous }()

	byAbsPath, filesByDir, _ := indexTerraformFiles(context.Background(), files, root)
	evaluator := tfeval.New()
	evaluator.SetMaxInstantiated(budget)
	seen := make(map[docContentKey]string)
	extras := make(map[string][]extraCallerInfo)
	instantiated := make(instantiatedIndex)
	out := rootEvaluationOutcome{Successful: map[string]bool{}, Unresolved: map[string]bool{}, Called: map[string]bool{}}
	var docs []model.Document
	var synthetic []*model.FileMetadata
	evaluateRootModules(context.Background(), evaluator, roots, filesByDir, root, nil, nil, nil,
		byAbsPath, seen, extras, instantiated, out.Successful, out.Unresolved, out.Called,
		&docs, &synthetic, &out.ResourceCount, &out.RootEvalOK)

	encode := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	out.Docs = encode(docs)
	syntheticIDs := make([][2]string, 0, len(synthetic))
	for _, f := range synthetic {
		syntheticIDs = append(syntheticIDs, [2]string{f.ID, f.FilePath})
	}
	out.SyntheticFiles = encode(syntheticIDs)
	seenPairs := make([]string, 0, len(seen))
	for key, id := range seen {
		seenPairs = append(seenPairs, fmt.Sprintf("%v=%s", key, id))
	}
	sort.Strings(seenPairs)
	out.Seen = encode(seenPairs)
	out.Extras = encode(extras)
	out.Instantiated = encode(instantiated)
	out.BudgetExceeded = evaluator.BudgetExceeded()
	out.InstantiatedCount = evaluator.InstantiatedCount()
	out.NotEvaluated = evaluator.NotEvaluatedDirs()
	sort.Strings(out.NotEvaluated)
	return out
}

func TestConcurrentRootEvaluationMatchesSerial(t *testing.T) {
	root := t.TempDir()
	bucketFile := writeFile(t, filepath.Join(root, "modules", "bucket"), "main.tf", `
variable "name" {}
variable "copies" { default = 1 }
resource "aws_s3_bucket" "b" {
  count  = var.copies
  bucket = "${var.name}-${count.index}"
}
`)
	pairFile := writeFile(t, filepath.Join(root, "modules", "pair"), "main.tf", `
variable "names" { default = ["a", "b"] }
resource "aws_s3_bucket" "p" {
  for_each = toset(var.names)
  bucket   = each.key
}
module "inner" {
  source = "../bucket"
  name   = "inner"
}
`)
	files := model.FileMetadatas{fileMeta("bucket", bucketFile), fileMeta("pair", pairFile)}
	var roots []string
	for i := range 12 {
		dir := filepath.Join(root, fmt.Sprintf("stack-%02d", i))
		// Pairs of stacks pass identical inputs, so which one owns each shared
		// document depends on the order roots are merged in.
		src := fmt.Sprintf(`
module "bucket" {
  source = "../modules/bucket"
  name   = "shared-%d"
  copies = %d
}
module "pair" {
  source = "../modules/pair"
}
resource "aws_s3_bucket" "own" { bucket = "own-%d" }
`, i/2, 1+i%3, i)
		files = append(files, fileMeta(fmt.Sprintf("stack-%02d", i), writeFile(t, dir, "main.tf", src)))
		roots = append(roots, dir)
	}
	failed := filepath.Join(root, "stack-99")
	failedFile := writeFile(t, failed, "main.tf", `module "bucket" { source = "../modules/bucket" }`)
	failedMeta := fileMeta("stack-99", failedFile)
	failedMeta.Document = model.Document{"module": map[string]any{"bucket": map[string]any{"source": "../modules/bucket"}}}
	files = append(files, failedMeta)
	roots = append(roots, failed)
	if err := os.RemoveAll(failed); err != nil {
		t.Fatal(err)
	}
	sort.Strings(roots)

	for _, budget := range []int{0, 1000, 60, 31, 17, 8, 3, 1} {
		t.Run(fmt.Sprintf("budget_%d", budget), func(t *testing.T) {
			serial := evaluateRootsWith(t, 1, budget, root, roots, files)
			if budget == 0 && serial.ResourceCount == 0 {
				t.Fatal("the fixture must instantiate module resources")
			}
			for range 10 {
				concurrent := evaluateRootsWith(t, 4, budget, root, roots, files)
				if !reflect.DeepEqual(concurrent, serial) {
					t.Fatalf("concurrent evaluation differs from serial:\nserial:     %+v\nconcurrent: %+v", serial, concurrent)
				}
			}
		})
	}
}
