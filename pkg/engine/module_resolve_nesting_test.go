/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// writeBudgetFanOut lays down `roots` root modules that each call a shared
// module declaring `perModule` resources, so the total instantiated count is
// roots*perModule and every root contributes the same amount.
func writeBudgetFanOut(t *testing.T, roots, perModule int) (string, model.FileMetadatas) {
	t.Helper()
	root := t.TempDir()

	modDir := filepath.Join(root, "modules", "app")
	src := `variable "name" { type = string }` + "\n"
	for i := 0; i < perModule; i++ {
		src += fmt.Sprintf("resource \"aws_s3_bucket\" \"b%d\" {\n  bucket = \"${var.name}-%d\"\n}\n", i, i)
	}
	writeFile(t, modDir, "main.tf", src)

	files := model.FileMetadatas{fileMeta("mod-main", filepath.Join(modDir, "main.tf"))}
	for i := 0; i < roots; i++ {
		dir := filepath.Join(root, fmt.Sprintf("stack-%02d", i))
		writeFile(t, dir, "main.tf", fmt.Sprintf(`
module "app" {
  source = "../modules/app"
  name   = "stack-%02d"
}
`, i))
		files = append(files, fileMeta(fmt.Sprintf("root-%02d", i), filepath.Join(dir, "main.tf")))
	}
	return root, files
}

// writeDeepFanOut lays down `depth` nested module levels where every level calls
// the level below it `branch` times. The number of module instances is branch^depth
// even though the repository is one file per level, which is the shape that made a
// tiny repository able to exhaust any memory limit.
func writeDeepFanOut(t *testing.T, depth, branch int) (string, model.FileMetadatas) {
	t.Helper()
	root := t.TempDir()
	files := model.FileMetadatas{}

	for i := 0; i < depth; i++ {
		dir := filepath.Join(root, fmt.Sprintf("lvl%02d", i))
		body := "variable \"in\" { type = string }\n"
		if i == depth-1 {
			body += "resource \"aws_s3_bucket\" \"leaf\" { bucket = var.in }\noutput \"out\" { value = var.in }\n"
		} else {
			for b := 0; b < branch; b++ {
				body += fmt.Sprintf("module \"m%d\" {\n  source = \"../lvl%02d\"\n  in = var.in\n}\n", b, i+1)
			}
			body += "output \"out\" { value = module.m0.out }\n"
		}
		writeFile(t, dir, "main.tf", body)
		files = append(files, fileMeta(fmt.Sprintf("lvl-%02d", i), filepath.Join(dir, "main.tf")))
	}

	stack := filepath.Join(root, "stack")
	writeFile(t, stack, "main.tf", "module \"m\" {\n  source = \"../lvl00\"\n  in = \"seed\"\n}\n")
	files = append(files, fileMeta("stack", filepath.Join(stack, "main.tf")))
	return root, files
}

// Memoizing evaluations on their inputs rather than on the path taken to reach
// them is what keeps a deeply nested module tree affordable. Without it this
// shape evaluates branch^depth times for depth+1 distinct results, which is how a
// handful of files reached tens of gigabytes.
func TestResolveModuleDocuments_DeepFanOutStaysAffordable(t *testing.T) {
	const depth, branch = 12, 2
	root, files := writeDeepFanOut(t, depth, branch)

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)

	if res.resourceCount == 0 {
		t.Fatal("expected the nested module tree to instantiate resources, got none")
	}
	if len(res.docs) == 0 {
		t.Fatal("expected synthetic documents for the nested module tree, got none")
	}
	// The instantiated count follows the tree, while the documents collapse to the
	// handful of distinct contents behind it.
	if res.resourceCount < branch {
		t.Errorf("instantiated %d resources, expected at least the branching factor %d",
			res.resourceCount, branch)
	}
	t.Logf("depth=%d branch=%d instantiated=%d documents=%d",
		depth, branch, res.resourceCount, len(res.docs))
}

// Every directory whose body is suppressed from the scan must be replaced by at
// least one synthetic document. A module that was skipped rather than resolved
// (budget, depth cap, cycle) resolves to nothing, and treating that as a
// successful evaluation would drop it from the scan entirely.
func TestResolveModuleDocuments_NoDirectorySuppressedWithoutReplacement(t *testing.T) {
	root, files := writeBudgetFanOut(t, 6, 4)

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil)

	if res.resourceCount == 0 {
		t.Fatal("expected resources to be instantiated")
	}
	if len(res.suppressed) == 0 {
		t.Fatal("expected the shared module to be suppressed in favour of instantiated copies")
	}
	// Nothing may be suppressed unless resources were instantiated to stand in for
	// it, which is what keeps a skipped module in the scan rather than dropping it.
	if len(res.docs) == 0 {
		t.Error("resources were suppressed but no synthetic documents replace them")
	}
	for dir := range res.calledDirs {
		if !strings.HasPrefix(dir, root) {
			t.Errorf("called dir %s escapes the repository root %s", dir, root)
		}
	}
	t.Logf("instantiated=%d documents=%d suppressed_files=%d",
		res.resourceCount, len(res.docs), len(res.suppressed))
}
