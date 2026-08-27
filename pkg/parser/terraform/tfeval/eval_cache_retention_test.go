/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// writeSharedModuleFanout lays down `roots` independent root modules that all
// call the same shared module chain, which is the shape of a Terraform monorepo:
// one root per environment/region/stack over a common module library.
func writeSharedModuleFanout(t *testing.T, base string, roots, sharedDepth, resourcesPerModule int) []string {
	t.Helper()

	for i := 0; i < sharedDepth; i++ {
		dir := filepath.Join(base, "modules", fmt.Sprintf("m%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		src := fmt.Sprintf("variable \"in\" { default = \"x\" }\nlocals { p = \"${var.in}-%d\" }\n", i)
		for r := 0; r < resourcesPerModule; r++ {
			src += fmt.Sprintf(`
resource "aws_s3_bucket" "b%d" {
  bucket = "${local.p}-%d"
  tags   = { Name = "${local.p}-%d", Layer = "%d" }
}
`, r, r, r, i)
		}
		if i < sharedDepth-1 {
			src += fmt.Sprintf("module \"next\" {\n  source = \"../m%d\"\n  in     = local.p\n}\n", i+1)
			src += "output \"out\" { value = module.next.out }\n"
		} else {
			src += "output \"out\" { value = local.p }\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", dir, err)
		}
	}

	dirs := make([]string, 0, roots)
	for i := 0; i < roots; i++ {
		dir := filepath.Join(base, "stacks", fmt.Sprintf("stack%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		src := fmt.Sprintf(`
module "shared" {
  source = "../../modules/m0"
  in     = "stack%d"
}
resource "aws_s3_bucket" "root" { bucket = "stack%d-root" }
`, i, i)
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", dir, err)
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

// cachedResources counts the ResolvedResource structs the evaluation cache is
// holding. Every entry stores its whole subtree, so this is what a scan actually
// retains, not the number of resources it reports.
func cachedResources(e *Evaluator) int {
	total := 0
	for _, entry := range e.cache {
		total += len(entry.resources)
	}
	return total
}

// Every cache entry holds the resolved resources of its whole subtree, so holding
// entries for a whole repository makes peak memory scale with the number of
// roots, which is what puts a monorepo over its memory limit. Releasing between
// roots must keep retention flat as roots are added.
func TestReleaseEvalCache_RetentionDoesNotGrowWithRootCount(t *testing.T) {
	const sharedDepth = 6
	const resourcesPerModule = 4

	var firstRootRetention int
	for _, roots := range []int{1, 8, 64} {
		dirs := writeSharedModuleFanout(t, t.TempDir(), roots, sharedDepth, resourcesPerModule)

		e := New()
		peak := 0
		for _, dir := range dirs {
			if _, _, _, err := e.EvaluateModule(context.Background(), dir, nil); err != nil {
				t.Fatalf("roots=%d: EvaluateModule(%s): %v", roots, dir, err)
			}
			if got := cachedResources(e); got > peak {
				peak = got
			}
			e.ReleaseEvalCache()
		}

		if roots == 1 {
			firstRootRetention = peak
			continue
		}
		if peak != firstRootRetention {
			t.Fatalf("roots=%d: peak cached resources = %d, want %d (one root's worth); "+
				"retention must not scale with the number of roots",
				roots, peak, firstRootRetention)
		}
	}
}

// Dropping the evaluation cache between roots must not change what a root
// resolves; releasing it trades a low cross-root hit rate for a bounded peak.
func TestReleaseEvalCache_PreservesResolvedResources(t *testing.T) {
	dirs := writeSharedModuleFanout(t, t.TempDir(), 6, 5, 3)

	kept := New()
	var withCache []int
	for _, dir := range dirs {
		res, _, _, err := kept.EvaluateModule(context.Background(), dir, nil)
		if err != nil {
			t.Fatalf("EvaluateModule(%s): %v", dir, err)
		}
		withCache = append(withCache, len(res))
	}

	released := New()
	for i, dir := range dirs {
		res, _, _, err := released.EvaluateModule(context.Background(), dir, nil)
		if err != nil {
			t.Fatalf("EvaluateModule(%s): %v", dir, err)
		}
		if len(res) != withCache[i] {
			t.Fatalf("root %s resolved %d resources with a per-root cache release, want %d",
				dir, len(res), withCache[i])
		}
		released.ReleaseEvalCache()
	}
}

// ReleaseEvalCache must keep the parse cache, which is keyed by directory alone
// and is the one thing every root genuinely shares.
func TestReleaseEvalCache_KeepsParsedDirectories(t *testing.T) {
	dirs := writeSharedModuleFanout(t, t.TempDir(), 2, 4, 2)

	e := New()
	if _, _, _, err := e.EvaluateModule(context.Background(), dirs[0], nil); err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	parsedBefore := len(e.dirCache)
	if parsedBefore == 0 {
		t.Fatal("expected the first root to populate the parse cache")
	}

	e.ReleaseEvalCache()

	if got := len(e.cache); got != 0 {
		t.Fatalf("evaluation cache holds %d entries after release, want 0", got)
	}
	if got := len(e.dirCache); got != parsedBefore {
		t.Fatalf("parse cache holds %d entries after release, want %d — parsed bodies are shared across roots",
			got, parsedBefore)
	}

	e.ReleaseCaches()
	if got := len(e.dirCache); got != 0 {
		t.Fatalf("parse cache holds %d entries after ReleaseCaches, want 0", got)
	}
}
