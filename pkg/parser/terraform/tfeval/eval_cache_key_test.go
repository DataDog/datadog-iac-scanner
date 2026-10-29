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
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// writeNestedFanOut lays down `depth` nested module levels where every level
// calls the level below it `branch` times. The repository is one file per level,
// but the module tree it describes has branch^depth instances.
func writeNestedFanOut(t *testing.T, depth, branch int) string {
	t.Helper()
	root := t.TempDir()

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
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	stack := filepath.Join(root, "stack")
	if err := os.MkdirAll(stack, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stack, "main.tf"),
		[]byte("module \"m\" {\n  source = \"../lvl00\"\n  in = \"seed\"\n}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return stack
}

// A module reached by many paths with the same inputs must be evaluated once. When
// the call chain was part of the cache key this shape cost branch^depth
// evaluations, so a repository of a dozen files could exhaust any memory limit:
// depth 12 alone produced over 8,000 cache entries.
func TestEvalCache_NestedFanOutEvaluatesEachModuleOnce(t *testing.T) {
	for _, tc := range []struct{ depth, branch int }{{8, 2}, {12, 2}, {6, 3}} {
		name := fmt.Sprintf("depth%d_branch%d", tc.depth, tc.branch)
		t.Run(name, func(t *testing.T) {
			stack := writeNestedFanOut(t, tc.depth, tc.branch)

			e := New()
			resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
			if err != nil {
				t.Fatalf("EvaluateModule: %v", err)
			}

			// One distinct (dir, inputs) pair per level, plus the root stack.
			wantEntries := tc.depth + 1
			if got := len(e.cache); got > wantEntries {
				t.Errorf("cache holds %d entries, want at most %d (one per distinct module); "+
					"evaluation is scaling with the number of call paths, not with distinct modules",
					got, wantEntries)
			}
			if len(resources) == 0 {
				t.Error("expected the nested tree to resolve resources, got none")
			}
		})
	}
}

// Reusing an evaluation across call paths must not blur where its resources came
// from: each instance keeps the address and chain of the path that reached it,
// since findings are attributed with them.
func TestEvalCache_ReusedEvaluationKeepsPerPathAttribution(t *testing.T) {
	root := t.TempDir()

	child := filepath.Join(root, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(child, "main.tf"),
		[]byte("variable \"in\" { type = string }\nresource \"aws_s3_bucket\" \"b\" { bucket = var.in }\n"),
		0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	stack := filepath.Join(root, "stack")
	if err := os.MkdirAll(stack, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Same source, same inputs, two call sites: one evaluation, two attributions.
	if err := os.WriteFile(filepath.Join(stack, "main.tf"), []byte(`
module "alpha" {
  source = "../child"
  in     = "same"
}
module "beta" {
  source = "../child"
  in     = "same"
}
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	if len(resources) != 2 {
		t.Fatalf("resolved %d resources, want 2 (one per call site)", len(resources))
	}

	addrs := map[string]bool{}
	for _, r := range resources {
		addrs[r.ModuleAddress] = true
		if len(r.CallChain) != 1 {
			t.Errorf("resource at %s has a %d-hop call chain, want 1",
				r.ModuleAddress, len(r.CallChain))
			continue
		}
		// The chain must name the call site that reached this instance.
		wantName := strings.TrimPrefix(r.ModuleAddress, "module.")
		if got := r.CallChain[0].ModuleName; got != wantName {
			t.Errorf("resource at %s records call site %q, want %q",
				r.ModuleAddress, got, wantName)
		}
	}
	for _, want := range []string{"module.alpha", "module.beta"} {
		if !addrs[want] {
			t.Errorf("no resource attributed to %s; got %v", want, addrs)
		}
	}
}

// A module the evaluator declines to evaluate must be reported as not evaluated
// rather than as a module that resolved to nothing. The caller uses that to keep
// it in the scan, so conflating the two silently drops it.
func TestEvaluate_DepthCapReportsNotEvaluated(t *testing.T) {
	root := t.TempDir()
	// One level deeper than the evaluator will follow.
	depth := defaultMaxDepth + 3
	for i := 0; i < depth; i++ {
		dir := filepath.Join(root, fmt.Sprintf("lvl%02d", i))
		body := "variable \"in\" { type = string }\n"
		if i == depth-1 {
			body += "resource \"aws_s3_bucket\" \"leaf\" { bucket = var.in }\n"
		} else {
			body += fmt.Sprintf("module \"next\" {\n  source = \"../lvl%02d\"\n  in = var.in\n}\n", i+1)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	e := New()
	_, _, visited, err := e.EvaluateModule(context.Background(), filepath.Join(root, "lvl00"),
		map[string]cty.Value{"in": cty.StringVal("seed")})
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	// The levels past the cap were never resolved, so they must not be recorded as
	// evaluated — otherwise their bodies are suppressed with nothing standing in.
	for i := defaultMaxDepth + 1; i < depth; i++ {
		dir := filepath.Join(root, fmt.Sprintf("lvl%02d", i))
		if visited[dir] {
			t.Errorf("%s was not evaluated (past the depth cap) but is recorded as visited, "+
				"so it would be dropped from the scan", dir)
		}
	}
}

func TestEvalCache_SeparatesPathRootValues(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "shared", map[string]string{
		"main.tf": `
output "root" {
  value = path.root
}
`,
	})
	rootBody := `
module "shared" {
  source = "../shared"
}

resource "test_resource" "root" {
  value = module.shared.root
}
`
	rootA := writeModule(t, root, "root-a", map[string]string{"main.tf": rootBody})
	rootB := writeModule(t, root, "root-b", map[string]string{"main.tf": rootBody})

	e := New()
	if _, _, _, err := e.EvaluateModule(context.Background(), rootA, nil); err != nil {
		t.Fatalf("EvaluateModule(root-a): %v", err)
	}
	resources, _, _, err := e.EvaluateModule(context.Background(), rootB, nil)
	if err != nil {
		t.Fatalf("EvaluateModule(root-b): %v", err)
	}
	r := findResource(t, resources, "test_resource", "root")
	requireString(t, r.Attributes, "value", filepath.ToSlash(rootB))
}

func TestEvalCache_DoesNotReuseDepthTruncatedResult(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "leaf")
	target := filepath.Join(root, "target")
	for _, dir := range []string{leaf, target} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(leaf, "main.tf"), []byte(`
variable "in" { type = string }
resource "aws_s3_bucket" "leaf" { bucket = var.in }
`), 0o644); err != nil {
		t.Fatalf("write leaf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.tf"), []byte(`
variable "in" { type = string }
resource "aws_s3_bucket" "target" { bucket = var.in }
module "leaf" {
  source = "../leaf"
  in     = var.in
}
`), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	e := New()
	inputs := map[string]cty.Value{"in": cty.StringVal("same")}
	partial, _, err := e.evaluate(
		context.Background(), target, target, "", inputs, "module.deep", nil,
		e.maxDepth, map[string]bool{}, map[string]bool{},
	)
	if err != nil {
		t.Fatalf("deep evaluate: %v", err)
	}
	if len(partial) != 1 {
		t.Fatalf("deep evaluate returned %d resources, want the target resource only", len(partial))
	}
	key := evalCacheKey{dir: target, rootDir: target, inputs: canonicalInputsKey(inputs)}
	if _, ok := e.cache[key]; ok {
		t.Fatal("depth-truncated evaluation was cached as complete")
	}

	complete, _, err := e.evaluate(
		context.Background(), target, target, "", inputs, "module.shallow", nil,
		0, map[string]bool{}, map[string]bool{},
	)
	if err != nil {
		t.Fatalf("shallow evaluate: %v", err)
	}
	if len(complete) != 2 {
		t.Fatalf("shallow evaluate returned %d resources, want target and leaf", len(complete))
	}
}

func TestEvalCache_DoesNotReuseResultCachedFromDeeperDepth(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "leaf")
	mid := filepath.Join(root, "mid")
	wrapper := filepath.Join(root, "wrapper")
	for _, dir := range []string{leaf, mid, wrapper} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(leaf, "main.tf"), []byte(`
variable "in" { type = string }
resource "aws_s3_bucket" "leaf" { bucket = var.in }
`), 0o644); err != nil {
		t.Fatalf("write leaf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mid, "main.tf"), []byte(`
variable "in" { type = string }
resource "aws_s3_bucket" "mid" { bucket = var.in }
module "leaf" {
  source = "../leaf"
  in     = var.in
}
`), 0o644); err != nil {
		t.Fatalf("write mid: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wrapper, "main.tf"), []byte(`
variable "in" { type = string }
module "mid" {
  source = "../mid"
  in     = var.in
}
`), 0o644); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}

	e := New()
	inputs := map[string]cty.Value{"in": cty.StringVal("same")}
	deepDepth := e.maxDepth - 1
	deep, _, err := e.evaluate(
		context.Background(), mid, mid, "", inputs, "module.deep", nil,
		deepDepth, map[string]bool{}, map[string]bool{},
	)
	if err != nil {
		t.Fatalf("deep evaluate: %v", err)
	}
	if len(deep) != 2 {
		t.Fatalf("deep evaluate returned %d resources, want mid and leaf", len(deep))
	}
	key := evalCacheKey{dir: mid, rootDir: mid, inputs: canonicalInputsKey(inputs)}
	entry, ok := e.cache[key]
	if !ok {
		t.Fatal("expected mid module to cache its partial deep evaluation")
	}
	if entry.evalDepth != deepDepth {
		t.Fatalf("cached evalDepth = %d, want %d", entry.evalDepth, deepDepth)
	}

	shallow, _, err := e.evaluate(
		context.Background(), mid, mid, "", inputs, "module.shallow", nil,
		0, map[string]bool{}, map[string]bool{},
	)
	if err != nil {
		t.Fatalf("shallow evaluate: %v", err)
	}
	if len(shallow) != 2 {
		t.Fatalf("shallow evaluate returned %d resources, want mid and leaf", len(shallow))
	}
}
