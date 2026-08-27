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

// The instantiation budget is a backstop for shapes that are genuinely enormous.
// It must stop the recursion rather than let a single root grow without bound.
func TestInstantiationBudget_StopsRecursion(t *testing.T) {
	stack := writeNestedFanOut(t, 10, 3)

	unbounded := New()
	unbounded.SetMaxInstantiated(0)
	all, _, _, err := unbounded.EvaluateModule(context.Background(), stack, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if unbounded.BudgetExceeded() {
		t.Error("budget reported exceeded when disabled")
	}

	bounded := New()
	bounded.SetMaxInstantiated(4)
	limited, _, _, err := bounded.EvaluateModule(context.Background(), stack, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if !bounded.BudgetExceeded() {
		t.Error("budget was not reported as exceeded")
	}
	if len(limited) >= len(all) {
		t.Errorf("bounded run resolved %d resources, want fewer than the %d of an unbounded run",
			len(limited), len(all))
	}
}

func TestInstantiationBudget_CountsFinalInstancesOnce(t *testing.T) {
	stack := writeNestedFanOut(t, 12, 3)

	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}

	const want = 177147
	if got := len(resources); got != want {
		t.Fatalf("resolved %d resources after counting %d, want %d below the %d-resource budget",
			got, e.instantiated, want, defaultMaxInstantiated)
	}
	if e.BudgetExceeded() {
		t.Fatalf("budget was exhausted after resolving %d resources below its %d limit",
			len(resources), defaultMaxInstantiated)
	}
	if e.instantiated != len(resources) {
		t.Fatalf("budget counted %d instances for %d returned resources",
			e.instantiated, len(resources))
	}
}

func TestResetInstantiationBudget_FreshQuotaPerRoot(t *testing.T) {
	e := New()
	e.SetMaxInstantiated(100)
	ctx := context.Background()

	e.chargeInstantiationBudget(ctx, 80)
	if e.BudgetExceeded() {
		t.Fatal("budget should not be exceeded at 80 of 100")
	}

	e.ResetInstantiationBudget()
	e.chargeInstantiationBudget(ctx, 80)
	if e.BudgetExceeded() {
		t.Fatal("after reset, a second root should get a fresh quota of 100")
	}

	e.chargeInstantiationBudget(ctx, 25)
	if !e.BudgetExceeded() {
		t.Fatal("budget should exceed once a single root passes 100 resources")
	}
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
		context.Background(), target, "", inputs, "module.deep", nil,
		e.maxDepth, map[string]bool{}, map[string]bool{},
	)
	if err != nil {
		t.Fatalf("deep evaluate: %v", err)
	}
	if len(partial) != 1 {
		t.Fatalf("deep evaluate returned %d resources, want the target resource only", len(partial))
	}
	key := evalCacheKey{dir: target, inputs: canonicalInputsKey(inputs)}
	if _, ok := e.cache[key]; ok {
		t.Fatal("depth-truncated evaluation was cached as complete")
	}

	complete, _, err := e.evaluate(
		context.Background(), target, "", inputs, "module.shallow", nil,
		0, map[string]bool{}, map[string]bool{},
	)
	if err != nil {
		t.Fatalf("shallow evaluate: %v", err)
	}
	if len(complete) != 2 {
		t.Fatalf("shallow evaluate returned %d resources, want target and leaf", len(complete))
	}
}

// Whether a module was resolved is decided per directory by the caller, but the
// stops are per call site: the same directory can be resolved on one path and
// skipped on another. Every skipped directory has to be reported, or the caller
// suppresses a body whose skipped instances nothing replaces.
func TestNotEvaluatedDirs_ReportsSkippedDirectories(t *testing.T) {
	stack := writeNestedFanOut(t, 10, 3)

	unbounded := New()
	unbounded.SetMaxInstantiated(0)
	if _, _, _, err := unbounded.EvaluateModule(context.Background(), stack, nil); err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if dirs := unbounded.NotEvaluatedDirs(); len(dirs) != 0 {
		t.Errorf("nothing was skipped, yet %d directories are reported as not evaluated: %v",
			len(dirs), dirs)
	}

	bounded := New()
	bounded.SetMaxInstantiated(4)
	if _, _, _, err := bounded.EvaluateModule(context.Background(), stack, nil); err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	skipped := bounded.NotEvaluatedDirs()
	if len(skipped) == 0 {
		t.Fatal("the budget stopped the recursion but no directory is reported as not evaluated")
	}
	for _, dir := range skipped {
		if !strings.HasPrefix(dir, filepath.Dir(stack)) {
			t.Errorf("reported directory %s is outside the fixture", dir)
		}
	}

	// The budget resets per root, but a skipped directory stays skipped: the
	// caller's suppression decision spans every root.
	bounded.ResetInstantiationBudget()
	if got := len(bounded.NotEvaluatedDirs()); got != len(skipped) {
		t.Errorf("resetting the budget changed the skipped set from %d to %d directories",
			len(skipped), got)
	}
}
