/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"errors"
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

// writeChain lays down depth module levels, each calling the next once; the
// last declares the resource.
func writeChain(t *testing.T, depth int) string {
	t.Helper()
	root := t.TempDir()
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
	return root
}

// Module nesting has no depth limit: Terraform has none, and a chain without
// a cycle ends after as many levels as it has directories. Every level of a
// chain far deeper than the 15 levels evaluation once stopped at resolves.
func TestEvaluate_DeepChainEvaluatesEveryLevel(t *testing.T) {
	const depth = 40
	root := writeChain(t, depth)
	e := New()
	resources, _, visited, err := e.EvaluateModule(context.Background(), filepath.Join(root, "lvl00"),
		map[string]cty.Value{"in": cty.StringVal("seed")})
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("resolved %d resources, want the leaf", len(resources))
	}
	want := strings.Repeat("module.next.", depth-1)
	if got := resources[0].ModuleAddress + "."; got != want {
		t.Fatalf("leaf address %q, want %q", got, want)
	}
	if len(resources[0].CallChain) != depth-1 {
		t.Fatalf("leaf call chain has %d hops, want %d", len(resources[0].CallChain), depth-1)
	}
	for i := 1; i < depth; i++ {
		if dir := filepath.Join(root, fmt.Sprintf("lvl%02d", i)); !visited[dir] {
			t.Errorf("%s was not recorded as evaluated", dir)
		}
	}
	if len(e.NotEvaluatedDirs()) != 0 {
		t.Fatalf("deep chain skipped %v", e.NotEvaluatedDirs())
	}
}

// A module calling itself is the one recursion Terraform rejects. Its
// directory is left to be scanned as written.
func TestEvaluate_ModuleCycleIsLeftAsWritten(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "a", map[string]string{"main.tf": `
resource "aws_s3_bucket" "a" {}
module "b" { source = "../b" }
`})
	writeModule(t, root, "b", map[string]string{"main.tf": `
module "a" { source = "../a" }
`})
	stack := writeModule(t, root, "stack", map[string]string{"main.tf": `module "a" { source = "../a" }`})
	e := New()
	_, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	if !slicesContain(e.NotEvaluatedDirs(), filepath.Join(root, "a")) {
		t.Fatalf("cycle directory not reported as not evaluated: %v", e.NotEvaluatedDirs())
	}
}

func slicesContain(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// A fan-out of branch^depth instances resolves every one of them.
func TestEvaluate_NestedFanOutResolvesEveryInstance(t *testing.T) {
	for _, c := range []struct{ depth, want int }{{10, 19683}, {12, 177147}} {
		stack := writeNestedFanOut(t, c.depth, 3)
		resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
		if err != nil {
			t.Fatalf("EvaluateModule: %v", err)
		}
		if len(resources) != c.want {
			t.Fatalf("depth %d resolved %d resources, want %d", c.depth, len(resources), c.want)
		}
	}
}

// Canceling the scan stops evaluation; nothing evaluated before the
// cancellation is passed off as the whole module.
func TestEvaluate_CancellationStopsExplicitly(t *testing.T) {
	stack := writeNestedFanOut(t, 10, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := New()
	resources, _, _, err := e.EvaluateModule(ctx, stack, nil)
	if !errors.Is(err, ErrEvaluationStopped) || len(resources) != 0 {
		t.Fatalf("cancelled evaluation: %d resources, %v", len(resources), err)
	}
	// Work stops within one check interval rather than after the whole tree.
	if n := e.Report().ModuleEvaluations; n > cancelCheckEvery {
		t.Fatalf("%d module evaluations ran after cancellation", n)
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
