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

	"github.com/stretchr/testify/require"
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
			evaluation, err := e.EvaluateModule(context.Background(), stack, nil)
			resources := evaluation.Resources
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
	evaluation, err := e.EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
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

func TestEvaluateModule_DeepLocalModules(t *testing.T) {
	for _, levels := range []int{24, 64} {
		t.Run(fmt.Sprint(levels), func(t *testing.T) {
			root := t.TempDir()
			for i := levels - 1; i >= 0; i-- {
				source := `resource "terraform_data" "leaf" {input="leaf-known"}
output "value" {value="leaf-known"}`
				if i < levels-1 {
					source = fmt.Sprintf("module \"n\" {source=\"../l%02d\"}\noutput \"value\" {value=module.n.value}", i+1)
				}
				writeModule(t, root, fmt.Sprintf("l%02d", i), map[string]string{"main.tf": source})
			}
			evaluator := New()
			evaluator.SetTrackModuleInstances(true)
			result, err := evaluator.EvaluateModule(t.Context(), filepath.Join(root, "l00"), nil)
			require.NoError(t, err)
			require.NoError(t, result.PolicyUnit(nil).Failure())
			require.Len(t, result.Resources, 1)
			require.Equal(t, cty.StringVal("leaf-known"), result.Resources[0].Attributes["input"])
			require.Equal(t, cty.StringVal("leaf-known"), result.Outputs["value"])
			require.Len(t, result.ModuleInstances, levels-1)
			require.Empty(t, result.InventoryObservations().Gaps)
			require.Empty(t, evaluator.NotEvaluatedDirs())
			for i := 1; i < levels; i++ {
				require.True(t, result.VisitedChildDirs[filepath.Join(root, fmt.Sprintf("l%02d", i))])
			}
		})
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
	if _, err := e.EvaluateModule(context.Background(), rootA, nil); err != nil {
		t.Fatalf("EvaluateModule(root-a): %v", err)
	}
	evaluation, err := e.EvaluateModule(context.Background(), rootB, nil)
	resources := evaluation.Resources
	if err != nil {
		t.Fatalf("EvaluateModule(root-b): %v", err)
	}
	r := findResource(t, resources, "test_resource", "root")
	requireString(t, r.Attributes, "value", filepath.ToSlash(rootB))
}

func TestEvalCache_DoesNotReuseCycleStoppedResult(t *testing.T) {
	root := t.TempDir()
	leaf := writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "terraform_data" "leaf" {input="leaf"}`})
	target := writeModule(t, root, "target", map[string]string{"main.tf": `resource "terraform_data" "target" {input="target"}
module "leaf" {source="../leaf"}`})
	evaluator := New()
	stopped, _, err := evaluator.evaluate(t.Context(), target, target, "", nil, "module.first", nil, map[string]bool{leaf: true}, map[string]bool{})
	require.NoError(t, err)
	require.Len(t, stopped, 1)
	key := evalCacheKey{dir: target, rootDir: target, inputs: canonicalInputsKey(nil)}
	require.NotContains(t, evaluator.cache, key, "a skipped subtree is never cached as complete")
	complete, _, err := evaluator.evaluate(t.Context(), target, target, "", nil, "module.second", nil, map[string]bool{}, map[string]bool{})
	require.NoError(t, err)
	require.Len(t, complete, 2)
	require.Contains(t, evaluator.cache, key)
}

func TestEvalCache_ReusesCompleteResultAcrossCallChains(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "terraform_data" "leaf" {input="leaf"}`})
	mid := writeModule(t, root, "mid", map[string]string{"main.tf": `resource "terraform_data" "mid" {input="mid"}
module "leaf" {source="../leaf"}`})
	evaluator := New()
	deep, _, err := evaluator.evaluate(t.Context(), mid, root, "", nil, "module.outer.module.mid", []CallSite{{ModuleName: "outer"}, {ModuleName: "mid"}}, map[string]bool{}, map[string]bool{})
	require.NoError(t, err)
	require.Len(t, deep, 2)
	key := evalCacheKey{dir: mid, rootDir: root, inputs: canonicalInputsKey(nil)}
	entry := evaluator.cache[key]
	require.NotNil(t, entry)
	shallow, _, err := evaluator.evaluate(t.Context(), mid, root, "", nil, "module.mid", []CallSite{{ModuleName: "mid"}}, map[string]bool{}, map[string]bool{})
	require.NoError(t, err)
	require.Len(t, shallow, 2)
	require.Same(t, entry, evaluator.cache[key], "a complete subtree is reused regardless of calling depth")
	require.Equal(t, "module.mid", findResource(t, shallow, "terraform_data", "mid").ModuleAddress)
	require.Equal(t, "module.mid.module.leaf", findResource(t, shallow, "terraform_data", "leaf").ModuleAddress)
	require.Len(t, findResource(t, shallow, "terraform_data", "mid").CallChain, 1)
	require.Len(t, findResource(t, shallow, "terraform_data", "leaf").CallChain, 2)
}

func TestEvalCache_RespectsActiveModulePath(t *testing.T) {
	root := t.TempDir()
	a := writeModule(t, root, "a", map[string]string{"main.tf": `variable "loop" {default=false}
module "m" {
 source="../m"
 count=var.loop ? 1 : 0
}
output "v" {value="a-base"}`})
	m := writeModule(t, root, "m", map[string]string{"main.tf": `module "a" {
 source="../a"
 loop=false
}
resource "terraform_data" "m" {input=module.a.v}
output "v" {value=module.a.v}`})
	for _, callDepth := range []int{1, 2} {
		for _, contextName := range []string{"empty", "unrelated", "active descendant", "previously visited active descendant"} {
			t.Run(fmt.Sprintf("depth%d/%s", callDepth, contextName), func(t *testing.T) {
				cached := New()
				primingVisited := map[string]bool{}
				if contextName == "previously visited active descendant" {
					primingVisited[a] = true
				}
				primed, _, err := cached.evaluate(t.Context(), m, root, "", nil, "module.m", []CallSite{{ModuleName: "m"}}, map[string]bool{}, primingVisited)
				require.NoError(t, err)
				key := evalCacheKey{dir: m, rootDir: root, inputs: canonicalInputsKey(nil)}
				entry := cached.cache[key]
				require.NotNil(t, entry)
				require.Contains(t, entry.visitedDirs, a, "cache footprints include descendants visited before this module")
				visiting := map[string]bool{}
				switch contextName {
				case "unrelated":
					visiting[filepath.Join(root, "unrelated")] = true
				case "active descendant", "previously visited active descendant":
					visiting[a] = true
				}
				fresh := New()
				freshVisited, cachedVisited := map[string]bool{}, map[string]bool{}
				chain := []CallSite{{ModuleName: "m"}}
				addr := "module.m"
				if callDepth == 2 {
					chain = append([]CallSite{{ModuleName: "current"}}, chain...)
					addr = "module.current.module.m"
				}
				freshResources, freshOutputs, err := fresh.evaluate(t.Context(), m, root, "", nil, addr, chain, visiting, freshVisited)
				require.NoError(t, err)
				cachedResources, cachedOutputs, err := cached.evaluate(t.Context(), m, root, "", nil, addr, chain, visiting, cachedVisited)
				require.NoError(t, err)
				require.True(t, freshOutputs["v"].RawEquals(cachedOutputs["v"]), "cached output %#v differs from fresh %#v", cachedOutputs["v"], freshOutputs["v"])
				require.Len(t, cachedResources, len(freshResources))
				require.True(t, freshResources[0].Attributes["input"].RawEquals(cachedResources[0].Attributes["input"]))
				require.Equal(t, freshVisited, cachedVisited)
				require.Equal(t, fresh.inventoryGaps, cached.inventoryGaps)
				if contextName == "empty" || contextName == "unrelated" {
					require.Same(t, entry, cached.cache[key])
					require.Same(t, primed[0].Scope, cachedResources[0].Scope, "safe contexts must reuse the cached native value scope")
				} else {
					require.NotSame(t, primed[0].Scope, cachedResources[0].Scope, "active ancestors require fresh traversal")
				}
			})
		}
	}
}

func TestEvalCache_TracksPreviouslyVisitedDescendants(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "a", map[string]string{"main.tf": `resource "terraform_data" "a" {input="known"}
output "v" {value="known"}`})
	writeModule(t, root, "m", map[string]string{"main.tf": `module "a" {source="../a"}
output "v" {value=module.a.v}`})
	writeModule(t, root, "root", map[string]string{"main.tf": `variable "seed" {type=bool}
module "a_seed" {
source="../a"
count=var.seed ? 1 : 0
}
module "z_consumer" {source="../m"}
output "v" {value=module.z_consumer.v}`})
	evaluator := New()
	for _, seed := range []bool{true, false, true} {
		result, err := evaluator.EvaluateModule(t.Context(), filepath.Join(root, "root"), map[string]cty.Value{"seed": cty.BoolVal(seed)})
		require.NoError(t, err)
		require.Equal(t, cty.StringVal("known"), result.Outputs["v"])
		require.True(t, result.VisitedChildDirs[filepath.Join(root, "a")], "the complete footprint survives sibling order and later cache hits")
		require.True(t, result.VisitedChildDirs[filepath.Join(root, "m")])
	}
}
