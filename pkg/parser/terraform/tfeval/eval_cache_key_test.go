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

	"github.com/hashicorp/hcl/v2"
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
			resources, outputs, visited, err := evaluator.EvaluateModule(t.Context(), filepath.Join(root, "l00"), nil)
			require.NoError(t, err)
			require.Len(t, resources, 1)
			require.Equal(t, cty.StringVal("leaf-known"), resources[0].Attributes["input"])
			require.Equal(t, cty.StringVal("leaf-known"), outputs["value"])
			require.Len(t, evaluator.TakeModuleInstances(), levels-1)
			require.Empty(t, evaluator.NotEvaluatedDirs())
			for i := 1; i < levels; i++ {
				require.True(t, visited[filepath.Join(root, fmt.Sprintf("l%02d", i))])
			}
		})
	}
}

// A sibling-output pre-pass must reuse the work it just performed, even when
// an active-path cycle prevents global memoization. Refined inputs must instead
// evaluate the subtree again, and publish only the final instance records.
func TestEvaluateModule_SiblingPrepassReusesPartialSubtrees(t *testing.T) {
	for _, levels := range []int{4, 6, 8} {
		for _, cycle := range []bool{false, true} {
			for _, refined := range []bool{false, true} {
				name := fmt.Sprintf("levels%d/cycle%t/refined%t", levels, cycle, refined)
				t.Run(name, func(t *testing.T) {
					root := t.TempDir()
					writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "terraform_data" "leaf" {input="leaf"}`})
					writeModule(t, root, "producer", map[string]string{"main.tf": `variable "in" {}
output "value" {value=var.in}`})
					for i := levels - 1; i >= 0; i-- {
						body := `variable "in" {}` + "\n"
						if i == levels-1 {
							source := "../leaf"
							if cycle {
								source = "../l00"
							}
							body += fmt.Sprintf("resource \"terraform_data\" \"terminal\" {input=var.in}\ndata \"x\" \"y\" {input=var.in}\nmodule \"back\" {source=%q}\n", source)
						} else {
							body += fmt.Sprintf("resource \"terraform_data\" \"r\" {input=var.in}\nmodule \"next\" {\nsource=\"../l%02d\"\nin=terraform_data.r.input\n}\nmodule \"leaf\" {source=\"../leaf\"}\n", i+1)
						}
						writeModule(t, root, fmt.Sprintf("l%02d", i), map[string]string{"main.tf": body})
					}
					input := `"ready"`
					if refined {
						input = "module.producer.value"
					}
					stack := writeModule(t, root, "stack", map[string]string{"main.tf": fmt.Sprintf(`resource "terraform_data" "seed" {input="ready"}
module "tree" {
 source="../l00"
 in=%s
}
module "producer" {
 source="../producer"
 in=terraform_data.seed.input
}
`, input)})
					evaluator := New()
					evaluator.SetTrackModuleInstances(true)
					resources, _, visited, err := evaluator.EvaluateModule(t.Context(), stack, nil)
					require.NoError(t, err)
					wantEvaluations := 1
					if refined {
						wantEvaluations = 2
					}
					require.Equal(t, wantEvaluations, evaluator.DataBlockEvaluations(), "work follows distinct inputs, not pre-pass paths")
					wantResources, wantInstances := 2*levels+2, 2*levels+1
					if cycle {
						wantResources--
						wantInstances--
						require.Equal(t, []string{filepath.Join(root, "l00")}, evaluator.NotEvaluatedDirs())
						require.NotContains(t, evaluator.cache, evalCacheKey{dir: stack, rootDir: stack, inputs: canonicalInputsKey(nil)}, "transient partial results must not enter the global cache")
					} else {
						require.Empty(t, evaluator.NotEvaluatedDirs())
					}
					require.Len(t, resources, wantResources)
					require.Len(t, visited, levels+2)
					instances := evaluator.TakeModuleInstances()
					require.Len(t, instances, wantInstances)
					addresses := make(map[string]bool)
					for _, instance := range instances {
						require.False(t, addresses[instance.ModuleAddress], "speculative instances must not leak into the result")
						addresses[instance.ModuleAddress] = true
						require.Len(t, instance.CallChain, strings.Count(instance.ModuleAddress, "module."))
					}
					for _, resource := range resources {
						if resource.Name == "leaf" {
							require.Equal(t, cty.StringVal("leaf"), resource.Attributes["input"])
						} else {
							require.Equal(t, cty.StringVal("ready"), resource.Attributes["input"], "stale speculative attributes must not survive refined inputs")
						}
						if resource.ModuleAddress != "" {
							require.True(t, addresses[resource.ModuleAddress])
						}
						require.Len(t, resource.CallChain, strings.Count(resource.ModuleAddress, "module."))
					}
				})
			}
		}
	}
	for _, changed := range []string{"unknown input refinements", "source", "version"} {
		t.Run(changed, func(t *testing.T) {
			root := t.TempDir()
			writeModule(t, root, "partial", map[string]string{"main.tf": `variable "value" {type=string}
resource "terraform_data" "value" {input=var.value == null}
data "x" "y" {}
module "recursive" {source="./."}`})
			writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "terraform_data" "leaf" {input="leaf"}`})
			stack := writeModule(t, root, "stack", map[string]string{"main.tf": `module "target" {
 source=var.source
 version=var.version
 value=var.value
}
module "leaf" {source="../leaf"}`})
			evaluator := New()
			parsed := evaluator.parseDir(t.Context(), stack, "")
			require.NoError(t, parsed.err)
			evalCtx := &hcl.EvalContext{
				Variables: map[string]cty.Value{"var": cty.ObjectVal(map[string]cty.Value{
					"value": cty.UnknownVal(cty.String), "source": cty.StringVal("../partial"), "version": cty.StringVal("before"),
				})},
				Functions: evaluator.funcs,
			}
			scope := &ModuleScope{
				Locals: parsed.localExprs, localGraph: parsed.locals, static: parsed.static,
				evalCtx: evalCtx, sources: parsed.sources,
			}
			data := newModuleData(evaluator, parsed.sources, parsed.locals, parsed.static, "", nil)
			identity, err := evaluator.moduleDirectoryIdentity(t.Context(), stack)
			require.NoError(t, err)
			visiting := map[string]bool{identity: true}
			evaluator.evaluation = &evaluationRun{}
			evaluator.preliminaryModuleOutputs(t.Context(), parsed.modules, parsed.static.siblings,
				evalCtx, scope, stack, stack, "", "", nil, visiting)
			require.Len(t, evaluator.evaluation.partial, 1)
			require.Empty(t, evaluator.NotEvaluatedDirs(), "speculative stops must not escape the pre-pass")
			finalSource, finalVersion := "../partial", "before"
			finalValue := cty.UnknownVal(cty.String)
			switch changed {
			case "unknown input refinements":
				finalValue = finalValue.RefineNotNull()
			case "source":
				finalSource = "../partial/."
			case "version":
				finalVersion = "after"
			}
			evalCtx.Variables["var"] = cty.ObjectVal(map[string]cty.Value{
				"value": finalValue, "source": cty.StringVal(finalSource), "version": cty.StringVal(finalVersion),
			})
			resources, _ := evaluator.evaluateLocalModuleBlocks(t.Context(), parsed.modules, parsed.static.siblings,
				evalCtx, scope, data, stack, stack, "", "", nil, visiting, map[string]bool{})
			wantEvaluations := 1
			if changed == "unknown input refinements" {
				wantEvaluations = 2
			}
			require.Equal(t, wantEvaluations, evaluator.DataBlockEvaluations(), "changed native inputs require fresh evaluation; provenance alone is rebound")
			value := findResource(t, resources, "terraform_data", "value")
			require.True(t, value.Attributes["input"].RawEquals(finalValue.Equals(cty.NullVal(cty.String))), "the final attributes must reflect the refined inputs")
			require.Len(t, value.CallChain, 1)
			require.Equal(t, finalSource, value.CallChain[0].Source)
			require.Equal(t, finalVersion, value.CallChain[0].Version)
		})
	}
}

// The same native subtrees can be reached repeatedly while sibling inputs
// refine, or through empty fan-out. Partial cycle results must stay reusable
// under compatible ancestries without expanding their stop effects into a tree.
func TestEvalCache_ContextualPartialResults(t *testing.T) {
	for _, levels := range []int{4, 6, 8} {
		for _, cycle := range []bool{false, true} {
			for _, refining := range []bool{false, true} {
				t.Run(fmt.Sprintf("levels%d/cycle%t/refining%t", levels, cycle, refining), func(t *testing.T) {
					root := t.TempDir()
					writeModule(t, root, "producer", map[string]string{"main.tf": `variable "in" {}
output "value" {value=var.in}`})
					for i := levels - 1; i >= 0; i-- {
						body := ""
						if refining {
							body = "variable \"in\" {}\nresource \"terraform_data\" \"r\" {input=\"ready\"}\n"
						}
						if i == levels-1 {
							if refining {
								body += "data \"x\" \"y\" {input=var.in}\n"
							}
							if cycle {
								body += "module \"back\" {source=\"../l00\"}\n"
							}
						} else if refining {
							body += fmt.Sprintf("module \"next\" {\nsource=\"../l%02d\"\nin=module.producer.value\n}\nmodule \"producer\" {\nsource=\"../producer\"\nin=terraform_data.r.input\n}\n", i+1)
						} else {
							body = fmt.Sprintf("module \"left\" {source=\"../l%02d\"}\nmodule \"right\" {source=\"../l%02d\"}\n", i+1, i+1)
						}
						writeModule(t, root, fmt.Sprintf("l%02d", i), map[string]string{"main.tf": body})
					}
					argument := ""
					if refining {
						argument = "in=\"ready\"\n"
					}
					stack := writeModule(t, root, "stack", map[string]string{"main.tf": "module \"tree\" {\nsource=\"../l00\"\n" + argument + "}"})
					evaluator := New()
					evaluator.SetTrackModuleInstances(refining)
					base, cancel := context.WithCancel(t.Context())
					defer cancel()
					// This test guard counts control-flow checks, not wall time.
					// No corresponding work limit exists in the evaluator.
					ctx := &cancellationCheckContext{Context: base, cancel: cancel, maxChecks: int64(200 * levels)}
					resources, _, visited, err := evaluator.EvaluateModule(ctx, stack, nil)
					require.NoError(t, err, "repeated partial paths must not expand exponentially")
					require.Nil(t, evaluator.evaluation, "partial results belong only to the current root")
					wantVisited := levels
					if refining {
						wantVisited++
						require.Equal(t, 2, evaluator.DataBlockEvaluations(), "each final input state is evaluated once, regardless of call paths")
						require.Len(t, resources, levels+1)
						require.Len(t, evaluator.TakeModuleInstances(), 2*levels-1)
						for _, resource := range resources {
							require.Equal(t, cty.StringVal("ready"), resource.Attributes["input"])
							for _, call := range resource.CallChain {
								if call.Caller.Var.Type().HasAttribute("in") {
									require.Equal(t, cty.StringVal("ready"), call.Caller.Var.GetAttr("in"), "cached resources need the final caller scopes")
								}
							}
						}
					} else {
						require.Empty(t, resources)
						require.Empty(t, evaluator.TakeModuleInstances())
					}
					require.Len(t, visited, wantVisited)
					for i := range levels {
						require.True(t, visited[filepath.Join(root, fmt.Sprintf("l%02d", i))])
					}
					if cycle {
						require.Equal(t, []string{filepath.Join(root, "l00")}, evaluator.NotEvaluatedDirs())
					} else {
						require.Empty(t, evaluator.NotEvaluatedDirs())
					}
				})
			}
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

func TestEvalCache_DoesNotReuseCycleStoppedResult(t *testing.T) {
	root := t.TempDir()
	leaf := writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "terraform_data" "leaf" {input="leaf"}`})
	target := writeModule(t, root, "target", map[string]string{"main.tf": `resource "terraform_data" "target" {input="target"}
module "leaf" {source="../leaf"}`})
	evaluator := New()
	leafIdentity, err := evaluator.moduleDirectoryIdentity(t.Context(), leaf)
	require.NoError(t, err)
	stopped, _, err := evaluator.evaluate(t.Context(), target, target, "", nil, "module.first", nil, map[string]bool{leafIdentity: true}, map[string]bool{})
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
	alias := filepath.Join(root, "a-link")
	aliasError := os.Symlink(a, alias)
	for _, source := range []struct{ name, dir string }{{"direct", a}, {"alias", alias}} {
		t.Run(source.name, func(t *testing.T) {
			if source.name == "alias" && aliasError != nil {
				t.Skipf("directory symlinks unavailable: %v", aliasError)
			}
			m := writeModule(t, root, "m", map[string]string{"main.tf": fmt.Sprintf(`module "a" {
 source=%q
 loop=false
}
resource "terraform_data" "m" {input=module.a.v}
output "v" {value=module.a.v}`, "../"+filepath.Base(source.dir))})
			for _, callDepth := range []int{1, 2} {
				for _, contextName := range []string{"empty", "unrelated", "active descendant", "previously visited active descendant"} {
					t.Run(fmt.Sprintf("depth%d/%s", callDepth, contextName), func(t *testing.T) {
						cached := New()
						activeIdentity, err := cached.moduleDirectoryIdentity(t.Context(), a)
						require.NoError(t, err)
						primingVisited := map[string]bool{}
						if contextName == "previously visited active descendant" {
							primingVisited[source.dir] = true
						}
						primed, _, err := cached.evaluate(t.Context(), m, root, "", nil, "module.m", []CallSite{{ModuleName: "m"}}, map[string]bool{}, primingVisited)
						require.NoError(t, err)
						key := evalCacheKey{dir: m, rootDir: root, inputs: canonicalInputsKey(nil)}
						entry := cached.cache[key]
						require.NotNil(t, entry)
						require.Contains(t, entry.visitedDirs, source.dir, "coverage retains the evaluated lexical path")
						visiting := map[string]bool{}
						switch contextName {
						case "unrelated":
							visiting[filepath.Join(root, "unrelated")] = true
						case "active descendant", "previously visited active descendant":
							visiting[activeIdentity] = true
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
						if contextName == "empty" || contextName == "unrelated" {
							require.Same(t, entry, cached.cache[key])
							require.Same(t, primed[0].Scope, cachedResources[0].Scope, "safe contexts reuse the cached native value scope")
						} else {
							require.NotSame(t, primed[0].Scope, cachedResources[0].Scope, "physical active ancestors require fresh traversal")
						}
					})
				}
			}
		})
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
		_, outputs, visited, err := evaluator.EvaluateModule(t.Context(), filepath.Join(root, "root"), map[string]cty.Value{"seed": cty.BoolVal(seed)})
		require.NoError(t, err)
		require.Equal(t, cty.StringVal("known"), outputs["v"])
		require.True(t, visited[filepath.Join(root, "a")], "the complete footprint survives sibling order and later cache hits")
		require.True(t, visited[filepath.Join(root, "m")])
	}
}

// Distinct directory paths can converge before a cycle. Work must follow the
// evaluated directory/input states, rather than all paths through the DAG.
func TestEvalCache_PartialDAG(t *testing.T) {
	for _, shape := range []string{"diamond", "empty-grid"} {
		t.Run(shape, func(t *testing.T) {
			root := t.TempDir()
			levels := 12
			if shape == "empty-grid" {
				levels = 40
			}
			for i := levels - 1; i >= 0; i-- {
				body := ""
				if i == levels-1 {
					if shape == "diamond" {
						body = "data \"x\" \"y\" {}\nmodule \"back\" {source=\"../h00\"}\n"
					} else {
						body = "module \"self\" {source=\"./\"}\n"
					}
				} else if shape == "diamond" {
					body = fmt.Sprintf("module \"direct\" {source=\"../h%02d\"}\nmodule \"via\" {source=\"../a%02d\"}\n", i+1, i)
					writeModule(t, root, fmt.Sprintf("a%02d", i), map[string]string{"main.tf": fmt.Sprintf("module \"next\" {source=\"../h%02d\"}", i+1)})
				} else {
					body = fmt.Sprintf("module \"left\" {source=\"../h%02d\"}\nmodule \"right\" {source=\"../a%02d\"}\n", i+1, i+1)
				}
				writeModule(t, root, fmt.Sprintf("h%02d", i), map[string]string{"main.tf": body})
				if shape == "empty-grid" {
					writeModule(t, root, fmt.Sprintf("a%02d", i), map[string]string{"main.tf": body})
				}
			}
			evaluator := New()
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &cancellationCheckContext{Context: base, cancel: cancel, maxChecks: int64(2000 * levels)}
			resources, _, visited, err := evaluator.EvaluateModule(ctx, filepath.Join(root, "h00"), nil)
			require.NoError(t, err)
			require.LessOrEqual(t, evaluator.DataBlockEvaluations(), 4*levels)
			if shape == "diamond" {
				require.Len(t, resources, 1<<(levels-1), "each data occurrence still needs its own provenance")
				require.Equal(t, []string{filepath.Join(root, "h00")}, evaluator.NotEvaluatedDirs())
				require.Len(t, visited, 2*levels-2)
			} else {
				require.Empty(t, resources)
				require.Equal(t, 2, len(evaluator.NotEvaluatedDirs()))
				require.Len(t, visited, 2*levels-2)
			}
			require.Empty(t, evaluator.cache, "partial DAGs never enter the complete cache")
			require.Nil(t, evaluator.evaluation)
		})
	}
}

func TestEvalCache_PartialAncestryCompatibility(t *testing.T) {
	root := t.TempDir()
	leaf := writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "terraform_data" "leaf" {input="leaf"}`})
	target := writeModule(t, root, "target", map[string]string{"main.tf": `resource "terraform_data" "target" {input="target"}
module "leaf" {source="../leaf"}
module "self" {source="./"}`})
	for _, changed := range []string{"stop no longer active", "entered directory now active", "irrelevant ancestor"} {
		t.Run(changed, func(t *testing.T) {
			e := New()
			e.evaluation = &evaluationRun{}
			leafID, err := e.moduleDirectoryIdentity(t.Context(), leaf)
			require.NoError(t, err)
			firstVisiting := map[string]bool{}
			if changed != "entered directory now active" {
				firstVisiting[leafID] = true
			}
			first, _, err := e.evaluate(t.Context(), target, root, "", nil, "module.first", nil, firstVisiting, map[string]bool{})
			require.NoError(t, err)
			key := evalCacheKey{dir: target, rootDir: root, inputs: canonicalInputsKey(nil)}
			nextVisiting := map[string]bool{}
			if changed != "stop no longer active" {
				nextVisiting[leafID] = true
			}
			nextVisiting["unrelated"] = true
			entry := e.evaluation.partialResult(&key, nil, nextVisiting)
			if changed == "irrelevant ancestor" {
				require.NotNil(t, entry)
			} else {
				require.Nil(t, entry)
			}
			next, _, err := e.evaluate(t.Context(), target, root, "", nil, "module.second", nil, nextVisiting, map[string]bool{})
			require.NoError(t, err)
			wantFirst, wantNext := 1, 1
			if changed == "entered directory now active" {
				wantFirst = 2
			}
			if changed == "stop no longer active" {
				wantNext = 2
			}
			require.Len(t, first, wantFirst)
			require.Len(t, next, wantNext)
			for _, r := range next {
				require.True(t, strings.HasPrefix(r.ModuleAddress, "module.second"))
			}
		})
	}
}

// A pre-pass may be abandoned, but changing one of its cycle decisions can
// change the outputs it supplied. Such entries must still respect that ancestry.
func TestEvalCache_SpeculativeCycleDependencies(t *testing.T) {
	root := t.TempDir()
	leaf := writeModule(t, root, "leaf", map[string]string{"main.tf": `resource "terraform_data" "r" {input="ready"}`})
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked=%t", blocked), func(t *testing.T) {
			e := New()
			e.evaluation = &evaluationRun{}
			outer := e.evaluation.beginEffects()
			speculative := e.evaluation.beginEffects()
			identity, err := e.moduleDirectoryIdentity(t.Context(), leaf)
			require.NoError(t, err)
			visiting := map[string]bool{identity: blocked}
			_, _, err = e.evaluate(t.Context(), leaf, root, "", nil, "module.speculative", nil, visiting, map[string]bool{})
			if blocked {
				require.ErrorIs(t, err, ErrModuleNotEvaluated)
			} else {
				require.NoError(t, err)
			}
			e.evaluation.finishEffects(speculative, e.notEvaluatedDirs, false)
			require.Empty(t, e.NotEvaluatedDirs(), "speculative reporting effects must roll back")
			key := evalCacheKey{dir: root, rootDir: root, inputs: canonicalInputsKey(nil)}
			e.cacheEvaluation(&key, true, nil, outer, nil, nil, map[string]cty.Value{}, map[string]bool{}, "", nil)
			// This parent has no published children or stops, only pre-pass dependencies.
			visiting[identity] = !blocked
			if blocked {
				require.Nil(t, e.evaluation.partialResult(&key, nil, visiting), "external speculative stop no longer applies")
				visiting[identity] = true
				require.NotNil(t, e.evaluation.partialResult(&key, nil, visiting))
			} else {
				_, _, hit := e.reuseCachedEvaluation(t.Context(), key, true, "", nil, visiting, map[string]bool{})
				require.False(t, hit, "a speculative child would now stop")
				visiting[identity] = false
				_, _, hit = e.reuseCachedEvaluation(t.Context(), key, true, "", nil, visiting, map[string]bool{})
				require.True(t, hit)
			}
		})
	}
}
