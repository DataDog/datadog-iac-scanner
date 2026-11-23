/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// siblingModuleFiles varies input identity while keeping module depth fixed.
// Resource-mediated sibling calls exercise the evaluator's speculative path.
func siblingModuleFiles(root string, width int, distinct bool) map[string][]byte {
	input := "0"
	if distinct {
		input = "count.index"
	}
	return map[string][]byte{
		filepath.Join(root, "entry", "main.tf"): []byte(fmt.Sprintf(`module "wrapper" {
 source="../wrapper"
 count=%d
 value=%s
}
output "values" {value=[for w in module.wrapper:w.value]}`, width, input)),
		filepath.Join(root, "wrapper", "main.tf"): []byte(`variable "value" {}
resource "terraform_data" "seed" {input=var.value}
module "left" {
 source="../child"
 value=terraform_data.seed.input
}
module "right" {
 source="../child"
 value=module.left.value
}
output "value" {value=module.right.value}`),
		filepath.Join(root, "child", "main.tf"): []byte(`variable "value" {}
module "leaf" {
 source="../leaf"
 value=var.value
}
output "value" {value=module.leaf.value}`),
		filepath.Join(root, "leaf", "main.tf"): []byte(`variable "value" {}
output "value" {value=var.value}`),
	}
}

// cachedResources counts distinct resource structs retained by the cache,
// accounting for subtree nodes shared by multiple entries.
func cachedResources(e *Evaluator) int {
	total := 0
	seen := map[*resourceTree]bool{}
	var pending []*resourceTree
	for _, entry := range e.cache {
		pending = append(pending, entry.resources)
	}
	for len(pending) > 0 {
		last := len(pending) - 1
		node := pending[last]
		pending = pending[:last]
		if node == nil || seen[node] {
			continue
		}
		seen[node] = true
		total += len(node.local)
		pending = append(pending, node.source)
		pending = append(pending, node.children...)
	}
	return total
}

// Releasing between roots must keep cache retention flat as roots are added,
// even when every root evaluates a shared module chain with distinct inputs.
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
	for _, width := range []int{1, 16, 64, 128, 512} {
		for _, distinct := range []bool{false, true} {
			for _, track := range []bool{false, true} {
				t.Run(fmt.Sprintf("siblings%d/distinct%t/track%t", width, distinct, track), func(t *testing.T) {
					root := t.TempDir()
					e := NewWithFS(vfs.NewMemFS(siblingModuleFiles(root, width, distinct)))
					e.SetTrackModuleInstances(track)
					entry := filepath.Join(root, "entry")
					var baselineBytes uint64
					if width == 512 {
						// Each selectable case owns its baseline; sibling subtests
						// may be filtered, shuffled or run independently by an IDE.
						baseline := NewWithFS(vfs.NewMemFS(siblingModuleFiles(root, 128, distinct)))
						baseline.SetTrackModuleInstances(track)
						var before, after runtime.MemStats
						runtime.ReadMemStats(&before)
						_, _, _, baselineErr := baseline.EvaluateModule(t.Context(), entry, nil)
						baseline.TakeModuleInstances()
						runtime.ReadMemStats(&after)
						require.NoError(t, baselineErr)
						baselineBytes = after.TotalAlloc - before.TotalAlloc
						require.Positive(t, baselineBytes)
					}
					var previousOutputs map[string]cty.Value
					var previousResources []ResolvedResource
					var previousInstances []ModuleInstance
					for pass := range 3 {
						if pass == 2 {
							e.ReleaseEvalCache()
						}
						var before, after runtime.MemStats
						if pass == 0 && width == 512 {
							runtime.ReadMemStats(&before)
						}
						resources, outputs, _, err := e.EvaluateModule(t.Context(), entry, nil)
						instances := e.TakeModuleInstances()
						if pass == 0 && width == 512 {
							runtime.ReadMemStats(&after)
							allocated := after.TotalAlloc - before.TotalAlloc
							// Fixed depth and per-instance payload imply linear work.
							// Allow 50% headroom over proportional 4x growth.
							require.LessOrEqual(t, allocated, 6*baselineBytes, "allocation growth must follow occurrences, not accumulated sibling prefixes")
						}
						require.NoError(t, err)
						require.Len(t, resources, width)
						values := outputs["values"].AsValueSlice()
						require.Len(t, values, width)
						for i := range width {
							want := cty.NumberIntVal(0)
							if distinct {
								want = cty.NumberIntVal(int64(i))
							}
							require.True(t, want.RawEquals(values[i]))
							require.True(t, want.RawEquals(resources[i].Attributes["input"]))
						}
						expected := 0
						if track {
							expected = 5 * width
						}
						require.Len(t, instances, expected)
						addresses := map[string]bool{}
						for _, instance := range instances {
							require.False(t, addresses[instance.ModuleAddress])
							addresses[instance.ModuleAddress] = true
							require.Len(t, instance.CallChain, strings.Count(instance.ModuleAddress, "module."))
							if len(instance.CallChain) > 1 {
								want := cty.NumberIntVal(0)
								if distinct {
									want = instance.CallChain[0].InstanceKey
								}
								require.True(t, want.RawEquals(instance.CallChain[len(instance.CallChain)-1].Caller.Var.GetAttr("value")))
							}
						}
						if pass == 1 {
							require.Equal(t, previousOutputs, outputs)
							require.Equal(t, previousResources, resources)
							require.Equal(t, previousInstances, instances)
						}
						previousOutputs, previousResources, previousInstances = outputs, resources, instances
					}
				})
			}
		}
	}

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

func BenchmarkEvaluateModuleSiblingInputs(b *testing.B) {
	for _, width := range []int{64, 128, 256, 512} {
		b.Run(fmt.Sprint(width), func(b *testing.B) {
			root := b.TempDir()
			fsys := vfs.NewMemFS(siblingModuleFiles(root, width, true))
			entry := filepath.Join(root, "entry")
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				e := NewWithFS(fsys)
				e.SetTrackModuleInstances(true)
				resources, _, _, err := e.EvaluateModule(b.Context(), entry, nil)
				if err != nil || len(resources) != width || len(e.TakeModuleInstances()) != 5*width {
					b.Fatalf("incomplete evaluation: %v", err)
				}
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			retained := NewWithFS(fsys)
			retained.SetTrackModuleInstances(true)
			if _, _, _, err := retained.EvaluateModule(b.Context(), entry, nil); err != nil {
				b.Fatal(err)
			}
			retained.TakeModuleInstances()
			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(retained)
			if after.HeapAlloc > before.HeapAlloc {
				b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
			}
		})
	}
}
