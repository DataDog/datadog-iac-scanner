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
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeNestedFanOutForProbe(t *testing.T, depth, branch int) string {
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

// TestProbe_OOMReproBeforeAfter compares peak heap for the nested fan-out shape
// that matches production OOMs. Run explicitly:
//
//	go test ./pkg/parser/terraform/tfeval -run TestProbe_OOMReproBeforeAfter -v -count=1
//
// Set IAC_PROBE_DEPTH and IAC_PROBE_BRANCH to tune (defaults depth=12 branch=3).
func TestProbe_OOMReproBeforeAfter(t *testing.T) {
	if os.Getenv("IAC_PROBE_OOM") == "" {
		t.Skip("set IAC_PROBE_OOM=1 to run the OOM reproduction probe")
	}

	depth := 12
	if v := os.Getenv("IAC_PROBE_DEPTH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("IAC_PROBE_DEPTH: %v", err)
		}
		depth = n
	}
	branch := 3
	if v := os.Getenv("IAC_PROBE_BRANCH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("IAC_PROBE_BRANCH: %v", err)
		}
		branch = n
	}

	stack := writeNestedFanOutForProbe(t, depth, branch)
	theoretical := powInt(branch, depth-1)

	t.Logf("fixture: depth=%d branch=%d files=%d theoretical_resources=branch^(depth-1)=%d",
		depth, branch, depth+1, theoretical)

	run := func(label string) (resources, cacheEntries int, peakMiB float64, elapsed time.Duration, oom bool) {
		debug.SetGCPercent(-1) // disable GC so peak allocation is visible
		defer debug.SetGCPercent(100)

		runtime.GC()
		var start runtime.MemStats
		runtime.ReadMemStats(&start)
		peak := start.HeapAlloc

		e := New()
		begin := time.Now()
		res, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
		elapsed = time.Since(begin)
		if err != nil {
			t.Logf("%s: EvaluateModule error: %v", label, err)
		}

		var end runtime.MemStats
		runtime.ReadMemStats(&end)
		if end.HeapAlloc > peak {
			peak = end.HeapAlloc
		}
		peakMiB = float64(peak-start.HeapAlloc) / (1 << 20)

		// Detect if we hit swap/OOM pressure via runtime
		if peakMiB > 30000 {
			oom = true
		}
		return len(res), len(e.cache), peakMiB, elapsed, oom
	}

	mode := os.Getenv("IAC_PROBE_MODE")
	if mode == "" {
		mode = "current"
	}

	res, cache, peak, elapsed, _ := run(mode)
	t.Logf("%s: resources=%d cache_entries=%d peak_heap=%.1f MiB elapsed=%s",
		mode, res, cache, peak, elapsed.Round(time.Millisecond))

	if cache > depth+2 {
		t.Errorf("WITH FIX: cache has %d entries, expected ~%d", cache, depth+1)
	}
	if theoretical <= defaultMaxInstantiated && res != theoretical {
		t.Errorf("resolved %d resources, want %d below the instantiation budget",
			res, theoretical)
	}
}

func powInt(base, exp int) int {
	r := 1
	for i := 0; i < exp; i++ {
		r *= base
	}
	return r
}

// The value-heavy fixture below matches the nested fan-out probe with 150 tags.
// IAC_FANOUT_DEPTH=10 evaluates 19,683 leaves; depth 12 evaluates 177,147.
// The benchmark disables the resource budget and asserts every leaf is returned.

func writeTagFanout(tb testing.TB, depth int, repeated bool) string {
	tb.Helper()
	root := tb.TempDir()
	for level := 0; level < depth; level++ {
		dir := filepath.Join(root, fmt.Sprintf("lvl%02d", level))
		require.NoError(tb, os.MkdirAll(dir, 0o755))
		var body strings.Builder
		body.WriteString("variable \"in\" { type = string }\nvariable \"env\" { type = string }\n")
		if level == depth-1 {
			body.WriteString("resource \"aws_s3_bucket\" \"leaf\" {\n bucket = var.in\n acl = \"public-read\"\n tags = {\n")
			input := "in"
			if repeated {
				input = "env"
			}
			for j := 0; j < 150; j++ {
				fmt.Fprintf(&body, " tag%d = \"${var.%s}-%s-%d\"\n", j, input, strings.Repeat("v", 80), j)
			}
			body.WriteString(" }\n}\noutput \"out\" { value = var.in }\n")
		} else {
			for k := 0; k < 3; k++ {
				fmt.Fprintf(&body, "module \"m%d\" {\n source = \"../lvl%02d\"\n in = \"${var.in}-%d\"\n env = var.env\n}\n", k, level+1, k)
			}
			body.WriteString("output \"out\" { value = module.m0.out }\n")
		}
		require.NoError(tb, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body.String()), 0o644))
	}
	stack := filepath.Join(root, "stack")
	require.NoError(tb, os.MkdirAll(stack, 0o755))
	require.NoError(tb, os.WriteFile(filepath.Join(stack, "main.tf"), []byte("module \"m\" {\n source = \"../lvl00\"\n in = \"seed\"\n env = \"prod\"\n}\n"), 0o644))
	return stack
}

// BenchmarkTagFanout reproduces nested local-module fan-out with large tag
// objects. IAC_FANOUT_DEPTH=10 evaluates 19,683 resources; depth 12 evaluates
// 177,147. The resource budget is disabled so measurements include every leaf.
func BenchmarkTagFanout(b *testing.B) {
	depth := 7
	if value := os.Getenv("IAC_FANOUT_DEPTH"); value != "" {
		var err error
		depth, err = strconv.Atoi(value)
		require.NoError(b, err)
		require.Positive(b, depth)
	}
	expected := powInt(3, depth-1)
	for _, repeated := range []bool{false, true} {
		b.Run(fmt.Sprintf("repeated=%t", repeated), func(b *testing.B) {
			stack := writeTagFanout(b, depth, repeated)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				e := New()
				e.SetMaxInstantiated(0)
				resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
				require.NoError(b, err)
				require.Len(b, resources, expected)
			}
		})
	}
}

// Repeated values must share immutable evaluation storage while each instance
// keeps its own identity. Unique inputs must continue to produce unique tags.
func TestTagFanout(t *testing.T) {
	for _, repeated := range []bool{false, true} {
		t.Run(fmt.Sprintf("repeated=%t", repeated), func(t *testing.T) {
			stack := writeTagFanout(t, 4, repeated)
			e := New()
			e.SetMaxInstantiated(0)
			e.SetTrackModuleInstances(true)
			resources, _, visited, err := e.EvaluateModule(context.Background(), stack, nil)
			require.NoError(t, err)
			require.Len(t, resources, 27)
			require.Len(t, visited, 4)
			require.Len(t, e.TakeModuleInstances(), 40)
			require.Empty(t, e.NotEvaluatedDirs())
			require.Zero(t, e.ExpansionTruncations())

			seen := make(map[string]bool)
			for i := range resources {
				r := &resources[i]
				name := "seed"
				for _, segment := range strings.Split(r.ModuleAddress, ".") {
					if len(segment) == 2 && segment[0] == 'm' {
						name += "-" + segment[1:]
					}
				}
				require.False(t, seen[name], "duplicate resource instance")
				seen[name] = true
				require.Equal(t, name, r.Attributes["bucket"].AsString())
				tagPrefix := name
				if repeated {
					tagPrefix = "prod"
				}
				doc := AttributesToDocument(r)
				tags := doc["tags"].(map[string]interface{})
				require.Len(t, tags, 150)
				for j := 0; j < 150; j++ {
					require.Equal(t, fmt.Sprintf("%s-%s-%d", tagPrefix, strings.Repeat("v", 80), j), tags[fmt.Sprintf("tag%d", j)])
				}
				if i > 0 {
					require.Equal(t, repeated, sharesStorage(resources[0].Attributes["tags"], r.Attributes["tags"]),
						"only equal tag evaluations should share storage")
				}
			}
			// Dropping caches before conversion must leave resolved values renderable.
			e.ReleaseEvalCache()
			require.Len(t, AttributesToDocument(&resources[0])["tags"], 150)
		})
	}
}
