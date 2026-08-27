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
	"testing"
	"time"
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
