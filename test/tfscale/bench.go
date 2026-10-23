/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfscale

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// Run is one measured scanner run over a generated fixture.
type Run struct {
	Shape    string   `json:"shape"`
	Label    string   `json:"label"`
	Expected Expected `json:"expected"`

	WallSeconds float64 `json:"wall_seconds"`
	CPUSeconds  float64 `json:"cpu_seconds"`
	PeakRSS     int64   `json:"peak_rss_bytes"`
	ExitCode    int     `json:"exit_code"`
	TimedOut    bool    `json:"timed_out"`

	// Counters the scanner logs, absent from scanners that do not log them.
	ModuleResources  int      `json:"module_resources_instantiated"`
	ModuleDocuments  int      `json:"module_documents"`
	EvaluatedModules int      `json:"evaluated_module_instances"`
	EvalCacheEntries int      `json:"eval_cache_entries"`
	GoTotalAlloc     int64    `json:"go_total_alloc_bytes"`
	GoMallocs        int64    `json:"go_mallocs"`
	Truncations      int      `json:"count_expansion_truncated"`
	BudgetExhausted  bool     `json:"resource_budget_exhausted"`
	Warnings         []string `json:"warnings,omitempty"`

	Findings       int            `json:"findings"`
	FindingsByRule map[string]int `json:"findings_by_rule"`

	// Complete is set when the findings the fixture guarantees are all present
	// and nothing was truncated.
	Complete bool     `json:"complete"`
	Problems []string `json:"problems,omitempty"`
}

// Rules is the rule bundle every run of a comparison scans with.
type Rules struct {
	// Dir holds queries/ and libraries/.
	Dir string
	// Bundle is a directory `fetch-bundle` wrote, used instead of Dir.
	Bundle string
}

// ScanArgs are the production-equivalent scanner flags.
func ScanArgs(fixture, output string, rules Rules) []string {
	args := []string{
		"--log-level", "info",
		"--log-format", "json",
		"scan",
		"--x-parallelparsing",
		"--x-local-module-eval",
		"--x-disable-rule-isolation",
		"-p", fixture,
		"-o", output,
		"-t", "Terraform",
	}
	if rules.Bundle != "" {
		return append(args, "--offline-bundle-path", rules.Bundle)
	}
	return append(args,
		"-q", filepath.Join(rules.Dir, "queries"),
		"--libraries-path", filepath.Join(rules.Dir, "libraries"))
}

// PrepareRepo makes dir a git repository with an origin, which the scanner
// requires to report commit information.
func PrepareRepo(ctx context.Context, dir string) error {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return nil
	}
	steps := [][]string{
		{"init", "-q", "."},
		{"remote", "add", "origin", "https://example.invalid/tfscale.git"},
		{"add", "-A"},
		{"-c", "user.email=tfscale@example.invalid", "-c", "user.name=tfscale", "commit", "-q", "-m", "fixture"},
	}
	for _, args := range steps {
		cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // fixed git subcommands on a generated fixture
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %w: %s", args, err, out)
		}
	}
	return nil
}

// Measure runs scanner over fixture and checks the result against expected.
func Measure(
	ctx context.Context, scanner string, rules Rules, fixture, work string, expected *Expected, timeout time.Duration,
) (Run, error) {
	run := Run{Shape: expected.Shape.Name, Expected: *expected}
	out := filepath.Join(work, "out")
	if err := os.RemoveAll(out); err != nil {
		return run, err
	}
	logPath := filepath.Join(work, "scanner.log")
	logFile, err := os.Create(logPath) //nolint:gosec // the benchmark's own work directory
	if err != nil {
		return run, err
	}
	defer func() { _ = logFile.Close() }()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, scanner, ScanArgs(fixture, out, rules)...) //nolint:gosec // the scanner under benchmark
	cmd.Stdout, cmd.Stderr = logFile, logFile
	start := time.Now()
	err = cmd.Run()
	run.WallSeconds = time.Since(start).Seconds()
	run.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
	if cmd.ProcessState != nil {
		run.ExitCode = cmd.ProcessState.ExitCode()
		run.CPUSeconds = (cmd.ProcessState.UserTime() + cmd.ProcessState.SystemTime()).Seconds()
		run.PeakRSS = peakRSS(cmd.ProcessState)
	} else if err != nil {
		return run, err
	}
	if err := readLog(logPath, &run); err != nil {
		return run, err
	}
	if err := readSARIF(filepath.Join(out, "datadog-iac-scanner-result.sarif"), &run); err != nil {
		run.Problems = append(run.Problems, "no SARIF output: "+err.Error())
	}
	run.check()
	return run, nil
}

// check compares the run against the cardinality the fixture guarantees.
func (r *Run) check() {
	e := r.Expected
	if r.TimedOut {
		r.Problems = append(r.Problems, "timed out")
	}
	if got := r.FindingsByRule[ACLRule]; got != e.ACLFindings {
		r.Problems = append(r.Problems, fmt.Sprintf("%s: %d findings, want %d", ACLRule, got, e.ACLFindings))
	}
	if e.CORSFindings > 0 {
		if got := r.FindingsByRule[CORSRule]; got != e.CORSFindings {
			r.Problems = append(r.Problems, fmt.Sprintf("%s: %d findings, want %d", CORSRule, got, e.CORSFindings))
		}
	}
	if r.Truncations > 0 {
		r.Problems = append(r.Problems, fmt.Sprintf("%d expansions truncated", r.Truncations))
	}
	if r.BudgetExhausted {
		r.Problems = append(r.Problems, "instantiation budget exhausted")
	}
	r.Complete = len(r.Problems) == 0
}

// initialLogLine and maxLogLine size the buffer scanner log lines are read in.
const (
	initialLogLine = 1 << 20
	maxLogLine     = 64 << 20
)

// maxWarnings bounds the distinct warnings a run keeps.
const maxWarnings = 50

// readLog extracts the counters the scanner logs as JSON lines.
func readLog(path string, run *Run) error {
	f, err := os.Open(path) //nolint:gosec // the benchmark's own log
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, initialLogLine), maxLogLine)
	warnings := map[string]bool{}
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.HasPrefix(line, []byte("{")) {
			continue
		}
		var entry map[string]any
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		run.readEntry(entry)
		if level, _ := entry["level"].(string); level == "warn" || level == "error" {
			if msg, _ := entry["message"].(string); msg != "" && len(warnings) < maxWarnings {
				warnings[msg] = true
			}
		}
	}
	for msg := range warnings {
		run.Warnings = append(run.Warnings, msg)
	}
	sort.Strings(run.Warnings)
	return sc.Err()
}

// readEntry takes the counters one log entry holds.
func (r *Run) readEntry(entry map[string]any) {
	intField(entry, "module_resources_instantiated", &r.ModuleResources)
	intField(entry, "module_documents", &r.ModuleDocuments)
	intField(entry, "module_instances_evaluated", &r.EvaluatedModules)
	intField(entry, "eval_cache_entries", &r.EvalCacheEntries)
	intField(entry, "count_expansion_truncated", &r.Truncations)
	int64Field(entry, "go_total_alloc_bytes", &r.GoTotalAlloc)
	int64Field(entry, "go_mallocs", &r.GoMallocs)
	if v, ok := entry["resource_budget_exhausted"].(bool); ok && v {
		r.BudgetExhausted = true
	}

}

func intField(entry map[string]any, key string, dst *int) {
	if v, ok := entry[key].(float64); ok {
		*dst = int(v)
	}
}

func int64Field(entry map[string]any, key string, dst *int64) {
	if v, ok := entry[key].(float64); ok {
		*dst = int64(v)
	}
}

func readSARIF(path string, run *Run) error {
	data, err := os.ReadFile(path) //nolint:gosec // the scanner's output under the work directory
	if err != nil {
		return err
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	run.FindingsByRule = map[string]int{}
	for _, r := range doc.Runs {
		for _, res := range r.Results {
			run.FindingsByRule[res.RuleID]++
			run.Findings++
		}
	}
	return nil
}

// mibShift converts bytes to MiB.
const mibShift = 20

// MiB returns n bytes in MiB.
func MiB(n int64) int64 { return n >> mibShift }

// Thresholds bound how much a head run may regress against its baseline.
type Thresholds struct {
	MaxRSSRatio float64
	MaxCPURatio float64
}

// Compare reports the regressions of head against base, matched by shape.
// A head run that is not complete always fails, as does one whose findings
// differ from a complete baseline's.
func Compare(base, head []Run, t Thresholds) []string {
	byShape := make(map[string]*Run, len(base))
	for i := range base {
		byShape[base[i].Shape] = &base[i]
	}
	var failures []string
	for i := range head {
		h := &head[i]
		if !h.Complete {
			failures = append(failures, fmt.Sprintf("%s: instances missing: %v", h.Shape, h.Problems))
			continue
		}
		b, ok := byShape[h.Shape]
		if !ok || !b.Complete {
			continue
		}
		mib := func(n int64) int64 { return n >> mibShift }
		if b.Findings != h.Findings {
			failures = append(failures, fmt.Sprintf("%s: %d findings, baseline %d", h.Shape, h.Findings, b.Findings))
		}
		if t.MaxRSSRatio > 0 && b.PeakRSS > 0 && float64(h.PeakRSS) > float64(b.PeakRSS)*t.MaxRSSRatio {
			failures = append(failures, fmt.Sprintf("%s: peak RSS %d MiB, baseline %d MiB",
				h.Shape, mib(h.PeakRSS), mib(b.PeakRSS)))
		}
		if t.MaxCPURatio > 0 && b.CPUSeconds > 0 && h.CPUSeconds > b.CPUSeconds*t.MaxCPURatio {
			failures = append(failures, fmt.Sprintf("%s: CPU %.1fs, baseline %.1fs", h.Shape, h.CPUSeconds, b.CPUSeconds))
		}
	}
	return failures
}
