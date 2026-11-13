/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfharness runs a generated Terraform corpus through the scanner's
// two entry points and normalizes what comes back.
//
// Inspect drives the engine directly, so a test sees every raw finding
// before output formats fold them. ScanPath drives a whole scan the way the
// command line does and returns the SARIF it writes. Everything
// engine-facing lives in engine.go, so pointing the harness at another
// engine build is a one-file change.
package tfharness

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// Finding is one reported finding, normalized: file paths are relative to
// the scanned directory with forward slashes.
type Finding struct {
	Rule         string
	File         string
	Line         int
	ResourceType string
	ResourceName string
	SearchKey    string
	IdentityKey  string
	CallChain    string
	ResourceID   string
}

// Key tells one finding apart from its siblings: the properties the parity
// and indirection checks group by.
func (f Finding) Key() string {
	return strings.Join([]string{f.Rule, f.File, f.ResourceType, f.ResourceName, f.SearchKey, f.CallChain}, "|")
}

// Run is the outcome of one Inspect call.
type Run struct {
	// Vulns are the engine's findings, in engine order.
	Vulns []model.Vulnerability
	// Findings is Vulns normalized.
	Findings []Finding
}

// Sorted returns the findings in a stable order for comparisons.
func (r Run) Sorted() []Finding {
	out := append([]Finding(nil), r.Findings...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if c := strings.Compare(a.Key(), b.Key()); c != 0 {
			return c < 0
		}
		return a.Line < b.Line
	})
	return out
}

// OnSink keeps the findings of one rule.
func (r Run) OnSink(rule string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// Inspect scans dir with the probe rules of rulesDir and the shared
// libraries at librariesPath, through the engine's Inspect entry point.
func Inspect(t *testing.T, dir, rulesDir, librariesPath string) Run {
	t.Helper()
	return inspect(t, dir, rulesDir, librariesPath, nil)
}

// ParseTree parses every Terraform file under dir, in walk order.
func ParseTree(t *testing.T, dir string) model.FileMetadatas {
	t.Helper()
	return parseTerraformTree(t, dir)
}

// InspectParsed runs the engine over already parsed files, in the order
// given.
func InspectParsed(t *testing.T, files model.FileMetadatas, rulesDir, librariesPath, repoPath string) Run {
	t.Helper()
	ins := newInspector(t, rulesDir, librariesPath, repoPath)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"Terraform"})
	if err != nil {
		t.Fatal(err)
	}
	failed := ins.GetFailedQueries()
	if len(failed) > 0 {
		t.Fatalf("probe rules failed to evaluate: %v", failed)
	}
	return Run{Vulns: vulns, Findings: normalize(t, repoPath, vulns)}
}

// InspectCompact runs Inspect with the engine keeping one finding per
// identity as each rule's results are decoded.
func InspectCompact(t *testing.T, dir, rulesDir, librariesPath string) Run {
	t.Helper()
	return inspect(t, dir, rulesDir, librariesPath, func(in Inspector) {
		in.SetCompactFindingsAtDecode(true)
	})
}

// InspectWith scans like Inspect and lets the caller configure the inspector
// before it runs.
func InspectWith(t *testing.T, dir, rulesDir, librariesPath string, configure func(Inspector)) Run {
	t.Helper()
	return inspect(t, dir, rulesDir, librariesPath, configure)
}

// Inspector is the handle InspectWith configures.
type Inspector interface {
	SetCompactFindingsAtDecode(compact bool)
}

// ScanPath scans dir the way the command line does and returns the SARIF
// report, with the tool version and timing removed so two runs compare.
func ScanPath(t *testing.T, dir, rulesDir, librariesPath string) []byte {
	t.Helper()
	out := t.TempDir()
	scanTo(t, dir, rulesDir, librariesPath, out)
	raw, err := os.ReadFile(filepath.Join(out, "result.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	return normalizeSARIF(t, raw)
}

// normalizeSARIF strips the fields that change between runs of the same
// build, so byte comparison only sees real differences.
func normalizeSARIF(t *testing.T, raw []byte) []byte {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	runs, ok := report["runs"].([]any)
	if ok && len(runs) > 0 {
		if tool, ok := runs[0].(map[string]any)["tool"].(map[string]any); ok {
			if driver, ok := tool["driver"].(map[string]any); ok {
				delete(driver, "version")
				delete(driver, "semanticVersion")
				if info, ok := driver["informationUri"].(string); ok {
					_ = info
				}
			}
		}
	}
	delete(report, "version")
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// HasContract reports whether the engine build understands the contract
// input: it probes with one root that only a contract rule can flag.
func HasContract(t *testing.T, rulesDir, librariesPath string) bool {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.tf"), "resource \"aws_s3_bucket\" \"sink\" {\n  probe = \"fire\"\n}\n")
	run := Inspect(t, dir, rulesDir, librariesPath)
	for _, f := range run.Findings {
		if strings.HasPrefix(f.Rule, "probe-contract-") {
			return true
		}
	}
	return false
}

// FailureMessage renders a cell's findings for an assertion message.
func FailureMessage(cell, repro string, findings []Finding) string {
	var b strings.Builder
	b.WriteString(cell)
	b.WriteString("\n")
	for _, f := range findings {
		fmt.Fprintln(&b, f.Rule+" "+f.File+":"+itoa(f.Line)+" "+f.ResourceName+" "+f.SearchKey)
	}
	b.WriteString(repro)
	return b.String()
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
