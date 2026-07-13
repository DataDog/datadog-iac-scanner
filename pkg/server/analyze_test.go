/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return New(&Config{})
}

const syntheticRuleID = "test-terraform-resource-missing-owner"

// syntheticRule imports both test-only pushed libraries. Its identifiers and
// behavior are deliberately unrelated to the production rule corpus.
func syntheticRule() analyzeRule {
	return analyzeRule{
		ID:       syntheticRuleID,
		Platform: "terraform",
		Content: `package datadog

import rego.v1

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

DatadogPolicy contains result if {
	common_lib.library_enabled
	resource := input.document[i].resource[resource_type][name]
	not common_lib.has_owner(resource)
	result := {
		"documentId": input.document[i].id,
		"resourceType": resource_type,
		"resourceName": tf_lib.display_name(resource_type, name),
		"searchKey": sprintf("%s[%s].labels.owner", [resource_type, name]),
	}
}`,
		Metadata: map[string]any{
			"id":        syntheticRuleID,
			"queryName": "Synthetic missing owner label",
			"severity":  "INFO",
			"platform":  "Terraform",
			"category":  "Test",
		},
	}
}

func testLibraries(enabled bool) []analyzeLibrary {
	return []analyzeLibrary{
		{
			ID: "common",
			Content: `package generic.common

import rego.v1

library_enabled if data.test.enabled

has_owner(resource) if resource.labels.owner`,
			InputData: fmt.Sprintf(`{"test":{"enabled":%t}}`, enabled),
		},
		{
			ID: "terraform",
			Content: `package generic.terraform

import rego.v1

display_name(resource_type, name) := sprintf("%s.%s", [resource_type, name])`,
		},
	}
}

func postAnalyze(t *testing.T, s *Server, req analyzeRequest) (*analyzeResponse, int) {
	t.Helper()
	if len(req.Libraries) == 0 {
		req.Libraries = testLibraries(true)
	}
	out, err := s.analyze(context.Background(), &req)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return out, http.StatusOK
}

// TestAnalyze_ContentPush_TerraformFinding verifies the full content-push path:
// a pushed Terraform file plus its sibling variables file are scanned in memory
// (no disk), a synthetic rule fires, and same-directory siblings resolve without
// being reported missing.
func TestAnalyze_ContentPush_TerraformFinding(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: `resource "aws_s3_bucket" "b" {
  bucket = var.bucket_name
}`},
			{Path: "infra/variables.tf", Content: `variable "bucket_name" { default = "my-bucket" }`},
		},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	if len(out.Findings) == 0 {
		t.Fatalf("expected at least one synthetic finding, got none; failed queries: %v", out.FailedQueries)
	}
	var found bool
	for _, f := range out.Findings {
		if f.QueryID == syntheticRuleID {
			found = true
			if f.FileName != "infra/main.tf" {
				t.Errorf("finding fileName = %q, want infra/main.tf", f.FileName)
			}
		}
	}
	if !found {
		t.Errorf("expected the synthetic rule to fire; findings = %+v", out.Findings)
	}
	// Same-directory siblings resolve via the in-memory glob, so nothing is
	// reported missing.
	if len(out.MissingFiles) != 0 {
		t.Errorf("expected no missing files for same-dir siblings, got %v", out.MissingFiles)
	}
}

// TestAnalyze_MissingModuleEscalation verifies a Terraform module pointing at a
// directory that was not pushed is reported in missing_files as a clean
// workspace-relative path (the hybrid escalation signal).
func TestAnalyze_MissingModuleEscalation(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: `module "net" {
  source = "../modules/networking"
}
resource "aws_s3_bucket" "b" { bucket = "x" }`},
		},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var sawModule bool
	for _, m := range out.MissingFiles {
		if m == "modules/networking" {
			sawModule = true
		}
		if filepath.IsAbs(m) {
			t.Errorf("missing path should be workspace-relative, got absolute: %q", m)
		}
	}
	if !sawModule {
		t.Errorf("expected modules/networking in missing_files, got %v", out.MissingFiles)
	}
}

// TestAnalyze_MissingFilesCWDIndependent proves missing_files are
// workspace-relative regardless of the server process's working directory. A
// single server serves many IDE workspaces/windows, so the result must not
// depend on where the binary was launched.
func TestAnalyze_MissingFilesCWDIndependent(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()
	req := analyzeRequest{
		Files: []analyzeFile{{Path: "infra/main.tf", Content: `module "net" {
  source = "../modules/networking"
}
resource "aws_s3_bucket" "b" { bucket = "x" }`}},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
	}

	// Move CWD somewhere unrelated to the (virtual) workspace.
	t.Chdir(t.TempDir())

	out, _ := postAnalyze(t, s, req)
	if len(out.MissingFiles) != 1 || out.MissingFiles[0] != "modules/networking" {
		t.Errorf("missing_files = %v, want [modules/networking] (workspace-relative, CWD-independent)", out.MissingFiles)
	}
}

// TestAnalyze_Validation exercises the request validation rules.
func TestAnalyze_Validation(t *testing.T) {
	s := New(&Config{})
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	validRule := analyzeRule{ID: "test-rule", Platform: "terraform", Content: "package datadog"}
	validLibraries := []analyzeLibrary{
		{ID: "common", Content: "package generic.common"},
		{ID: "terraform", Content: "package generic.terraform"},
	}
	cases := []struct {
		name string
		req  analyzeRequest
		body string // used only for malformed input
		want int
	}{
		{
			name: "empty files",
			req:  analyzeRequest{Rules: []analyzeRule{validRule}, Libraries: validLibraries},
			want: http.StatusBadRequest,
		},
		{
			name: "empty rules",
			req: analyzeRequest{
				Files: []analyzeFile{{Path: "main.tf", Content: "x"}}, Libraries: validLibraries,
			},
			want: http.StatusBadRequest,
		},
		{
			name: "path traversal",
			req: analyzeRequest{
				Files: []analyzeFile{{Path: "../escape.tf", Content: "x"}},
				Rules: []analyzeRule{validRule}, Libraries: validLibraries,
			},
			want: http.StatusBadRequest,
		},
		{
			name: "absolute path",
			req: analyzeRequest{
				Files: []analyzeFile{{Path: "/etc/passwd", Content: "x"}},
				Rules: []analyzeRule{validRule}, Libraries: validLibraries,
			},
			want: http.StatusBadRequest,
		},
		{name: "malformed json", body: `{`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			if tc.body == "" {
				var err error
				body, err = json.Marshal(tc.req)
				if err != nil {
					t.Fatalf("marshal request: %v", err)
				}
			}
			resp, err := http.Post(ts.URL+"/ide/v1/iac/analyze", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestValidateAnalyzeRequest_Libraries(t *testing.T) {
	base := analyzeRequest{
		Files: []analyzeFile{{Path: "main.tf", Content: "resource"}},
		Rules: []analyzeRule{{ID: "rule", Platform: "Terraform", Content: "package datadog"}},
	}
	tests := []struct {
		name      string
		libraries []analyzeLibrary
		wantError string
	}{
		{name: "missing", wantError: "at least one library is required"},
		{
			name: "missing common",
			libraries: []analyzeLibrary{
				{ID: "terraform", Content: "package generic.terraform"},
			},
			wantError: "common library is required",
		},
		{
			name: "missing platform",
			libraries: []analyzeLibrary{
				{ID: "common", Content: "package generic.common"},
			},
			wantError: "library is required for rule platform: Terraform",
		},
		{
			name: "noncanonical id",
			libraries: []analyzeLibrary{
				{ID: "Common", Content: "package generic.common"},
				{ID: "terraform", Content: "package generic.terraform"},
			},
			wantError: "library id must be canonical lowercase: Common",
		},
		{
			name: "duplicate id",
			libraries: []analyzeLibrary{
				{ID: "common", Content: "package generic.common"},
				{ID: "common", Content: "package generic.common"},
				{ID: "terraform", Content: "package generic.terraform"},
			},
			wantError: "duplicate library id: common",
		},
		{
			name: "invalid input data",
			libraries: []analyzeLibrary{
				{ID: "common", Content: "package generic.common", InputData: "{"},
				{ID: "terraform", Content: "package generic.terraform"},
			},
			wantError: "invalid library input data for common",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			req.Libraries = tt.libraries
			err := validateAnalyzeRequest(&req, defaultMaxFiles)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateAnalyzeRequest() error = %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantError {
				t.Fatalf("validateAnalyzeRequest() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestAnalyze_NormalizesRuleAndScanPlatforms(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()
	rule.Platform = " Terraform "
	req := analyzeRequest{
		Files: []analyzeFile{{
			Path:    "infra/main.tf",
			Content: `resource "test_widget" "example" {}`,
		}},
		Rules:     []analyzeRule{rule},
		Libraries: testLibraries(true),
		Platform:  []string{" Terraform "},
	}
	if err := validateAnalyzeRequest(&req, defaultMaxFiles); err != nil {
		t.Fatalf("validateAnalyzeRequest() error = %v", err)
	}

	out, _ := postAnalyze(t, s, req)
	if len(out.Findings) != 1 || out.Findings[0].QueryID != syntheticRuleID {
		t.Fatalf("normalized platform request returned findings %+v", out.Findings)
	}
}

func TestAnalyze_RequestLibrariesInvalidateSharedRuleCache(t *testing.T) {
	s := New(&Config{UseRulesCache: true, DisableRuleIsolation: true})
	req := analyzeRequest{
		Files: []analyzeFile{{
			Path:    "infra/main.tf",
			Content: `resource "aws_s3_bucket" "b" { bucket = "x" }`,
		}},
		Rules:     []analyzeRule{syntheticRule()},
		Libraries: testLibraries(true),
		Platform:  []string{"terraform"},
	}

	enabled, _ := postAnalyze(t, s, req)
	if len(enabled.Findings) == 0 {
		t.Fatal("expected a finding when pushed library input enables the rule")
	}

	req.Libraries = testLibraries(false)
	disabled, _ := postAnalyze(t, s, req)
	if len(disabled.Findings) != 0 {
		t.Fatalf("stale cached rule used old library input; findings: %+v", disabled.Findings)
	}
}

func TestAnalyze_RequestLibrariesDoNotCallBackend(t *testing.T) {
	originalClient := http.DefaultClient
	var requests atomic.Int64
	http.DefaultClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, fmt.Errorf("unexpected outbound request to %s", req.URL)
	})}
	t.Cleanup(func() { http.DefaultClient = originalClient })

	s := New(&Config{})
	out, _ := postAnalyze(t, s, analyzeRequest{
		Files: []analyzeFile{{
			Path:    "infra/main.tf",
			Content: `resource "aws_s3_bucket" "b" { bucket = "x" }`,
		}},
		Rules:     []analyzeRule{syntheticRule()},
		Libraries: testLibraries(true),
		Platform:  []string{"terraform"},
	})
	if len(out.Findings) == 0 {
		t.Fatal("expected request-supplied rules and libraries to produce a finding")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server mode made %d outbound HTTP requests, want 0", got)
	}
}

// TestConfigDefaults checks that New applies the documented defaults for the
// configurable limits/timeouts, including the negative-WriteTimeout "disabled"
// sentinel.
func TestConfigDefaults(t *testing.T) {
	s := New(&Config{})
	if s.cfg.MaxFiles != defaultMaxFiles {
		t.Errorf("MaxFiles default = %d, want %d", s.cfg.MaxFiles, defaultMaxFiles)
	}
	if s.cfg.WriteTimeout != defaultWriteTimeout {
		t.Errorf("WriteTimeout default = %v, want %v", s.cfg.WriteTimeout, defaultWriteTimeout)
	}
	if s.http.WriteTimeout != defaultWriteTimeout {
		t.Errorf("http.WriteTimeout = %v, want %v", s.http.WriteTimeout, defaultWriteTimeout)
	}

	// Negative WriteTimeout disables the timeout entirely.
	sd := New(&Config{WriteTimeout: -1})
	if sd.http.WriteTimeout != 0 {
		t.Errorf("disabled WriteTimeout: http.WriteTimeout = %v, want 0", sd.http.WriteTimeout)
	}

	// Explicit values are honored.
	sc := New(&Config{MaxFiles: 7, WriteTimeout: 42 * time.Second})
	if sc.cfg.MaxFiles != 7 || sc.http.WriteTimeout != 42*time.Second {
		t.Errorf("explicit config not honored: MaxFiles=%d WriteTimeout=%v", sc.cfg.MaxFiles, sc.http.WriteTimeout)
	}
}

// TestAnalyze_MaxFilesEnforced confirms the per-server MaxFiles cap rejects an
// over-limit request with 400.
func TestAnalyze_MaxFilesEnforced(t *testing.T) {
	s := New(&Config{MaxFiles: 2})
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	body := `{"files":[{"path":"a.tf","content":"x"},{"path":"b.tf","content":"x"},{"path":"c.tf","content":"x"}],"rules":[]}`
	resp, err := http.Post(ts.URL+"/ide/v1/iac/analyze", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("3 files with MaxFiles=2: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// TestLifecycle_Contract checks the SAST-mirrored lifecycle contract: /ping
// returns "pong", standard + CORS headers are present, and /shutdown is gated by
// --enable-shutdown.
func TestLifecycle_Contract(t *testing.T) {
	s := New(&Config{}) // EnableShutdown defaults false
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ping")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	body, _ := readAll(resp)
	if resp.StatusCode != http.StatusOK || string(body) != "pong" {
		t.Errorf("/ping = %d %q, want 200 pong", resp.StatusCode, body)
	}
	for _, h := range []string{"X-Iac-Scanner-Server-Version", "Access-Control-Allow-Origin", "X-Request-Id"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing response header %s", h)
		}
	}

	// Shutdown is disabled by default → 403.
	sresp, err := http.Post(ts.URL+"/shutdown", "", nil)
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	defer sresp.Body.Close()
	if sresp.StatusCode != http.StatusForbidden {
		t.Errorf("/shutdown (disabled) = %d, want 403", sresp.StatusCode)
	}

	// Supported-files returns the strategy map.
	fresp, err := http.Get(ts.URL + "/ide/v1/iac/supported-files")
	if err != nil {
		t.Fatalf("supported-files: %v", err)
	}
	defer fresp.Body.Close()
	var entries []SupportedFileEntry
	if err := json.NewDecoder(fresp.Body).Decode(&entries); err != nil {
		t.Fatalf("decode supported-files: %v", err)
	}
	if len(entries) == 0 {
		t.Errorf("supported-files returned no entries")
	}
}

// TestAnalyze_Concurrent runs many analyze requests in parallel — each spawning
// a multi-worker inspector over several documents — to exercise the engine's
// shared per-request state (notably the failedQueries map written by worker
// goroutines). Run with `go test -race` to surface data races.
func TestAnalyze_Concurrent(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()

	files := make([]analyzeFile, 0, 6)
	for i := range 6 {
		files = append(files, analyzeFile{
			Path:    fmt.Sprintf("infra/r%d.tf", i),
			Content: fmt.Sprintf(`resource "aws_s3_bucket" "b%d" { bucket = "x%d" }`, i, i),
		})
	}
	// Replicate the rule under distinct IDs so the inspector runs several queries
	// across multiple worker goroutines, producing findings concurrently — this
	// exercises the shared per-request engine state (failedQueries, the shared
	// line detector) that earlier raced under -race.
	rules := make([]analyzeRule, 0, 8)
	for i := range 8 {
		r := rule
		r.ID = fmt.Sprintf("%s-%d", rule.ID, i)
		rules = append(rules, r)
	}
	req := analyzeRequest{
		Files: files, Rules: rules, Libraries: testLibraries(true), Platform: []string{"terraform"},
	}

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		// Each goroutine builds its own client/inspector; the request value is
		// read-only and safe to share.
		wg.Go(func() {
			out, err := s.analyze(context.Background(), &req)
			if err != nil {
				errs <- err
				return
			}
			if len(out.Findings) == 0 {
				errs <- fmt.Errorf("expected findings, got none")
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent analyze: %v", err)
	}
}

// TestAnalyze_ConfigWithoutIacSection guards against a nil-pointer panic when
// the caller pushes a valid config that has no `iac` section (e.g. a workspace
// configured only for secrets). ParseConfig returns (nil, nil) there; analyze
// must fall back to the empty IaC config rather than dereferencing nil.
func TestAnalyze_ConfigWithoutIacSection(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()

	req := analyzeRequest{
		Files:    []analyzeFile{{Path: "infra/main.tf", Content: `resource "aws_s3_bucket" "b" { bucket = "x" }`}},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
		Config:   "schema-version: v1.3\nsecrets:\n  enabled: true\n",
	}

	out, _ := postAnalyze(t, s, req) // must not panic
	if len(out.Findings) == 0 {
		t.Errorf("expected findings with an iac-less config (empty config fallback), got none")
	}
}

// TestAnalyze_ConfigIgnoreRulePushedRule verifies that ignore-rules in config
// suppresses a rule even when the caller pushes that rule in the request — the
// pushed-rule source must apply the same query filters the filesystem source
// applies.
func TestAnalyze_ConfigIgnoreRulePushedRule(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()

	req := analyzeRequest{
		Files:    []analyzeFile{{Path: "infra/main.tf", Content: `resource "aws_s3_bucket" "b" { bucket = "x" }`}},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
		Config:   "schema-version: v1.3\niac:\n  ignore-rules:\n    - " + syntheticRuleID + "\n",
	}

	out, _ := postAnalyze(t, s, req)
	for _, f := range out.Findings {
		if f.QueryID == syntheticRuleID {
			t.Errorf("ignore-rules should have suppressed the pushed rule, but it fired: %+v", f)
		}
	}
}

// TestAnalyze_ConfigIgnorePaths verifies that global ignore-paths in config
// suppresses findings for matching pushed files in the in-memory (server) scan
// path, mirroring the disk scanner's behavior.
func TestAnalyze_ConfigIgnorePaths(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()
	body := `resource "aws_s3_bucket" "b" { bucket = "x" }`

	// Baseline: without filters the rule fires on infra/main.tf.
	base, _ := postAnalyze(t, s, analyzeRequest{
		Files:    []analyzeFile{{Path: "infra/main.tf", Content: body}},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
	})
	if len(base.Findings) == 0 {
		t.Fatalf("baseline expected findings, got none")
	}

	// With ignore-paths covering infra/, the file is skipped → no findings.
	out, _ := postAnalyze(t, s, analyzeRequest{
		Files:    []analyzeFile{{Path: "infra/main.tf", Content: body}},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
		Config:   "schema-version: v1.3\niac:\n  global-config:\n    ignore-paths:\n      - \"infra/**\"\n",
	})
	if len(out.Findings) != 0 {
		t.Errorf("ignore-paths should have skipped infra/main.tf, got findings: %+v", out.Findings)
	}
}

// TestKeepAlive_NotShutdownWhileInFlight verifies the keep-alive monitor does
// not shut the server down while a request is being handled, even after the
// idle window has elapsed — then shuts down once the request completes and the
// server is genuinely idle.
func TestKeepAlive_NotShutdownWhileInFlight(t *testing.T) {
	s := New(&Config{KeepAliveTimeout: 15 * time.Millisecond})
	s.pollInterval = 2 * time.Millisecond
	// Look idle for far longer than the keep-alive window.
	s.lastRequestNanos.Store(time.Now().Add(-time.Hour).UnixNano())
	// But a request is in flight.
	s.inFlight.Add(1)

	go s.keepAliveMonitor(t.Context())

	select {
	case <-s.shutdownCh:
		t.Fatal("server shut down while a request was in flight")
	case <-time.After(60 * time.Millisecond):
	}

	// Request completes; server is now idle past the window → must shut down.
	s.inFlight.Add(-1)
	s.lastRequestNanos.Store(time.Now().Add(-time.Hour).UnixNano())
	select {
	case <-s.shutdownCh:
	case <-time.After(time.Second):
		t.Fatal("server did not shut down after the request completed and idle elapsed")
	}
}

// TestAnalyze_ConcurrencyLimit verifies /analyze returns 503 once the
// concurrency limit is saturated, without running a scan.
func TestAnalyze_ConcurrencyLimit(t *testing.T) {
	s := New(&Config{MaxConcurrentAnalyze: 1})
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	// Saturate the single slot so the next request is rejected.
	s.analyzeSem <- struct{}{}

	resp, err := http.Post(ts.URL+"/ide/v1/iac/analyze", "application/json",
		strings.NewReader(`{"files":[{"path":"a.tf","content":"x"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when concurrency limit is saturated", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("expected a Retry-After header on the 503 response")
	}
}

// TestAnalyze_HCLCacheIsolatedBetweenRequests verifies that the per-scan HCL
// parse cache does not bleed between server analyze calls. If the cache were
// reused across requests, the second request's line-detection would use stale
// block ranges from the first parse and report an incorrect finding line.
func TestAnalyze_HCLCacheIsolatedBetweenRequests(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()

	// Request 1: resource is at line 1.
	req1 := analyzeRequest{
		Files:    []analyzeFile{{Path: "infra/main.tf", Content: "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n"}},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
	}
	out1, _ := postAnalyze(t, s, req1)
	if len(out1.Findings) == 0 {
		t.Fatalf("request 1: expected at least one finding, got none")
	}
	var line1 int
	for _, f := range out1.Findings {
		if f.QueryID == rule.ID {
			line1 = f.Line
		}
	}
	if line1 == 0 {
		t.Fatalf("request 1: rule did not fire")
	}

	// Request 2: same path, resource pushed down by 3 blank lines. A stale
	// cached body from request 1 would return the old block range (line 1),
	// not the updated one.
	req2 := analyzeRequest{
		Files:    []analyzeFile{{Path: "infra/main.tf", Content: "\n\n\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n"}},
		Rules:    []analyzeRule{rule},
		Platform: []string{"terraform"},
	}
	out2, _ := postAnalyze(t, s, req2)
	if len(out2.Findings) == 0 {
		t.Fatalf("request 2: expected at least one finding, got none")
	}
	var line2 int
	for _, f := range out2.Findings {
		if f.QueryID == rule.ID {
			line2 = f.Line
		}
	}
	if line2 == 0 {
		t.Fatalf("request 2: rule did not fire")
	}

	if line2 <= line1 {
		t.Errorf("request 2 finding line = %d, want > %d (resource was pushed down by 3 lines; stale HCL cache would return the old position)", line2, line1)
	}
}

func readAll(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}
