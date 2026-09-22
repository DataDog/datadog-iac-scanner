/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
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

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	engineSource "github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/rs/zerolog"
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

const syntheticK8sRuleID = "test-k8s-deployment-missing-owner"

var (
	analyzeCompiledQueryCacheTestMu sync.Mutex
	analyzeProcessCwdMu             sync.Mutex
)

// syntheticRule imports both test-only pushed libraries. Its identifiers and
// behavior are deliberately unrelated to the production rule corpus.
func syntheticRule() datadog.Rule {
	return datadog.Rule{
		ID:               syntheticRuleID,
		Name:             syntheticRuleID,
		ShortDescription: "Synthetic missing owner label",
		Platform:         "Terraform",
		Severity:         "INFO",
		Category:         "Test",
		IsPublished:      true,
		RegoQuery: []byte(`package datadog

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
}`),
	}
}

func testLibraries(enabled bool) []datadog.Library {
	return []datadog.Library{
		{
			ID: "common",
			RegoCode: `package generic.common

import rego.v1

library_enabled if data.test.enabled

has_owner(resource) if resource.labels.owner`,
			InputData: fmt.Sprintf(`{"test":{"enabled":%t}}`, enabled),
		},
		{
			ID: "terraform",
			RegoCode: `package generic.terraform

import rego.v1

display_name(resource_type, name) := sprintf("%s.%s", [resource_type, name])`,
		},
	}
}

// ruleset wraps rule values in the request's [datadog.Ruleset] shape.
func ruleset(rules ...datadog.Rule) datadog.Ruleset {
	ptrs := make([]*datadog.Rule, len(rules))
	for i := range rules {
		ptrs[i] = &rules[i]
	}
	return datadog.Ruleset{Rules: ptrs}
}

// newParallelTestServer is newTestServer with parallel parsing on — the serve
// binary's default, and the path that runs the shared memory dispatch (Helm
// chart rendering included).
func newParallelTestServer(t *testing.T) *Server {
	t.Helper()
	return New(&Config{ParallelParsing: true})
}

// syntheticK8sRule is the pushed-rules counterpart of syntheticRule for the
// Kubernetes platform: it fires on any Deployment whose metadata carries no
// owner label, which a pushed Helm chart renders.
func syntheticK8sRule() datadog.Rule {
	return datadog.Rule{
		ID:               syntheticK8sRuleID,
		Name:             syntheticK8sRuleID,
		ShortDescription: "Synthetic missing owner label",
		Platform:         "Kubernetes",
		Severity:         "INFO",
		Category:         "Test",
		IsPublished:      true,
		RegoQuery: []byte(`package datadog

import rego.v1

import data.generic.common as common_lib

DatadogPolicy contains result if {
	common_lib.library_enabled
	doc := input.document[i]
	doc.kind == "Deployment"
	not common_lib.has_owner(doc.metadata)
	result := {
		"documentId": input.document[i].id,
		"resourceType": "Deployment",
		"resourceName": doc.metadata.name,
		"searchKey": sprintf("%s.metadata.labels.owner", [doc.metadata.name]),
	}
}`),
	}
}

func k8sTestLibraries() []datadog.Library {
	return []datadog.Library{
		testLibraries(true)[0],
		{
			ID:       "k8s",
			RegoCode: "package generic.k8s\n\nimport rego.v1\n\nplaceholder := true",
		},
	}
}

// postAnalyzeK8s is postAnalyze with the Kubernetes library set.
func postAnalyzeK8s(t *testing.T, s *Server, req analyzeRequest) (*analyzeResponse, int) {
	t.Helper()
	req.Libraries = k8sTestLibraries()
	return postAnalyze(t, s, req)
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
		Ruleset:  ruleset(rule),
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

// TestAnalyze_ContentPush_HelmChartFinding verifies the full content-push helm
// path: a chart pushed as plain files renders through the in-memory FS, its
// manifests are scanned with the Kubernetes rules, and the finding anchors on
// the pushed template path.
func TestAnalyze_ContentPush_HelmChartFinding(t *testing.T) {
	s := newParallelTestServer(t)

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "chart/Chart.yaml", Content: "apiVersion: v2\nname: e2e\nversion: 0.1.0\n"},
			{Path: "chart/values.yaml", Content: "replicas: 1\n"},
			{Path: "chart/templates/deployment.yaml", Content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
  labels:
    app: e2e
spec:
  replicas: {{ .Values.replicas }}
`},
		},
		Ruleset:  ruleset(syntheticK8sRule()),
		Platform: []string{"kubernetes"},
	}

	out, _ := postAnalyzeK8s(t, s, req)

	var found *model.Vulnerability
	for i := range out.Findings {
		if out.Findings[i].QueryID == syntheticK8sRuleID {
			found = &out.Findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected the synthetic k8s rule to fire on the rendered chart; findings = %+v; failed queries: %v",
			out.Findings, out.FailedQueries)
	}
	if found.FileName != "chart/templates/deployment.yaml" {
		t.Errorf("finding fileName = %q, want chart/templates/deployment.yaml", found.FileName)
	}
	if found.Line <= 0 {
		t.Errorf("finding line = %d, want a line mapped back to the template", found.Line)
	}
	if len(out.MissingFiles) != 0 {
		t.Errorf("expected no missing files for a fully pushed chart, got %v", out.MissingFiles)
	}
}

// chartTgzBytes packages files (name → content) as a gzipped tar chart
// archive, the shape `helm package` produces: each entry is named under a
// single leading directory that helm's archive loader strips.
func chartTgzBytes(t *testing.T, leading string, files [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: leading + "/" + f[0],
			Mode: 0o644,
			Size: int64(len(f[1])),
		}); err != nil {
			t.Fatalf("writing tar header: %v", err)
		}
		if _, err := tw.Write([]byte(f[1])); err != nil {
			t.Fatalf("writing tar entry: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
	return buf.Bytes()
}

// TestAnalyze_ContentPush_PackagedSubchart verifies that a binary chart
// dependency pushed base64-encoded (charts/*.tgz, which cannot ride the wire
// as text) is decoded, assembled and rendered: the subchart's template yields
// a finding anchored on its path inside the pushed chart.
func TestAnalyze_ContentPush_PackagedSubchart(t *testing.T) {
	s := newParallelTestServer(t)

	subchart := chartTgzBytes(t, "sub", [][2]string{
		{"Chart.yaml", "apiVersion: v2\nname: sub\nversion: 0.1.0\n"},
		{"templates/service.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n  labels:\n    app: sub\n"},
	})

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "chart/Chart.yaml", Content: "apiVersion: v2\nname: e2e\nversion: 0.1.0\n"},
			{Path: "chart/values.yaml", Content: "replicas: 1\n"},
			{Path: "chart/charts/sub.tgz", Content: base64.StdEncoding.EncodeToString(subchart), Encoding: "base64"},
		},
		Ruleset:  ruleset(syntheticK8sRule()),
		Platform: []string{"kubernetes"},
	}

	out, _ := postAnalyzeK8s(t, s, req)

	var found bool
	for _, f := range out.Findings {
		if f.QueryID == syntheticK8sRuleID && f.FileName == "chart/charts/sub/templates/service.yaml" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a finding on the packaged subchart's template; findings = %+v; failed queries: %v",
			out.Findings, out.FailedQueries)
	}
	if got := out.ArchiveFiles["chart/charts/sub/templates/service.yaml"]; got != "chart/charts/sub.tgz" {
		t.Errorf("archive_files = %v, want the subchart template mapped to chart/charts/sub.tgz", out.ArchiveFiles)
	}
	if len(out.MissingFiles) != 0 {
		t.Errorf("expected no missing files, got %v", out.MissingFiles)
	}
}

// TestAnalyze_ContentPush_PackagedSubchartVersionedArchive pins that the
// archive is found by the chart name it declares, not by its file name.
func TestAnalyze_ContentPush_PackagedSubchartVersionedArchive(t *testing.T) {
	s := newParallelTestServer(t)

	subchart := chartTgzBytes(t, "nginx", [][2]string{
		{"Chart.yaml", "apiVersion: v2\nname: nginx\nversion: 1.2.3\n"},
		{"templates/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n  labels:\n    app: nginx\n"},
	})

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "chart/Chart.yaml", Content: "apiVersion: v2\nname: e2e\nversion: 0.1.0\n"},
			{Path: "chart/charts/nginx-1.2.3.tgz", Content: base64.StdEncoding.EncodeToString(subchart), Encoding: "base64"},
		},
		Ruleset:  ruleset(syntheticK8sRule()),
		Platform: []string{"kubernetes"},
	}

	out, _ := postAnalyzeK8s(t, s, req)

	if got := out.ArchiveFiles["chart/charts/nginx/templates/deployment.yaml"]; got != "chart/charts/nginx-1.2.3.tgz" {
		t.Errorf("archive_files = %v, want the template mapped to chart/charts/nginx-1.2.3.tgz; findings = %+v",
			out.ArchiveFiles, out.Findings)
	}
}

// TestAnalyze_ContentPush_RootChartKeepsOtherFiles pins that a chart at the
// workspace root withholds only its Helm files from the parsers: Terraform
// beside it is still scanned, and so is a standalone chart elsewhere in the tree
// (Helm only loads subcharts from charts/).
func TestAnalyze_ContentPush_RootChartKeepsOtherFiles(t *testing.T) {
	s := newParallelTestServer(t)

	deployment := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n  labels:\n    app: e2e\n"
	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "Chart.yaml", Content: "apiVersion: v2\nname: root\nversion: 0.1.0\n"},
			{Path: "templates/deployment.yaml", Content: deployment},
			{Path: "infra/main.tf", Content: "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"b\"\n}\n"},
			{Path: "deploy/app/Chart.yaml", Content: "apiVersion: v2\nname: app\nversion: 0.1.0\n"},
			{Path: "deploy/app/templates/deployment.yaml", Content: deployment},
		},
		Ruleset:   ruleset(syntheticRule(), syntheticK8sRule()),
		Libraries: append(testLibraries(true), k8sTestLibraries()[1]),
		Platform:  []string{"terraform", "kubernetes"},
	}

	out, _ := postAnalyze(t, s, req)

	want := map[string]string{
		"infra/main.tf":                        syntheticRuleID,
		"templates/deployment.yaml":            syntheticK8sRuleID,
		"deploy/app/templates/deployment.yaml": syntheticK8sRuleID,
	}
	for _, f := range out.Findings {
		if want[f.FileName] == f.QueryID {
			delete(want, f.FileName)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing findings for %v; findings = %+v; failed queries: %v", want, out.Findings, out.FailedQueries)
	}
}

// TestValidateAnalyzeRequest_Encoding pins the base64 wire contract: only
// text and base64 are accepted, and malformed base64 is rejected up front with
// the offending path.
func TestValidateAnalyzeRequest_Encoding(t *testing.T) {
	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "a.tf", Content: "x"},
			{Path: "b.tgz", Content: "not base64!!", Encoding: "base64"},
		},
		Ruleset: ruleset(datadog.Rule{ID: "tf-rule", Name: "tf-rule", Platform: "Terraform", RegoQuery: []byte("package datadog")}),
		Libraries: []datadog.Library{
			{ID: "common", RegoCode: "package generic.common"},
			{ID: "terraform", RegoCode: "package generic.terraform"},
		},
	}
	err := validateAnalyzeRequest(&req, 10)
	if err == nil || !strings.Contains(err.Error(), "b.tgz") {
		t.Fatalf("expected malformed base64 to be rejected with the file path, got %v", err)
	}

	req.Files[1].Content = base64.StdEncoding.EncodeToString([]byte("gzip bytes"))
	if err := validateAnalyzeRequest(&req, 10); err != nil {
		t.Fatalf("valid base64 should pass validation: %v", err)
	}

	req.Files[1].Encoding = "rot13"
	if err := validateAnalyzeRequest(&req, 10); err == nil || !strings.Contains(err.Error(), "rot13") {
		t.Fatalf("expected an unknown encoding to be rejected, got %v", err)
	}
}

// TestAnalyze_HelmChartRenderFailureEscalates verifies that a chart that
// cannot render from the pushed content (here: a template including a helper
// whose _helpers.tpl was never pushed) escalates its directory in missing_files
// so the IDE pushes the rest of the chart.
func TestAnalyze_HelmChartRenderFailureEscalates(t *testing.T) {
	s := newParallelTestServer(t)

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "chart/Chart.yaml", Content: "apiVersion: v2\nname: e2e\nversion: 0.1.0\n"},
			{Path: "chart/templates/deployment.yaml", Content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
  labels:
    {{- include "e2e.labels" . | nindent 4 }}
`},
		},
		Ruleset:  ruleset(syntheticK8sRule()),
		Platform: []string{"kubernetes"},
	}

	out, _ := postAnalyzeK8s(t, s, req)

	found := false
	for _, p := range out.MissingFiles {
		if p == "chart" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing files = %v, want the chart directory escalated", out.MissingFiles)
	}
}

func TestAnalyze_HelmChartRenderFailureEscalatesWorkspaceRoot(t *testing.T) {
	s := newParallelTestServer(t)

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "Chart.yaml", Content: "apiVersion: v2\nname: e2e\nversion: 0.1.0\n"},
			{Path: "templates/deployment.yaml", Content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
  labels:
    {{- include "e2e.labels" . | nindent 4 }}
`},
		},
		Ruleset:  ruleset(syntheticK8sRule()),
		Platform: []string{"kubernetes"},
	}

	out, _ := postAnalyzeK8s(t, s, req)

	found := false
	for _, p := range out.MissingFiles {
		if p == "." {
			found = true
		}
	}
	if !found {
		t.Errorf("missing files = %v, want the workspace-root chart escalated as %q", out.MissingFiles, ".")
	}
}

// TestAnalyze_ContentPush_ParallelDispatchFinding runs the terraform
// content-push case through the shared memory dispatch (parallel parsing on,
// the serve binary's default) to pin that the dispatch path behaves like the
// per-service one for plain files.
func TestAnalyze_ContentPush_ParallelDispatchFinding(t *testing.T) {
	s := newParallelTestServer(t)

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: `resource "aws_s3_bucket" "b" {
  bucket = var.bucket_name
}`},
			{Path: "infra/variables.tf", Content: `variable "bucket_name" { default = "my-bucket" }`},
		},
		Ruleset:  ruleset(syntheticRule()),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

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
		t.Errorf("expected the synthetic rule to fire through the shared dispatch; findings = %+v; failed queries: %v",
			out.Findings, out.FailedQueries)
	}
	if len(out.MissingFiles) != 0 {
		t.Errorf("expected no missing files, got %v", out.MissingFiles)
	}
}

// TestAnalyze_MissingModuleEscalation verifies a Terraform module pointing at a
// directory that was not pushed is reported in missing_files as a clean
// workspace-relative path (the hybrid escalation signal).
//
// Relative in, relative out: this pins how the pushed paths' own shape is
// preserved, not a global "missing_files are never absolute" invariant. Push
// absolute paths and missing_files come back absolute — see
// TestAnalyze_AbsolutePathMissingModuleEscalation.
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
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var sawModule bool
	for _, m := range out.MissingFiles {
		if m == "modules/networking" {
			sawModule = true
		}
		if filepath.IsAbs(m) {
			t.Errorf("relative input should produce relative missing paths, got absolute: %q", m)
		}
	}
	if !sawModule {
		t.Errorf("expected modules/networking in missing_files, got %v", out.MissingFiles)
	}
}

// TestAnalyze_MissingFilesCWDIndependent proves missing_files derived from
// relative input stay workspace-relative regardless of the server process's
// working directory. A single server serves many IDE workspaces/windows, so the
// result must not depend on where the binary was launched. CWD-independence is
// the property this pins; the relative shape just follows the input's.
func TestAnalyze_MissingFilesCWDIndependent(t *testing.T) {
	analyzeProcessCwdMu.Lock()
	t.Cleanup(analyzeProcessCwdMu.Unlock)

	s := newTestServer(t)
	rule := syntheticRule()
	req := analyzeRequest{
		Files: []analyzeFile{{Path: "infra/main.tf", Content: `module "net" {
  source = "../modules/networking"
}
resource "aws_s3_bucket" "b" { bucket = "x" }`}},
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	}

	// Move CWD somewhere unrelated to the (virtual) workspace.
	t.Chdir(t.TempDir())

	out, _ := postAnalyze(t, s, req)
	if len(out.MissingFiles) != 1 || out.MissingFiles[0] != "modules/networking" {
		t.Errorf("missing_files = %v, want [modules/networking] (workspace-relative, CWD-independent)", out.MissingFiles)
	}
}

// TestAnalyze_ContentPush_AbsolutePathFinding is the absolute-path twin of
// TestAnalyze_ContentPush_TerraformFinding: a file outside every IDE workspace
// folder is pushed under its absolute path, and must scan exactly like a
// workspace-relative one.
//
// The FileName assertion is a cross-process contract. The extension keeps only
// the findings whose fileName equals the path it pushed (an exact string
// compare), so an echo that differs by so much as a separator silently drops
// every finding for the file and it renders as clean. The contract is equality
// after MemFS normalization (filepath.Clean + ToSlash), not byte identity: the
// paths used here are already normalized, which is what the IDE sends (VS Code's
// uri.path is always forward-slash, even on Windows).
func TestAnalyze_ContentPush_AbsolutePathFinding(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()

	const target = "/tmp/ws/main.tf"
	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: target, Content: `resource "aws_s3_bucket" "b" {
  bucket = var.bucket_name
}`},
			{Path: "/tmp/ws/variables.tf", Content: `variable "bucket_name" { default = "my-bucket" }`},
		},
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var found bool
	for _, f := range out.Findings {
		if f.QueryID == syntheticRuleID {
			found = true
			if f.FileName != target {
				t.Errorf("finding fileName = %q, want %q echoed back unchanged", f.FileName, target)
			}
		}
	}
	if !found {
		t.Errorf("expected the synthetic rule to fire on an absolute path; findings = %+v, failed queries: %v",
			out.Findings, out.FailedQueries)
	}
	// Sibling resolution works off the absolute directory too.
	if len(out.MissingFiles) != 0 {
		t.Errorf("expected no missing files for same-dir siblings, got %v", out.MissingFiles)
	}
}

// TestAnalyze_AbsolutePathMissingModuleEscalation pins the other half of the
// echo contract: missing_files keeps the shape of the paths that were pushed, so
// absolute input escalates as absolute paths. The IDE resolves these against a
// workspace folder, and there is none for an out-of-workspace file, so it
// declines to escalate and the analysis stays best-effort — findings on the file
// itself, no cross-directory module enrichment.
func TestAnalyze_AbsolutePathMissingModuleEscalation(t *testing.T) {
	s := newTestServer(t)

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "/tmp/ws/infra/main.tf", Content: `module "net" {
  source = "../modules/networking"
}
resource "aws_s3_bucket" "b" { bucket = "x" }`},
		},
		Ruleset:  ruleset(syntheticRule()),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var sawModule bool
	for _, m := range out.MissingFiles {
		if m == "/tmp/ws/modules/networking" {
			sawModule = true
		}
	}
	if !sawModule {
		t.Errorf("expected /tmp/ws/modules/networking in missing_files, got %v", out.MissingFiles)
	}
}

// TestAnalyze_MixedAbsoluteAndRelativePaths pins mixing as defined rather than
// accidental. The extension cannot produce such a request — a path's shape
// follows its directory, and every file in a request comes from one directory —
// but validation is per-path, so mixing is what the server does by default, and
// other API clients are not bound by the extension's fileset construction.
// Rejecting it would mean one odd path failing the whole request, which is the
// failure mode dropping the absolute-path check exists to remove.
func TestAnalyze_MixedAbsoluteAndRelativePaths(t *testing.T) {
	s := newTestServer(t)
	body := `resource "aws_s3_bucket" "b" { bucket = "x" }`

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "/tmp/ws/absolute.tf", Content: body},
			{Path: "infra/relative.tf", Content: body},
		},
		Ruleset:   ruleset(syntheticRule()),
		Libraries: testLibraries(true),
		Platform:  []string{"terraform"},
	}
	if err := validateAnalyzeRequest(&req, defaultMaxFiles); err != nil {
		t.Fatalf("validateAnalyzeRequest() error = %v, want a mixed request to be accepted", err)
	}

	out, _ := postAnalyze(t, s, req)

	got := make(map[string]bool, len(out.Findings))
	for _, f := range out.Findings {
		if f.QueryID == syntheticRuleID {
			got[f.FileName] = true
		}
	}
	for _, want := range []string{"/tmp/ws/absolute.tf", "infra/relative.tf"} {
		if !got[want] {
			t.Errorf("expected a finding for %q, got findings for %v", want, got)
		}
	}
}

// syntheticBucketRule matches only an aws_s3_bucket whose bucket attribute
// resolved to a concrete value, so it can only fire on an instantiated module
// resource: the module body holds the unresolved `var.name` reference, and the
// call-site file has no resource at all.
const syntheticBucketRuleID = "test-terraform-resolved-bucket-value"

func syntheticBucketRule(wantBucket string) datadog.Rule {
	return datadog.Rule{
		ID:               syntheticBucketRuleID,
		Name:             syntheticBucketRuleID,
		ShortDescription: "Synthetic resolved bucket value",
		Platform:         "Terraform",
		Severity:         "INFO",
		Category:         "Test",
		IsPublished:      true,
		RegoQuery: []byte(`package datadog

import rego.v1

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

DatadogPolicy contains result if {
	common_lib.library_enabled
	resource := input.document[i].resource["aws_s3_bucket"][name]
	resource.bucket == "` + wantBucket + `"
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": tf_lib.display_name("aws_s3_bucket", name),
		"searchKey": sprintf("aws_s3_bucket[%s].bucket", [name]),
	}
}`),
	}
}

// moduleCallerFixture is a root module calling a sibling module whose resource
// derives its bucket from the call site's `name` input.
const (
	moduleCallerMainTF = `module "net" {
  source = "../modules/networking"
  name   = %s
}
`
	moduleChildMainTF = `variable "name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.name
}
`
)

// TestAnalyze_LocalModuleInstantiation proves the full content-push module
// path: the module tree is evaluated against the request's in-memory FS, the
// caller's input binds into the module resource, and the instantiated document
// is attributed to the module's defining file. Everything being pushed, no
// missing files are reported.
func TestAnalyze_LocalModuleInstantiation(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticBucketRule("resolved-bucket-name")

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: fmt.Sprintf(moduleCallerMainTF, "\"resolved-bucket-name\"")},
			{Path: "modules/networking/main.tf", Content: moduleChildMainTF},
		},
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var sawResolved bool
	for _, f := range out.Findings {
		if f.QueryID != syntheticBucketRuleID {
			continue
		}
		sawResolved = true
		if f.FileName != "modules/networking/main.tf" {
			t.Errorf("finding fileName = %q, want modules/networking/main.tf (the defining file)", f.FileName)
		}
		// The finding anchors on the call-site declaration (the SARIF report's
		// convention); fileName keeps the defining file so code_location stays
		// meaningful.
		attr := f.ModuleAttribution
		if attr == nil {
			t.Errorf("expected moduleAttribution on the instantiated finding")
			continue
		}
		if attr.CallSite.Filename != "infra/main.tf" {
			t.Errorf("call_site filename = %q, want infra/main.tf", attr.CallSite.Filename)
		}
		if attr.CallSite.LineStart != 1 || attr.CallSite.LineEnd != 4 {
			t.Errorf("call_site lines = %d-%d, want the module block 1-4",
				attr.CallSite.LineStart, attr.CallSite.LineEnd)
		}
		if attr.ModuleCodeLocation.Filename != "main.tf" {
			t.Errorf("code_location filename = %q, want module-relative main.tf", attr.ModuleCodeLocation.Filename)
		}
		// Workspace-relative, like the CLI's repo-relative shape — not the
		// basename the no-repo-root path would otherwise collapse to.
		if attr.Source != "modules/networking" {
			t.Errorf("source = %q, want modules/networking", attr.Source)
		}
	}
	if !sawResolved {
		t.Errorf("expected an instantiated finding with the resolved bucket value; findings = %+v; failed queries: %v",
			out.Findings, out.FailedQueries)
	}
	if len(out.MissingFiles) != 0 {
		t.Errorf("expected no missing files for a fully pushed module tree, got %v", out.MissingFiles)
	}
}

// TestAnalyze_LocalModuleRootVariableBinding chains three resolution steps
// through the in-memory FS: the root's variable default (pushed variables.tf),
// the module call-site input, and the module resource attribute. Only the
// instantiated document carries the final concrete value, so a finding proves
// all three ran.
func TestAnalyze_LocalModuleRootVariableBinding(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticBucketRule("root-default-bucket")

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: fmt.Sprintf(moduleCallerMainTF, "var.bucket_name")},
			{Path: "infra/variables.tf", Content: `variable "bucket_name" {
  type    = string
  default = "root-default-bucket"
}
`},
			{Path: "modules/networking/main.tf", Content: moduleChildMainTF},
		},
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var sawResolved bool
	for _, f := range out.Findings {
		if f.QueryID == syntheticBucketRuleID {
			sawResolved = true
		}
	}
	if !sawResolved {
		t.Errorf("expected the root variable default to bind into the module input; findings = %+v; failed queries: %v",
			out.Findings, out.FailedQueries)
	}
	if len(out.MissingFiles) != 0 {
		t.Errorf("expected no missing files, got %v", out.MissingFiles)
	}
}

// TestAnalyze_LocalModuleTfvarsOverrideBinding proves the root-module inputs
// come from the pushed terraform.tfvars (read through the in-memory FS by
// LoadRootVars), overriding the declared variable default.
func TestAnalyze_LocalModuleTfvarsOverrideBinding(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticBucketRule("tfvars-bucket")

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: fmt.Sprintf(moduleCallerMainTF, "var.bucket_name")},
			{Path: "infra/variables.tf", Content: `variable "bucket_name" {
  type    = string
  default = "root-default-bucket"
}
`},
			{Path: "infra/terraform.tfvars", Content: `bucket_name = "tfvars-bucket"
`},
			{Path: "modules/networking/main.tf", Content: moduleChildMainTF},
		},
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var sawOverride bool
	for _, f := range out.Findings {
		if f.QueryID == syntheticBucketRuleID {
			sawOverride = true
		}
	}
	if !sawOverride {
		t.Errorf("expected the tfvars value to override the default and bind into the module input; "+
			"findings = %+v; failed queries: %v", out.Findings, out.FailedQueries)
	}
}

// TestAnalyze_LocalModuleAbsentTfvarsNotReported pins the speculative tfvars
// probe: LoadRootVars always tries terraform.tfvars, and MemFS records ReadFile
// misses but not Stat misses, so an absent terraform.tfvars (the common case)
// must not surface as a missing file.
func TestAnalyze_LocalModuleAbsentTfvarsNotReported(t *testing.T) {
	s := newTestServer(t)

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: fmt.Sprintf(moduleCallerMainTF, "\"resolved-bucket-name\"")},
			{Path: "modules/networking/main.tf", Content: moduleChildMainTF},
		},
		Ruleset:  ruleset(syntheticRule()),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	for _, m := range out.MissingFiles {
		if strings.HasSuffix(m, "terraform.tfvars") {
			t.Errorf("absent terraform.tfvars must not be reported missing (speculative probe), got %q", m)
		}
	}
}

// TestAnalyze_LocalModuleAbsolutePathShape pins module attribution for a
// file pushed as an absolute path (outside every workspace folder): every path
// the response echoes keeps the pushed shape — the call site stays absolute
// rather than collapsing to a basename, the same convention missing_files
// follow (TestAnalyze_AbsolutePathMissingModuleEscalation).
func TestAnalyze_LocalModuleAbsolutePathShape(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticBucketRule("resolved-bucket-name")

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "/tmp/ws/infra/main.tf", Content: fmt.Sprintf(moduleCallerMainTF, "\"resolved-bucket-name\"")},
			{Path: "/tmp/ws/modules/networking/main.tf", Content: moduleChildMainTF},
		},
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	}

	out, _ := postAnalyze(t, s, req)

	var sawCallSite bool
	for _, f := range out.Findings {
		if f.QueryID != syntheticBucketRuleID || f.ModuleAttribution == nil {
			continue
		}
		sawCallSite = true
		if got := f.ModuleAttribution.CallSite.Filename; got != "/tmp/ws/infra/main.tf" {
			t.Errorf("call_site filename = %q, want the pushed absolute shape /tmp/ws/infra/main.tf", got)
		}
		if got := f.FileName; got != "/tmp/ws/modules/networking/main.tf" {
			t.Errorf("fileName = %q, want the pushed absolute shape /tmp/ws/modules/networking/main.tf", got)
		}
	}
	if !sawCallSite {
		t.Errorf("expected an instantiated finding carrying call-site attribution; findings = %+v; failed queries: %v",
			out.Findings, out.FailedQueries)
	}
}

// TestServerFlagEvaluator pins the flags server mode depends on. The
// local-module-eval pin is on: tfeval reads module and tfvars files through the
// request's in-memory FS, so evaluation can only see pushed content and an
// unpushed module directory is reported as a missing file for escalation,
// never read off the real disk. Helm is on too: the chart loader reads from
// the same in-memory FS, and a chart that fails to render escalates its
// directory.
func TestServerFlagEvaluator(t *testing.T) {
	evaluator := serverFlagEvaluator(false)

	if !evaluator.EvaluateWithOrg(featureflags.IacEnableKicsHelmResolver) {
		t.Error("IacEnableKicsHelmResolver must be pinned true in server mode: " +
			"the chart loader reads pushed content through the in-memory FS")
	}
	// Each flag is read through the same method its production call site uses,
	// so this keeps holding if server mode ever gets an evaluator whose methods
	// do not all resolve to the same value.
	if evaluator.EvaluateWithOrgAndEnv(featureflags.IaCEnableKicsParallelFileParsing) {
		t.Error("parallel file parsing should be off unless the server opts in")
	}
	if !serverFlagEvaluator(true).EvaluateWithOrgAndEnv(featureflags.IaCEnableKicsParallelFileParsing) {
		t.Error("parallel file parsing should follow the server's --x-parallelparsing setting")
	}
}

// TestValidateFilePath specifies the accepted path shapes directly, without a
// scan or an HTTP round trip.
func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{name: "workspace-relative", path: "infra/main.tf"},
		{name: "bare file name", path: "main.tf"},
		{name: "dot-relative", path: "./infra/main.tf"},
		// Absolute paths are what an out-of-workspace file looks like.
		{name: "posix absolute", path: "/tmp/ws/main.tf"},
		{name: "windows drive qualified", path: "C:/ws/main.tf"},
		{name: "vscode windows uri path", path: "/c:/ws/main.tf"},
		// Clean collapses interior "..", so these stay inside their own root.
		{name: "absolute with interior dotdot", path: "/tmp/ws/../ws/main.tf"},
		{name: "relative with interior dotdot", path: "infra/../infra/main.tf"},
		// Escaping a relative root is still refused.
		{name: "dotdot", path: "..", wantError: true},
		{name: "leading dotdot", path: "../escape.tf", wantError: true},
		{name: "dotdot after cleaning", path: "infra/../../escape.tf", wantError: true},
		{name: "empty", path: "", wantError: true},
		{name: "NUL byte", path: "infra/ma\x00in.tf", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)
			if tt.wantError && err == nil {
				t.Fatalf("validateFilePath(%q) = nil, want an error", tt.path)
			}
			if !tt.wantError && err != nil {
				t.Fatalf("validateFilePath(%q) = %v, want nil", tt.path, err)
			}
		})
	}
}

// TestAnalyze_Validation exercises the request validation rules.
func TestAnalyze_Validation(t *testing.T) {
	s := New(&Config{})
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	validRule := datadog.Rule{ID: "test-rule", Name: "test-rule", Platform: "Terraform", RegoQuery: []byte("package datadog")}
	validLibraries := []datadog.Library{
		{ID: "common", RegoCode: "package generic.common"},
		{ID: "terraform", RegoCode: "package generic.terraform"},
	}
	cases := []struct {
		name string
		req  analyzeRequest
		body string // used only for malformed input
		want int
	}{
		{
			name: "empty files",
			req:  analyzeRequest{Ruleset: ruleset(validRule), Libraries: validLibraries},
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
				Files:   []analyzeFile{{Path: "../escape.tf", Content: "x"}},
				Ruleset: ruleset(validRule), Libraries: validLibraries,
			},
			want: http.StatusBadRequest,
		},
		{
			// An absolute path is accepted: the IDE pushes one for a file that
			// lives outside every workspace folder. Uses a .tf path so the case
			// exercises a real scan rather than whatever an extensionless file
			// happens to do.
			name: "absolute path",
			req: analyzeRequest{
				Files:   []analyzeFile{{Path: "/tmp/ws/main.tf", Content: `resource "aws_s3_bucket" "b" { bucket = "x" }`}},
				Ruleset: ruleset(validRule), Libraries: validLibraries,
			},
			want: http.StatusOK,
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
		Files:   []analyzeFile{{Path: "main.tf", Content: "resource"}},
		Ruleset: ruleset(datadog.Rule{ID: "rule", Name: "rule", Platform: "Terraform", RegoQuery: []byte("package datadog")}),
	}
	tooManyLibraries := make([]datadog.Library, maxLibraries+1)
	tests := []struct {
		name      string
		libraries []datadog.Library
		wantError string
	}{
		{name: "missing", wantError: "at least one library is required"},
		{name: "too many", libraries: tooManyLibraries, wantError: "too many libraries"},
		{
			name:      "empty id",
			libraries: []datadog.Library{{RegoCode: "package generic.common"}},
			wantError: "empty library id",
		},
		{
			name:      "empty content",
			libraries: []datadog.Library{{ID: "common", RegoCode: " "}},
			wantError: "empty library content for common",
		},
		{
			name: "missing common",
			libraries: []datadog.Library{
				{ID: "terraform", RegoCode: "package generic.terraform"},
			},
			wantError: "common library is required",
		},
		{
			name: "missing platform",
			libraries: []datadog.Library{
				{ID: "common", RegoCode: "package generic.common"},
			},
			wantError: "library is required for rule platform: Terraform",
		},
		{
			name: "invalid input data",
			libraries: []datadog.Library{
				{ID: "common", RegoCode: "package generic.common", InputData: "{"},
				{ID: "terraform", RegoCode: "package generic.terraform"},
			},
			wantError: "invalid library input data for common",
		},
		{
			name: "non-object input data",
			libraries: []datadog.Library{
				{ID: "common", RegoCode: "package generic.common", InputData: "null"},
				{ID: "terraform", RegoCode: "package generic.terraform"},
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

func TestValidateAnalyzeRequest_RuleBoundaries(t *testing.T) {
	validRequest := func() analyzeRequest {
		return analyzeRequest{
			Files:     []analyzeFile{{Path: "main.tf", Content: "resource"}},
			Ruleset:   ruleset(datadog.Rule{ID: "test-rule", Name: "test-rule", Platform: "Terraform", RegoQuery: []byte("package datadog")}),
			Libraries: testLibraries(true),
		}
	}

	t.Run("too many rules", func(t *testing.T) {
		req := validRequest()
		req.Ruleset.Rules = make([]*datadog.Rule, maxRules+1)
		err := validateAnalyzeRequest(&req, defaultMaxFiles)
		if err == nil || err.Error() != "too many rules" {
			t.Fatalf("validateAnalyzeRequest() error = %v", err)
		}
	})

	t.Run("empty rule platform", func(t *testing.T) {
		req := validRequest()
		req.Ruleset.Rules[0].Platform = " "
		err := validateAnalyzeRequest(&req, defaultMaxFiles)
		if err == nil || err.Error() != "empty platform for rule test-rule" {
			t.Fatalf("validateAnalyzeRequest() error = %v", err)
		}
	})
}

// TestValidateAnalyzeRequest_LibraryIDNormalization verifies library ids match
// case-insensitively and that keys collapsing to the same normalized value
// ("cloudFormation"/"cloudformation") are not rejected as duplicates.
func TestValidateAnalyzeRequest_LibraryIDNormalization(t *testing.T) {
	req := analyzeRequest{
		Files:   []analyzeFile{{Path: "main.tf", Content: "resource"}},
		Ruleset: ruleset(datadog.Rule{ID: "cfn-rule", Name: "cfn-rule", Platform: "CloudFormation", RegoQuery: []byte("package datadog")}),
		Libraries: []datadog.Library{
			{ID: "Common", RegoCode: "package generic.common"},
			{ID: "cloudFormation", RegoCode: "package generic.cloudformation"},
			{ID: "cloudformation", RegoCode: "package generic.cloudformation"},
		},
	}
	if err := validateAnalyzeRequest(&req, defaultMaxFiles); err != nil {
		t.Fatalf("validateAnalyzeRequest() error = %v, want nil", err)
	}
}

func TestAnalyze_NormalizesRuleAndScanPlatforms(t *testing.T) {
	s := newTestServer(t)
	rule := syntheticRule()
	rule.Platform = " Terraform "
	rule.RegoQuery = []byte(`package datadog

import rego.v1

DatadogPolicy contains result if {
	result := {
		"documentId": input.document[0].id,
		"resourceType": "test_widget",
		"resourceName": "example",
		"searchKey": "resource",
	}
}`)
	req := analyzeRequest{
		Files: []analyzeFile{{
			Path:    "infra/main.tf",
			Content: `resource "test_widget" "example" {}`,
		}},
		Ruleset:   ruleset(rule),
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

func TestRequestQuerySource_MissingLibrary(t *testing.T) {
	source := &requestQuerySource{libraries: map[string]engineSource.RegoLibraries{
		"common": {},
	}}
	_, err := source.GetQueryLibrary(t.Context(), "terraform")
	if err == nil || err.Error() != "library not found in request: terraform" {
		t.Fatalf("GetQueryLibrary() error = %v", err)
	}
}

func TestAnalyze_MissingPlatformLibraryReportedAsFailedQuery(t *testing.T) {
	s := newTestServer(t)
	req := analyzeRequest{
		Files: []analyzeFile{{
			Path:    "infra/main.tf",
			Content: `resource "test_widget" "example" {}`,
		}},
		Ruleset: ruleset(syntheticRule()),
		Libraries: []datadog.Library{
			{ID: "common", RegoCode: "package generic.common\nimport rego.v1"},
		},
		Platform: []string{"terraform"},
	}

	out, err := s.analyze(t.Context(), &req)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	failed, ok := out.FailedQueries[syntheticRuleID]
	if !ok || !strings.Contains(failed, "failed to get platform library") {
		t.Fatalf("failed queries = %v", out.FailedQueries)
	}
}

func TestAnalyze_RequestLibrariesInvalidateSharedRuleCache(t *testing.T) {
	analyzeCompiledQueryCacheTestMu.Lock()
	t.Cleanup(analyzeCompiledQueryCacheTestMu.Unlock)

	engine.ResetCompiledQueryCachesForTest()
	t.Cleanup(engine.ResetCompiledQueryCachesForTest)

	s := New(&Config{UseRulesCache: true, DisableRuleIsolation: true})
	req := analyzeRequest{
		Files: []analyzeFile{{
			Path:    "infra/main.tf",
			Content: `resource "aws_s3_bucket" "b" { bucket = "x" }`,
		}},
		Ruleset:   ruleset(syntheticRule()),
		Libraries: testLibraries(true),
		Platform:  []string{"terraform"},
	}

	enabled, _ := postAnalyze(t, s, req)
	if len(enabled.Findings) == 0 {
		t.Fatalf("expected a finding when pushed library input enables the rule; failed queries: %v", enabled.FailedQueries)
	}

	req.Libraries = testLibraries(false)
	disabled, _ := postAnalyze(t, s, req)
	if len(disabled.Findings) != 0 {
		t.Fatalf("stale cached rule used old library input; findings: %+v", disabled.Findings)
	}
}

func TestAnalyze_RequestLibrariesDoNotCallBackend(t *testing.T) {
	analyzeCompiledQueryCacheTestMu.Lock()
	t.Cleanup(analyzeCompiledQueryCacheTestMu.Unlock)

	engine.ResetCompiledQueryCachesForTest()
	t.Cleanup(engine.ResetCompiledQueryCachesForTest)

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
		Ruleset:   ruleset(syntheticRule()),
		Libraries: testLibraries(true),
		Platform:  []string{"terraform"},
	})
	if len(out.Findings) == 0 {
		t.Fatalf("expected request-supplied rules and libraries to produce a finding; failed queries: %v", out.FailedQueries)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server mode made %d outbound HTTP requests, want 0", got)
	}
}

func TestAnalyze_LogsFailedQueryCount(t *testing.T) {
	s := newTestServer(t)
	req := analyzeRequest{
		Files: []analyzeFile{{
			Path:    "infra/main.tf",
			Content: `resource "test_widget" "example" {}`,
		}},
		Ruleset: ruleset(syntheticRule()),
		Libraries: []datadog.Library{
			{ID: "common", RegoCode: "package generic.common\nimport rego.v1"},
		},
		Platform: []string{"terraform"},
	}

	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())
	out, err := s.analyze(ctx, &req)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(out.FailedQueries) != 1 {
		t.Fatalf("failed queries = %v, want one", out.FailedQueries)
	}
	if !strings.Contains(logs.String(), `"level":"warn"`) ||
		!strings.Contains(logs.String(), `"failed_query_count":1`) {
		t.Fatalf("missing failed-query warning in logs: %s", logs.String())
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
	rules := make([]datadog.Rule, 0, 8)
	for i := range 8 {
		r := rule
		r.ID = fmt.Sprintf("%s-%d", rule.ID, i)
		r.Name = r.ID
		rules = append(rules, r)
	}
	req := analyzeRequest{
		Files: files, Ruleset: ruleset(rules...), Libraries: testLibraries(true), Platform: []string{"terraform"},
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
		Ruleset:  ruleset(rule),
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
		Ruleset:  ruleset(rule),
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
		Ruleset:  ruleset(rule),
		Platform: []string{"terraform"},
	})
	if len(base.Findings) == 0 {
		t.Fatalf("baseline expected findings, got none")
	}

	// With ignore-paths covering infra/, the file is skipped → no findings.
	out, _ := postAnalyze(t, s, analyzeRequest{
		Files:    []analyzeFile{{Path: "infra/main.tf", Content: body}},
		Ruleset:  ruleset(rule),
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
		Ruleset:  ruleset(rule),
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
		Ruleset:  ruleset(rule),
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
