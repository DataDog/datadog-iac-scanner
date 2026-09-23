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
	"encoding/base64"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const syntheticK8sRuleID = "test-k8s-deployment-missing-owner"

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

// TestAnalyze_ContentPush_PackagedSubchartAlias pins that a dependency alias
// is the directory the subchart renders under, not the name inside the archive.
func TestAnalyze_ContentPush_PackagedSubchartAlias(t *testing.T) {
	s := newParallelTestServer(t)

	subchart := chartTgzBytes(t, "redis", [][2]string{
		{"Chart.yaml", "apiVersion: v2\nname: redis\nversion: 0.1.0\n"},
		{"templates/service.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n  labels:\n    app: redis\n"},
	})

	req := analyzeRequest{
		Files: []analyzeFile{
			{Path: "chart/Chart.yaml", Content: "apiVersion: v2\nname: e2e\nversion: 0.1.0\ndependencies:\n  - name: redis\n    version: 0.1.0\n    alias: cache\n"},
			{Path: "chart/charts/redis-0.1.0.tgz", Content: base64.StdEncoding.EncodeToString(subchart), Encoding: "base64"},
		},
		Ruleset:  ruleset(syntheticK8sRule()),
		Platform: []string{"kubernetes"},
	}

	out, _ := postAnalyzeK8s(t, s, req)

	if got := out.ArchiveFiles["chart/charts/cache/templates/service.yaml"]; got != "chart/charts/redis-0.1.0.tgz" {
		t.Errorf("archive_files = %v, want the aliased template mapped to chart/charts/redis-0.1.0.tgz; findings = %+v",
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
