package helm

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestDryRunKubeVersionNonNil(t *testing.T) {
	if kv := dryRunKubeVersion(); kv == nil || kv.Version == "" {
		t.Fatal("dryRunKubeVersion() returned empty version")
	}
}

func TestResolveChartKubeVersion(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		wantVer    string
		wantDrop   bool
	}{
		{name: "no constraint uses default", constraint: "", wantVer: "v1.30.0", wantDrop: false},
		{name: "lower bound satisfied by default", constraint: ">= 1.22.0-0", wantVer: "v1.30.0", wantDrop: false},
		{name: "upper bound satisfied by default", constraint: "< 1.31.0", wantVer: "v1.30.0", wantDrop: false},
		{name: "range below default picks closest", constraint: ">= 1.22.0-0, < 1.25.0", wantVer: "v1.24.0", wantDrop: false},
		{name: "upper bound below default", constraint: "< 1.16.0", wantVer: "v1.15.0", wantDrop: false},
		{name: "patch lower-bound within default minor", constraint: ">= 1.30.1, < 1.31.0", wantVer: "v1.30.1", wantDrop: false},
		{name: "tilde patch constraint", constraint: "~1.30.1", wantVer: "v1.30.1", wantDrop: false},
		{name: "patch lower-bound in non-default minor", constraint: ">= 1.25.1, < 1.26.0", wantVer: "v1.25.1", wantDrop: false},
		{name: "high patch number (>= 20)", constraint: ">= 1.18.20, < 1.19.0", wantVer: "v1.18.20", wantDrop: false},
		{name: "out of range drops constraint", constraint: ">= 1.99.0-0", wantVer: "v1.30.0", wantDrop: true},
		{name: "malformed drops constraint", constraint: "not-a-constraint", wantVer: "v1.30.0", wantDrop: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv, drop := resolveChartKubeVersion(tt.constraint)
			if kv.Version != tt.wantVer {
				t.Errorf("version = %q, want %q", kv.Version, tt.wantVer)
			}
			if drop != tt.wantDrop {
				t.Errorf("drop = %v, want %v", drop, tt.wantDrop)
			}
		})
	}
}

// Lower-bound kubeVersion; rendered output must still include the constraint string.
func TestKubeVersionGateChart(t *testing.T) {
	res := &Resolver{}
	resolved, err := res.Resolve(context.Background(), filepath.FromSlash("../../../test/fixtures/test_helm_kube_version_gate"))
	if err != nil {
		t.Fatalf("expected chart with kubeVersion >= 1.22 to render successfully, got error: %v", err)
	}
	if len(resolved.File) == 0 {
		t.Fatal("expected at least one rendered file, got none")
	}
	var rendered string
	for _, f := range resolved.File {
		rendered += string(f.Content)
	}
	if !strings.Contains(rendered, ">= 1.22.0-0") {
		t.Errorf("expected .Chart.KubeVersion to be preserved in rendered output, got:\n%s", rendered)
	}
}

// Unsatisfiable kubeVersion; constraint is dropped so render succeeds.
func TestKubeVersionConstraintBypassed(t *testing.T) {
	res := &Resolver{}
	resolved, err := res.Resolve(context.Background(), filepath.FromSlash("../../../test/fixtures/test_helm_kube_version_incompatible"))
	if err != nil {
		t.Fatalf("expected chart with an incompatible kubeVersion to still render, got error: %v", err)
	}
	if len(resolved.File) == 0 {
		t.Fatal("expected at least one rendered file, got none")
	}
}
