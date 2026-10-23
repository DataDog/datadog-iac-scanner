/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2025 Datadog, Inc.
 */
package kustomize

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/types"
)

func TestPlainLocalPath(t *testing.T) {
	allowed := []string{
		"deployment.yaml",
		"./deployment.yaml",
		"../base/deployment.yaml",
		"base/deployment.yaml",
		"key=deployment.yaml",
	}
	refused := []string{
		"",
		".",
		"..",
		"/etc/passwd",
		"C:\\x.yaml",
		"https://example.com/x.yaml",
		"ssh://git@host/org/repo",
		"git@host:org/repo",
		"github.com:org/repo",
		"GitHub.com/org/repo",
		"HTTPS://example.com/x.yaml",
		"git::https://example.com/x.yaml",
		"key=https://example.com/x.yaml",
		"user@example.com:org/repo",
		"..\\base\\x.yaml",
		"a?b=x.yaml",
	}
	for _, p := range allowed {
		if !plainLocalPath(p) {
			t.Errorf("plainLocalPath(%q) = false, want true", p)
		}
	}
	for _, p := range refused {
		if plainLocalPath(p) {
			t.Errorf("plainLocalPath(%q) = true, want false", p)
		}
	}
}

func TestValidateKustomization(t *testing.T) {
	valid := []byte(`resources:
  - deployment.yaml
  - ../base
configMapGenerator:
  - name: cfg
    files:
      - app.properties
`)
	if _, err := validateKustomization(valid); err != nil {
		t.Fatalf("validateKustomization(valid) = %v, want nil", err)
	}
	invalid := map[string]string{
		"remote resource":  "resources:\n  - https://example.com/x.yaml\n",
		"remote patch":     "patches:\n  - path: https://example.com/p.yaml\n",
		"scp resource":     "resources:\n  - git@host:org/repo\n",
		"generators":       "generators:\n  - gen.yaml\n",
		"transformers":     "transformers:\n  - tr.yaml\n",
		"validators":       "validators:\n  - v.yaml\n",
		"helmCharts":       "helmCharts:\n  - name: foo\n",
		"helm generator":   "helmChartInflationGenerator:\n  - name: foo\n",
		"generator remote": "configMapGenerator:\n  - name: cfg\n    envs:\n      - https://x/.env\n",
		"openapi remote":   "openapi:\n  path: https://x/schema.json\n",
	}
	for name, content := range invalid {
		if _, err := validateKustomization([]byte(content)); err == nil {
			t.Errorf("validateKustomization(%s) = nil, want error", name)
		} else if re, ok := err.(*RenderError); !ok || re.Reason != ReasonValidation {
			t.Errorf("validateKustomization(%s) reason = %v, want validation", name, err)
		}
	}
}

func TestKustomizationFieldClassification(t *testing.T) {
	classified := make(map[string]bool)
	for _, list := range [][]string{kustomizationPathFields, kustomizationNoPathFields, kustomizationForbiddenFields} {
		for _, f := range list {
			if classified[f] {
				t.Errorf("field %s classified twice", f)
			}
			classified[f] = true
		}
	}
	typ := reflect.TypeOf(types.Kustomization{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !classified[name] {
			t.Errorf("field %s of types.Kustomization is unclassified; add it to the right list so its paths are validated", name)
		}
	}
}

func TestConstrainedFS_RefusesOutsideConfinement(t *testing.T) {
	outside := t.TempDir()
	root := t.TempDir()
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, outside, DefaultMaxFileBytes, &atomic.Int64{}, &byteCache{files: map[string][]byte{}})
	if err == nil {
		t.Fatal("newConstrainedFS outside root = nil error, want error")
	}
	_ = fs
}

func TestConstrainedFS_RefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "s.yaml"), []byte("x: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", DefaultMaxFileBytes, &atomic.Int64{}, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile(filepath.Join(root, "escape", "s.yaml")); err == nil {
		t.Fatal("ReadFile through symlink escape = nil error, want error")
	} else if re, ok := err.(*RenderError); ok && re.Reason != ReasonValidation && re.Reason != ReasonMissingFile {
		t.Errorf("reason = %s, want validation or missing_file", re.Reason)
	}
}

func TestConstrainedFS_SizeLimitBeforeRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "big.yaml")
	if err := os.WriteFile(path, []byte("x: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	budget := &atomic.Int64{}
	budget.Store(MaxTotalBytes)
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", 2, budget, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile(path); err == nil {
		t.Fatal("ReadFile oversized = nil error, want size limit")
	} else if re, ok := err.(*RenderError); !ok || re.Reason != ReasonSizeLimit {
		t.Errorf("reason = %v, want size_limit", err)
	}
	if got := budget.Load(); got != MaxTotalBytes {
		t.Errorf("budget = %d, want unchanged %d (file refused before reading)", got, MaxTotalBytes)
	}
}

func TestConstrainedFS_CumulativeBudget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.yaml"), []byte("a: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	budget := &atomic.Int64{}
	budget.Store(1)
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", DefaultMaxFileBytes, budget, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile(filepath.Join(root, "a.yaml")); err == nil {
		t.Fatal("ReadFile with exhausted budget = nil error, want size limit")
	}
}

func TestInjectOriginAnnotations(t *testing.T) {
	in := []byte("resources:\n  - deployment.yaml\n")
	out, err := injectOriginAnnotations(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "originAnnotations") {
		t.Error("injected copy missing originAnnotations")
	}
	if strings.Contains(string(in), "originAnnotations") {
		t.Error("injectOriginAnnotations mutated its input")
	}
	with := []byte("buildMetadata:\n  - transformerAnnotations\nresources: []\n")
	out, err = injectOriginAnnotations(with)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "originAnnotations") || !strings.Contains(string(out), "transformerAnnotations") {
		t.Errorf("existing buildMetadata not preserved: %s", out)
	}
}
