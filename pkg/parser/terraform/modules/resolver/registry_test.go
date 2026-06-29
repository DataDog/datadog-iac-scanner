/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestResolveRegistryVersionInvalidConstraint(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"modules":[{"versions":[{"version":"2.0.0"},{"version":"1.0.0"}]}]}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	_, err := resolveRegistryVersion(
		context.Background(),
		client,
		"https://registry.terraform.io/v1/modules/",
		"terraform-aws-modules",
		"vpc",
		"aws",
		"var.module_version",
	)

	if err == nil || !strings.Contains(err.Error(), "invalid version constraint") {
		t.Fatalf("expected invalid constraint error, got %v", err)
	}
}

func TestResolveRegistryVersionEmptyConstraintUsesHighestSemver(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"modules":[{"versions":[{"version":"1.0.0"},{"version":"2.0.0"},{"version":"bad"}]}]}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	got, err := resolveRegistryVersion(
		context.Background(),
		client,
		"https://registry.terraform.io/v1/modules/",
		"terraform-aws-modules",
		"vpc",
		"aws",
		"",
	)

	if err != nil {
		t.Fatalf("resolveRegistryVersion: %v", err)
	}
	if got != "2.0.0" {
		t.Fatalf("version = %q, want 2.0.0", got)
	}
}

func TestParseRegistrySourceWithSubdir(t *testing.T) {
	host, namespace, name, provider, err := parseRegistrySource("terraform-aws-modules/eks/aws//modules/karpenter")
	if err != nil {
		t.Fatalf("parseRegistrySource: %v", err)
	}
	if host != defaultRegistryHost || namespace != "terraform-aws-modules" || name != "eks" || provider != "aws" {
		t.Fatalf("unexpected source parts: %q %q %q %q", host, namespace, name, provider)
	}
	if got := registrySubdir("terraform-aws-modules/eks/aws//modules/karpenter"); got != "modules/karpenter" {
		t.Fatalf("subdir = %q, want modules/karpenter", got)
	}
}

func TestAppendGetterSubdirPreservesQuery(t *testing.T) {
	got := appendGetterSubdir("git::https://github.com/org/mod.git?ref=v1.0.0", "modules/child")
	want := "git::https://github.com/org/mod.git//modules/child?ref=v1.0.0"
	if got != want {
		t.Fatalf("getter URL = %q, want %q", got, want)
	}
}

func TestPrefetchedResolverUsesVersionedManifestKey(t *testing.T) {
	r := NewPrefetchedResolver(&Manifest{
		Modules: map[string]ManifestEntry{
			"terraform-aws-modules/vpc/aws@1.0.0": {LocalPath: "/cache/v1"},
			"terraform-aws-modules/vpc/aws@2.0.0": {LocalPath: "/cache/v2"},
		},
	})

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "2.0.0",
	})

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != "/cache/v2" {
		t.Fatalf("LocalPath = %q, want /cache/v2", res.LocalPath)
	}
}

func TestDotTerraformResolverDoesNotOverwriteAcrossRoots(t *testing.T) {
	root1 := writeModulesJSON(t, "terraform-aws-modules/vpc/aws", "1.0.0", "v1")
	root2 := writeModulesJSON(t, "terraform-aws-modules/vpc/aws", "2.0.0", "v2")
	r := &DotTerraformResolver{RootDirs: []string{root1, root2}}

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:   "terraform-aws-modules/vpc/aws",
		Version:  "2.0.0",
		FileName: filepath.Join(root2, "main.tf"),
	})

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != filepath.Join(root2, "v2") {
		t.Fatalf("LocalPath = %q, want %q", res.LocalPath, filepath.Join(root2, "v2"))
	}
}

func TestDotTerraformResolverDoesNotFallbackForExternalCallers(t *testing.T) {
	root := writeModulesJSON(t, "terraform-aws-modules/vpc/aws", "", "v1")
	external := t.TempDir()
	r := &DotTerraformResolver{RootDirs: []string{root}}

	_, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:   "terraform-aws-modules/vpc/aws",
		FileName: filepath.Join(external, "main.tf"),
	})

	if err == nil || !strings.Contains(err.Error(), "not found in .terraform/modules") {
		t.Fatalf("expected unresolved external caller, got %v", err)
	}
}

func TestDotTerraformResolverUsesVersionWithinRoot(t *testing.T) {
	root := writeModulesJSONRecords(t, []dotTerraformModuleRecord{
		{Key: "old", Source: "terraform-aws-modules/vpc/aws", Version: "1.0.0", Dir: "v1"},
		{Key: "new", Source: "terraform-aws-modules/vpc/aws", Version: "2.0.0", Dir: "v2"},
	})
	r := &DotTerraformResolver{RootDirs: []string{root}}

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:   "terraform-aws-modules/vpc/aws",
		Version:  "1.0.0",
		FileName: filepath.Join(root, "main.tf"),
	})

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != filepath.Join(root, "v1") {
		t.Fatalf("LocalPath = %q, want %q", res.LocalPath, filepath.Join(root, "v1"))
	}
}

func TestDotTerraformResolverUnpinnedUsesInitializedVersion(t *testing.T) {
	root := writeModulesJSON(t, "terraform-aws-modules/vpc/aws", "2.0.0", "v2")
	r := &DotTerraformResolver{RootDirs: []string{root}}

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:   "terraform-aws-modules/vpc/aws",
		FileName: filepath.Join(root, "main.tf"),
	})

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != filepath.Join(root, "v2") {
		t.Fatalf("LocalPath = %q, want %q", res.LocalPath, filepath.Join(root, "v2"))
	}
}

func TestDotTerraformResolverUnversionedDuplicateSourceUsesModuleName(t *testing.T) {
	root := writeModulesJSONRecords(t, []dotTerraformModuleRecord{
		{Key: "a", Source: "terraform-aws-modules/vpc/aws", Dir: "v1"},
		{Key: "b", Source: "terraform-aws-modules/vpc/aws", Dir: "v2"},
	})
	r := &DotTerraformResolver{RootDirs: []string{root}}

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Name:     "b",
		Source:   "terraform-aws-modules/vpc/aws",
		FileName: filepath.Join(root, "main.tf"),
	})

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != filepath.Join(root, "v2") {
		t.Fatalf("LocalPath = %q, want %q", res.LocalPath, filepath.Join(root, "v2"))
	}
}

func TestDotTerraformResolverUnpinnedCallUsesModuleNameWhenPinnedRecordSharesSource(t *testing.T) {
	root := writeModulesJSONRecords(t, []dotTerraformModuleRecord{
		{Key: "a", Source: "terraform-aws-modules/vpc/aws", Version: "1.0.0", Dir: "v1"},
		{Key: "b", Source: "terraform-aws-modules/vpc/aws", Version: "2.0.0", Dir: "v2"},
	})
	r := &DotTerraformResolver{RootDirs: []string{root}}

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Name:     "b",
		Source:   "terraform-aws-modules/vpc/aws",
		FileName: filepath.Join(root, "main.tf"),
	})

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != filepath.Join(root, "v2") {
		t.Fatalf("LocalPath = %q, want %q", res.LocalPath, filepath.Join(root, "v2"))
	}
}

func TestGoGetterCacheHitCountsTotalBytes(t *testing.T) {
	cacheDir := t.TempDir()
	err := os.WriteFile(filepath.Join(cacheDir, "main.tf"), []byte("0123456789"), 0o644)
	if err != nil {
		t.Fatalf("write cached module: %v", err)
	}
	cfg := NewGoGetterConfig()
	cfg.MaxTotalBytes = 5
	r := NewGoGetterResolver(cfg)

	err = r.reserveDirBytes(cacheDir)

	if err == nil || !strings.Contains(err.Error(), "scan-level remote module byte cap exceeded") {
		t.Fatalf("expected total byte cap error, got %v", err)
	}
}

func TestGoGetterCacheHitCountsDirectoryOnce(t *testing.T) {
	cacheDir := t.TempDir()
	err := os.WriteFile(filepath.Join(cacheDir, "main.tf"), []byte("0123456789"), 0o644)
	if err != nil {
		t.Fatalf("write cached module: %v", err)
	}
	cfg := NewGoGetterConfig()
	cfg.MaxTotalBytes = 15
	r := NewGoGetterResolver(cfg)

	if err := r.reserveDirBytes(cacheDir); err != nil {
		t.Fatalf("first reserveDirBytes: %v", err)
	}
	if err := r.reserveDirBytes(cacheDir); err != nil {
		t.Fatalf("second reserveDirBytes should not double-count: %v", err)
	}
}

func TestCacheableModuleOnlyAllowsStableRefs(t *testing.T) {
	if !cacheableModule("terraform-aws-modules/vpc/aws", "1.0.0") {
		t.Fatal("expected pinned registry version to be cacheable")
	}
	if cacheableModule("git::https://example.com/mod.git?ref=main", "") {
		t.Fatal("expected mutable git branch to skip disk cache")
	}
	if !cacheableModule("git::https://example.com/mod.git?ref=0123456789abcdef0123456789abcdef01234567", "") {
		t.Fatal("expected git commit SHA to be cacheable")
	}
}

func TestAllowlistRejectsTranslatedGetterHost(t *testing.T) {
	r := NewGoGetterResolver(&GoGetterConfig{HostAllowlist: []string{"registry.terraform.io"}})

	err := r.checkAllowlist("git::https://github.com/org/mod.git?ref=v1.0.0")

	if err == nil || !strings.Contains(err.Error(), `module host "github.com" is not in --module-host-allowlist`) {
		t.Fatalf("expected final getter host allowlist error, got %v", err)
	}
}

func TestAllowlistIgnoresURLPort(t *testing.T) {
	r := NewGoGetterResolver(&GoGetterConfig{HostAllowlist: []string{"git.example.com"}})

	if err := r.checkAllowlist("git::https://git.example.com:8443/org/mod.git?ref=v1.0.0"); err != nil {
		t.Fatalf("expected host with custom port to pass allowlist: %v", err)
	}
	if err := r.checkAllowlist("git.example.com:8443/org/mod/aws"); err != nil {
		t.Fatalf("expected shorthand host with custom port to pass allowlist: %v", err)
	}
	if err := r.checkAllowlist("git@git.example.com:8443/org/mod.git"); err != nil {
		t.Fatalf("expected scp-style host with custom port to pass allowlist: %v", err)
	}
}

func writeModulesJSON(t *testing.T, source, version, dir string) string {
	return writeModulesJSONRecords(t, []dotTerraformModuleRecord{{Key: "m", Source: source, Version: version, Dir: dir}})
}

func writeModulesJSONRecords(t *testing.T, records []dotTerraformModuleRecord) string {
	t.Helper()
	root := t.TempDir()
	// Create the .terraform/modules/ tree so modules.json can be written there.
	if err := os.MkdirAll(filepath.Join(root, ".terraform", "modules"), 0o755); err != nil {
		t.Fatalf("mkdir .terraform/modules: %v", err)
	}
	for _, rec := range records {
		// Create the directory that DotTerraformResolver resolves to (root + Dir).
		if err := os.MkdirAll(filepath.Join(root, rec.Dir), 0o755); err != nil {
			t.Fatalf("mkdir module dir: %v", err)
		}
	}
	payload := dotTerraformModulesJSON{Modules: records}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal modules.json: %v", err)
	}
	err = os.WriteFile(filepath.Join(root, ".terraform", "modules", "modules.json"), []byte(data), 0o644)
	if err != nil {
		t.Fatalf("write modules.json: %v", err)
	}
	return root
}
