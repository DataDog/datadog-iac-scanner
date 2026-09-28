/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRegistryClientRejectsPrivateDestinationWithoutAllowlist(t *testing.T) {
	cache := NewRegistryCache(time.Second)

	_, err := discoverModulesEndpoint(
		t.Context(),
		cache.client,
		"https://169.254.169.254",
	)

	if err == nil || !strings.Contains(err.Error(), "not a public unicast destination") {
		t.Fatalf("expected registry metadata destination to be rejected, got %v", err)
	}
}

func TestRegistryClientAppliesHostAllowlist(t *testing.T) {
	cache := NewRegistryCache(time.Second, "registry.terraform.io")

	_, err := discoverModulesEndpoint(
		t.Context(),
		cache.client,
		"https://example.com",
	)

	if err == nil || !strings.Contains(err.Error(), "not in --module-host-allowlist") {
		t.Fatalf("expected registry host outside allowlist to be rejected, got %v", err)
	}
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
		defaultRegistryHost,
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
		defaultRegistryHost,
	)

	if err != nil {
		t.Fatalf("resolveRegistryVersion: %v", err)
	}
	if got != "2.0.0" {
		t.Fatalf("version = %q, want 2.0.0", got)
	}
}

func TestResolveConcreteVersionBareVersionSkipsDiscovery(t *testing.T) {
	cache := NewRegistryCache(time.Second)
	cache.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("registry discovery must not run for pinned bare versions")
			return nil, nil
		}),
	}

	got, err := cache.resolveConcreteVersion(
		context.Background(),
		"terraform-aws-modules/vpc/aws",
		"1.0.0",
	)
	if err != nil {
		t.Fatalf("resolveConcreteVersion: %v", err)
	}
	if got != "1.0.0" {
		t.Fatalf("version = %q, want 1.0.0", got)
	}
}

func TestResolveRegistryVersionReadsLargeVersionLists(t *testing.T) {
	var body strings.Builder
	body.WriteString(`{"modules":[{"versions":[`)
	for i := 0; i < 5000; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `{"version":"1.%d.0","submodules":[{"path":"modules/padding","providers":[{"name":"aws"}]}]}`, i)
	}
	body.WriteString(`]}]}`)
	if body.Len() <= 128*1024 {
		t.Fatalf("fixture is only %d bytes", body.Len())
	}
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body.String())),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	got, err := resolveRegistryVersion(
		context.Background(), client, "https://registry.terraform.io/v1/modules/",
		"terraform-aws-modules", "iam", "aws", "~> 1.4000", defaultRegistryHost,
	)
	if err != nil {
		t.Fatalf("resolveRegistryVersion: %v", err)
	}
	if got != "1.4999.0" {
		t.Fatalf("got %q, want 1.4999.0", got)
	}
}

func TestReadLimitedBodyRejectsOversizedResponse(t *testing.T) {
	if _, err := readLimitedBody(strings.NewReader("12345"), 4, "versions"); err == nil ||
		!strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("expected an explicit size error, got %v", err)
	}
	data, err := readLimitedBody(strings.NewReader("1234"), 4, "versions")
	if err != nil || string(data) != "1234" {
		t.Fatalf("body at the limit: %q, %v", data, err)
	}
}

func TestResolveRegistryVersionSkipsUnrequestedPrerelease(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"modules":[{"versions":[{"version":"2.0.0"},{"version":"3.0.0-beta.1"}]}]}`,
				)),
				Header:  make(http.Header),
				Request: req,
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
		defaultRegistryHost,
	)
	if err != nil {
		t.Fatalf("resolveRegistryVersion: %v", err)
	}
	if got != "2.0.0" {
		t.Fatalf("version = %q, want 2.0.0", got)
	}
}

func TestResolveRegistryVersionConstraintCanSelectPrerelease(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"modules":[{"versions":[{"version":"2.0.0"},{"version":"3.0.0-beta.1"}]}]}`,
				)),
				Header:  make(http.Header),
				Request: req,
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
		">= 3.0.0-beta.1",
		defaultRegistryHost,
	)
	if err != nil {
		t.Fatalf("resolveRegistryVersion: %v", err)
	}
	if got != "3.0.0-beta.1" {
		t.Fatalf("version = %q, want 3.0.0-beta.1", got)
	}
}

func TestResolveRegistryVersionUsesRegistryHostToken(t *testing.T) {
	t.Setenv("TF_TOKEN_registry_example_com", "secret-token")
	var auth, requestHost string
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			auth = req.Header.Get("Authorization")
			requestHost = req.URL.Hostname()
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"modules":[{"versions":[{"version":"1.0.0"}]}]}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	got, err := resolveRegistryVersion(
		context.Background(),
		client,
		"https://modules.other.example/v1/modules/",
		"ns",
		"name",
		"aws",
		"1.0.0",
		"registry.example.com:8443",
	)
	if err != nil {
		t.Fatalf("resolveRegistryVersion: %v", err)
	}
	if got != "1.0.0" {
		t.Fatalf("version = %q, want 1.0.0", got)
	}
	if requestHost != "modules.other.example" {
		t.Fatalf("request host = %q, want modules.other.example", requestHost)
	}
	if auth != "Bearer secret-token" {
		t.Fatalf("authorization = %q, want registry-host token", auth)
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

func TestParseRegistrySourceWithHostPort(t *testing.T) {
	host, namespace, name, provider, err := parseRegistrySource("registry.example.com:8443/ns/name/aws//modules/child")
	if err != nil {
		t.Fatalf("parseRegistrySource: %v", err)
	}
	if host != "registry.example.com:8443" || namespace != "ns" || name != "name" || provider != "aws" {
		t.Fatalf("unexpected source parts: %q %q %q %q", host, namespace, name, provider)
	}
	if got := registrySubdir("registry.example.com:8443/ns/name/aws//modules/child"); got != "modules/child" {
		t.Fatalf("subdir = %q, want modules/child", got)
	}
}

func TestAppendGetterSubdirPreservesQuery(t *testing.T) {
	got := appendGetterSubdir("git::https://github.com/org/mod.git?ref=v1.0.0", "modules/child")
	want := "git::https://github.com/org/mod.git//modules/child?ref=v1.0.0"
	if got != want {
		t.Fatalf("getter URL = %q, want %q", got, want)
	}
}

func TestSplitGetterSubdirPreservesPackageSource(t *testing.T) {
	tests := []struct {
		source        string
		packageSource string
		subdir        string
	}{
		{
			source:        "git::https://github.com/org/mod.git//modules/child?ref=v1.0.0",
			packageSource: "git::https://github.com/org/mod.git?ref=v1.0.0",
			subdir:        "modules/child",
		},
		{
			source:        "https://example.com/mod.zip//modules/child",
			packageSource: "https://example.com/mod.zip",
			subdir:        "modules/child",
		},
		{
			source:        "git::https://github.com/org/mod.git?ref=v1.0.0",
			packageSource: "git::https://github.com/org/mod.git?ref=v1.0.0",
		},
		{
			source:        "https://example.com/mod.zip////modules/child?archive=zip",
			packageSource: "https://example.com/mod.zip?archive=zip",
			subdir:        "modules/child",
		},
	}
	for _, test := range tests {
		t.Run(test.source, func(t *testing.T) {
			packageSource, subdir := splitGetterSubdir(test.source)
			if packageSource != test.packageSource || subdir != test.subdir {
				t.Fatalf("splitGetterSubdir(%q) = (%q, %q), want (%q, %q)",
					test.source, packageSource, subdir, test.packageSource, test.subdir)
			}
		})
	}
}

func TestPrefetchedResolverUsesVersionedManifestKey(t *testing.T) {
	cacheRoot := t.TempDir()
	v1 := filepath.Join(cacheRoot, "v1")
	v2 := filepath.Join(cacheRoot, "v2")
	if err := os.MkdirAll(v1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(v2, 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewPrefetchedResolver(&Manifest{
		Modules: map[string]ManifestEntry{
			"terraform-aws-modules/vpc/aws@1.0.0": {LocalPath: v1},
			"terraform-aws-modules/vpc/aws@2.0.0": {LocalPath: v2},
		},
	})

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "2.0.0",
	})

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != v2 {
		t.Fatalf("LocalPath = %q, want %q", res.LocalPath, v2)
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

func TestDotTerraformResolverPrefersDeepestInstallRoot(t *testing.T) {
	outer := writeModulesJSON(t, "terraform-aws-modules/vpc/aws", "", "outer")
	inner := filepath.Join(outer, "stacks", "app")
	writeModulesJSONAt(t, inner, "terraform-aws-modules/vpc/aws", "", "inner")
	plain := filepath.Join(inner, "nested")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &DotTerraformResolver{RootDirs: TerraformRootDirs([]string{outer, inner, plain})}

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:   "terraform-aws-modules/vpc/aws",
		FileName: filepath.Join(plain, "main.tf"),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.LocalPath != filepath.Join(inner, "inner") {
		t.Fatalf("LocalPath = %q, want the innermost install", res.LocalPath)
	}
	if got := r.rootsFor(filepath.Join(plain, "main.tf")); len(got) != 2 || got[0] != inner || got[1] != outer {
		t.Fatalf("rootsFor = %v, want [%s %s]", got, inner, outer)
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

func TestDotTerraformResolverRejectsManifestEscape(t *testing.T) {
	root := t.TempDir()
	modulesDir := filepath.Join(root, ".terraform", "modules")
	if err := os.MkdirAll(modulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	payload := dotTerraformModulesJSON{Modules: []dotTerraformModuleRecord{{
		Key:    "m",
		Source: "terraform-aws-modules/vpc/aws",
		Dir:    outside,
	}}}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modulesDir, "modules.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	resolver := &DotTerraformResolver{RootDirs: []string{root}}

	_, err = resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Name:     "m",
		Source:   "terraform-aws-modules/vpc/aws",
		FileName: filepath.Join(root, "main.tf"),
	})
	if err == nil {
		t.Fatal("expected modules.json path outside the scan root to be rejected")
	}
}

func TestDotTerraformResolverRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	moduleDir := filepath.Join(root, ".terraform", "modules", "vpc")
	if err := os.MkdirAll(filepath.Dir(moduleDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, moduleDir); err != nil {
		t.Fatal(err)
	}
	payload := dotTerraformModulesJSON{Modules: []dotTerraformModuleRecord{{
		Key:    "m",
		Source: "terraform-aws-modules/vpc/aws",
		Dir:    filepath.Join(".terraform", "modules", "vpc"),
	}}}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".terraform", "modules", "modules.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	resolver := &DotTerraformResolver{RootDirs: []string{root}}

	_, err = resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Name:     "m",
		Source:   "terraform-aws-modules/vpc/aws",
		FileName: filepath.Join(root, "main.tf"),
	})
	if err == nil {
		t.Fatal("expected symlinked .terraform module path to be rejected")
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
	if res.ResolvedVersion != "2.0.0" {
		t.Fatalf("ResolvedVersion = %q, want %q", res.ResolvedVersion, "2.0.0")
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
	if err := os.WriteFile(filepath.Join(cacheDir, "main.tf"), []byte("0123456789"), 0o644); err != nil {
		t.Fatalf("write cached module: %v", err)
	}
	cfg := NewGoGetterConfig()
	cfg.MaxTotalBytes = 5
	r := NewGoGetterResolver(cfg)

	err := r.reserveDirBytes(t.Context(), cacheDir)

	if err == nil || !strings.Contains(err.Error(), "scan-level remote module byte cap exceeded") {
		t.Fatalf("expected total byte cap error, got %v", err)
	}
}

func TestGoGetterCacheHitCountsDirectoryOnce(t *testing.T) {
	cacheDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cacheDir, "main.tf"), []byte("0123456789"), 0o644); err != nil {
		t.Fatalf("write cached module: %v", err)
	}
	cfg := NewGoGetterConfig()
	cfg.MaxTotalBytes = 15
	r := NewGoGetterResolver(cfg)

	if err := r.reserveDirBytes(t.Context(), cacheDir); err != nil {
		t.Fatalf("first reserveDirBytes: %v", err)
	}
	if err := r.reserveDirBytes(t.Context(), cacheDir); err != nil {
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
	return writeModulesJSONRecordsAt(t, t.TempDir(), records)
}

func writeModulesJSONAt(t *testing.T, root, source, version, dir string) {
	t.Helper()
	writeModulesJSONRecordsAt(t, root, []dotTerraformModuleRecord{{Key: "m", Source: source, Version: version, Dir: dir}})
}

func writeModulesJSONRecordsAt(t *testing.T, root string, records []dotTerraformModuleRecord) string {
	t.Helper()
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

func TestRegistryDiscoveryFailureBackoffExpires(t *testing.T) {
	var calls atomic.Int64
	now := time.Now()
	cache := NewRegistryCache(time.Second)
	cache.now = func() time.Time { return now }
	cache.backoff = time.Second
	cache.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, &net.DNSError{Err: "no such host", Name: "registry.example", IsNotFound: true}
		}),
	}

	if _, err := cache.modulesV1(context.Background(), "registry.example"); err == nil {
		t.Fatal("expected discovery failure")
	}
	if _, err := cache.modulesV1(context.Background(), "registry.example"); err == nil {
		t.Fatal("expected cached discovery failure")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cached DNS failure retried immediately: %d calls", got)
	}
	now = now.Add(2 * time.Second)
	if _, err := cache.modulesV1(context.Background(), "registry.example"); err == nil {
		t.Fatal("expected retry to fail")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expired DNS failure was not retried: %d calls", got)
	}
}

func TestRegistryDiscoveryPolicyDenialDoesNotExpire(t *testing.T) {
	var lookups atomic.Int64
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP(fmt.Sprintf("172.19.1.%d", lookups.Load()))}, nil
	}
	now := time.Now()
	cache := NewRegistryCache(time.Second)
	cache.client = newPolicyHTTPClientWithPolicy(time.Second, policy)
	cache.now = func() time.Time { return now }
	cache.backoff = time.Second

	_, first := cache.modulesV1(t.Context(), "registry.internal.example")
	if !isDestinationDenied(first) {
		t.Fatalf("expected a policy denial, got %v", first)
	}
	now = now.Add(time.Hour)
	_, second := cache.modulesV1(t.Context(), "registry.internal.example")
	if got := lookups.Load(); got != 1 {
		t.Fatalf("denied registry host was probed %d times", got)
	}
	if second == nil || second.Error() != first.Error() {
		t.Fatalf("expected the first denial to be reused, got %v", second)
	}
}

func TestRegistryDiscoveryDoesNotCacheCanceledContext(t *testing.T) {
	var calls atomic.Int64
	cache := NewRegistryCache(time.Second)
	cache.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, context.Canceled
		}),
	}
	if _, err := cache.modulesV1(context.Background(), "registry.example"); err == nil {
		t.Fatal("expected canceled discovery")
	}
	if _, err := cache.modulesV1(context.Background(), "registry.example"); err == nil {
		t.Fatal("expected second canceled discovery")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("canceled discovery must not be cached, calls=%d", got)
	}
}

func TestRegistryDownloadPolicyDenialDoesNotExpire(t *testing.T) {
	var lookups atomic.Int64
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP("172.19.1.1")}, nil
	}
	now := time.Now()
	cache := NewRegistryCache(time.Second)
	cache.client = newPolicyHTTPClientWithPolicy(time.Second, policy)
	cache.now = func() time.Time { return now }
	cache.backoff = time.Second

	ep := "https://downloads.internal.example/v1/modules/"
	_, first := cache.downloadURL(t.Context(), ep, "registry.example", "acme", "vpc", "aws", "1.0.0")
	if !isDestinationDenied(first) {
		t.Fatalf("expected a policy denial, got %v", first)
	}
	now = now.Add(time.Hour)
	if _, second := cache.downloadURL(t.Context(), ep, "registry.example", "acme", "vpc", "aws", "1.0.0"); second == nil {
		t.Fatal("expected the cached denial")
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("denied download host was probed %d times", got)
	}
}

func TestRegistryDownloadDoesNotCacheCanceledContext(t *testing.T) {
	var calls atomic.Int64
	cache := NewRegistryCache(time.Second)
	cache.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, context.Canceled
		}),
	}
	ep := "https://registry.example/v1/modules/"
	for range 2 {
		if _, err := cache.downloadURL(t.Context(), ep, "registry.example", "acme", "vpc", "aws", "1.0.0"); err == nil {
			t.Fatal("expected canceled download")
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("canceled download must not be cached, calls=%d", got)
	}
}

func TestRegistryCacheDoesNotWriteDeadHostFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", home)
	cache := NewRegistryCache(time.Second)
	cache.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "no such host", Name: "registry.example", IsNotFound: true}
		}),
	}
	_, _ = cache.modulesV1(context.Background(), "registry.example")
	path := filepath.Join(home, "datadog-iac-scanner", "dead-registry-hosts.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("dead-host file should not exist, stat: %v", err)
	}
}
