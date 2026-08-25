/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	getter "github.com/hashicorp/go-getter"
	"github.com/stretchr/testify/require"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

func TestGoGetterHTTPRejectsPrivateDestinationWithoutAllowlist(t *testing.T) {
	cfg := NewGoGetterConfig()
	cfg.TmpDir = t.TempDir()
	r := NewGoGetterResolver(cfg)

	_, err := r.fetchOnce(t.Context(), "http://169.254.169.254/module.zip")

	if err == nil || !strings.Contains(err.Error(), "not a public unicast destination") {
		t.Fatalf("expected metadata destination to be rejected, got %v", err)
	}
}

func TestGoGetterConfigAppliesAllowlistToRegistryClient(t *testing.T) {
	cfg := NewGoGetterConfig()
	cfg.HostAllowlist = []string{"registry.terraform.io"}
	r := NewGoGetterResolver(cfg)

	_, err := discoverModulesEndpoint(
		t.Context(),
		r.cfg.RegistryCache.client,
		"https://example.com",
	)

	if err == nil || !strings.Contains(err.Error(), "not in --module-host-allowlist") {
		t.Fatalf("expected registry client to use resolver allowlist, got %v", err)
	}
}

func TestGoGetterHTTPValidatesXTerraformGetDestination(t *testing.T) {
	var target string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Terraform-Get", target)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(_ context.Context, _, host string) ([]net.IP, error) {
		switch host {
		case "source.example":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		case "metadata.internal":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		default:
			return nil, fmt.Errorf("unexpected host %q", host)
		}
	}
	policy.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}

	cfg := NewGoGetterConfig()
	cfg.TmpDir = t.TempDir()
	cfg.httpClient = newPolicyHTTPClientWithPolicy(time.Second, policy)
	r := NewGoGetterResolver(cfg)

	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "private HTTP destination",
			source: "http://metadata.internal/latest",
			want:   "not a public unicast destination",
		},
		{
			name:   "protocol switch",
			source: "git::http://169.254.169.254/repository.git",
			want:   `no getter available for X-Terraform-Get source protocol: "git"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target = test.source
			_, fetchErr := r.fetchOnce(t.Context(), "http://source.example:"+port+"/module")
			if fetchErr == nil || !strings.Contains(fetchErr.Error(), test.want) {
				t.Fatalf("expected X-Terraform-Get source to be rejected with %q, got %v", test.want, fetchErr)
			}
		})
	}
}

func TestGetterSourceForPreservesHTTPSGit(t *testing.T) {
	r := NewGoGetterResolver(NewGoGetterConfig())
	mod := &tfmodules.ParsedModule{
		Source: "git::https://github.com/org/repo.git//modules/child?ref=v1.0.0",
	}
	got, err := r.getterSourceFor(context.Background(), "git", mod, "")
	if err != nil {
		t.Fatalf("getterSourceFor: %v", err)
	}
	if !strings.HasPrefix(got, "git::https://") {
		t.Fatalf("getter source must preserve HTTPS, got %q", got)
	}
	if strings.Contains(got, "ssh://") {
		t.Fatalf("getter source must not rewrite to SSH, got %q", got)
	}
}

func TestGoGetterUsesGraphResourceLimits(t *testing.T) {
	t.Parallel()

	cfg := NewGoGetterConfig()
	resolver := NewGoGetterResolver(cfg)
	ctx := WithResourceBudget(t.Context(), NewResourceBudget(ResourceLimits{
		MaxPackageBytes: 1234,
		MaxPackageFiles: 7,
	}))

	httpGetter, ok := resolver.getters("https://example.com/module.zip")["https"].(*getter.HttpGetter)
	require.True(t, ok)
	require.Zero(t, httpGetter.MaxBytes)
	require.Equal(t, int64(1234), resolver.maxPackageBytes(ctx))

	decompressors := resolver.decompressors(ctx)
	budgeted, ok := decompressors["zip"].(*zipBudgetDecompressor)
	require.True(t, ok)
	zipper, ok := budgeted.inner.(*getter.ZipDecompressor)
	require.True(t, ok)
	require.Equal(t, int64(1234), zipper.FileSizeLimit)
	require.Equal(t, 7, zipper.FilesLimit)
}

func TestGoGetterDisablesUnpinnedNetworkTransports(t *testing.T) {
	r := NewGoGetterResolver(NewGoGetterConfig())
	for _, scheme := range []string{"s3", "gcs", "hg"} {
		if _, ok := r.getters(scheme + "::https://modules.example/package")[scheme]; ok {
			t.Fatalf("getter %q must be disabled", scheme)
		}
	}

	tests := []struct {
		source string
		want   string
	}{
		{"s3::https://s3.amazonaws.com/bucket/module", `module transport "s3" is disabled`},
		{"gcs::https://www.googleapis.com/storage/v1/bucket/module", `module transport "gcs" is disabled`},
		{"hg::https://modules.example/repository", `module transport "hg" is disabled`},
		{"git::ssh://git@modules.example/repository", `network git transport "ssh" is disabled`},
		{"git::https://modules.example/repository", `network git transport "https" is disabled`},
	}
	for _, test := range tests {
		t.Run(test.source, func(t *testing.T) {
			err := validateGetterSourceTransport(test.source)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
	if err := validateGetterSourceTransport("git::file:///tmp/repository"); err == nil {
		t.Fatal("git subprocess transport must be disabled even for file sources")
	}
}

func TestCacheableModuleRegistrySubdir(t *testing.T) {
	if !cacheableModule("terraform-aws-modules/eks/aws//modules/karpenter", "1.0.0") {
		t.Fatal("expected pinned registry subdir module to be cacheable")
	}
}

func TestIsTransientFetchError(t *testing.T) {
	transient := []string{
		"fetch failed: error downloading 'ssh://git@github.com/x?ref=v1': git exited with -1: ...fatal: early EOF",
		"git exited with -1: ...Session open refused by peer",
		"kex_exchange_identification: Connection closed by remote host",
		"fatal: the remote end hung up unexpectedly",
		"error: RPC failed; curl 18 transfer closed",
		"read tcp: connection reset by peer",
		"dial tcp: i/o timeout",
	}
	deterministic := []string{
		"registry discovery for r.example.com: Get \"https://...\": dial tcp: lookup r.example.com: no such host",
		"download endpoint returned HTTP 404",
		"module exceeds per-module limit of 10 MiB",
		"remote module fetching is disabled",
		"fetch failed: error downloading 'ssh://git@github.com/x?ref=v1': git exited with -1: Cloning into '/tmp/t'...",
	}
	for _, m := range transient {
		if !isTransientFetchError(errors.New(m)) {
			t.Errorf("expected transient: %q", m)
		}
	}
	for _, m := range deterministic {
		if isTransientFetchError(errors.New(m)) {
			t.Errorf("expected NOT transient: %q", m)
		}
	}
	if isTransientFetchError(nil) {
		t.Error("nil must not be transient")
	}
}

func TestAcquireHostSlotCapsConcurrencyPerHost(t *testing.T) {
	old := HostFetchConcurrency
	HostFetchConcurrency = 3
	defer func() { HostFetchConcurrency = old }()

	r := NewGoGetterResolver(NewGoGetterConfig())

	measure := func(host string, want int64) {
		var inFlight, maxInFlight atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				release, err := r.acquireHostSlot(context.Background(), host)
				if err != nil {
					t.Errorf("acquireHostSlot(%s): %v", host, err)
					return
				}
				defer release()
				n := inFlight.Add(1)
				for {
					m := maxInFlight.Load()
					if n <= m || maxInFlight.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				inFlight.Add(-1)
			}()
		}
		wg.Wait()
		if got := maxInFlight.Load(); got > want {
			t.Fatalf("host %s: max concurrency %d exceeds cap %d", host, got, want)
		}
	}

	measure("github.com", 3)
	measure("gitlab.com", 3)

	// Disabled cap is a no-op.
	HostFetchConcurrency = 0
	release, err := r.acquireHostSlot(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("disabled cap should not error: %v", err)
	}
	release()
}

func TestGoGetterResolveCoalescesConcurrentFetches(t *testing.T) {
	var moduleArchive bytes.Buffer
	zipWriter := zip.NewWriter(&moduleArchive)
	for i := 0; i < 5; i++ {
		file, err := zipWriter.Create(fmt.Sprintf("m%d.tf", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(fmt.Sprintf("resource \"r\" \"n%d\" {}\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(moduleArchive.Bytes())
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	policy.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}

	cacheRoot := t.TempDir()
	cfg := NewGoGetterConfig()
	cfg.Cache = &moduleCache{dir: cacheRoot}
	cfg.TmpDir = t.TempDir()
	cfg.httpClient = newPolicyHTTPClientWithPolicy(time.Second, policy)
	r := NewGoGetterResolver(cfg)

	source := "http://modules.example:" + port + "/module.zip?ref=" + strings.Repeat("a", gitSHALength)
	if !cacheableModule(source, "") {
		t.Fatalf("test setup: source %q is not cacheable", source)
	}

	const n = 12
	var wg sync.WaitGroup
	results := make([]Resolution, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mod := &tfmodules.ParsedModule{Source: source, Name: "m", FileName: "main.tf"}
			results[i], errs[i] = r.Resolve(context.Background(), mod)
		}()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("resolve %d failed: %v", i, errs[i])
		}
		if results[i].LocalPath != results[0].LocalPath {
			t.Fatalf("resolve %d localpath %q != %q", i, results[i].LocalPath, results[0].LocalPath)
		}
	}
	if got := cfg.fetchCount.Load(); got != 1 {
		t.Fatalf("expected exactly 1 fetch for %d concurrent identical resolves, got %d", n, got)
	}
}

type stubGitResolver struct {
	last *tfmodules.ParsedModule
	res  Resolution
}

func (s *stubGitResolver) Resolve(_ context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	s.last = mod
	return s.res, nil
}

func TestFetchAndCommitDelegatesPinnableGit(t *testing.T) {
	stub := &stubGitResolver{
		res: Resolution{LocalPath: "/tmp/mod", PackageRoot: "/tmp/mod"},
	}
	cfg := NewGoGetterConfig()
	cfg.Git = stub
	r := NewGoGetterResolver(cfg)

	mod := &tfmodules.ParsedModule{Source: "git::https://github.com/org/repo.git"}
	res, err := r.fetchAndCommit(context.Background(), sourceTypeGit, mod, "", "", false)
	if err != nil {
		t.Fatalf("fetchAndCommit: %v", err)
	}
	if res.LocalPath != stub.res.LocalPath {
		t.Fatalf("LocalPath = %q, want delegated result", res.LocalPath)
	}
	if stub.last == nil || stub.last.Source != "git::https://github.com/org/repo.git?ref=HEAD" {
		t.Fatalf("delegated source = %v, want git::https with ref=HEAD", stub.last)
	}

	mod = &tfmodules.ParsedModule{Source: "git::https://github.com/terraform-aws-modules/terraform-aws-vpc?ref=abc123"}
	_, err = r.fetchAndCommit(context.Background(), sourceTypeGit, mod, "", "modules/vpc", false)
	if err != nil {
		t.Fatalf("fetchAndCommit registry-style: %v", err)
	}
	if stub.last.Source != "git::https://github.com/terraform-aws-modules/terraform-aws-vpc//modules/vpc?ref=abc123" {
		t.Fatalf("delegated source = %q", stub.last.Source)
	}
}
