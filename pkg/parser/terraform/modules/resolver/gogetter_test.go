/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

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
	repo := t.TempDir()
	for i := 0; i < 5; i++ {
		f := filepath.Join(repo, fmt.Sprintf("m%d.tf", i))
		if err := os.WriteFile(f, []byte(fmt.Sprintf("resource \"r\" \"n%d\" {}\n", i)), 0o644); err != nil {
			t.Fatalf("write tf: %v", err)
		}
	}
	runGit(t, repo, "init")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init")
	sha := runGit(t, repo, "rev-parse", "HEAD")

	cacheRoot := t.TempDir()
	cfg := NewGoGetterConfig()
	cfg.Cache = &moduleCache{dir: cacheRoot}
	cfg.TmpDir = t.TempDir()
	r := NewGoGetterResolver(cfg)

	// Build a valid file URL: forward slashes required, and Windows absolute
	// paths need a leading "/" before the drive letter (file:///C:/...).
	slashPath := filepath.ToSlash(repo)
	if !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	source := fmt.Sprintf("git::file://%s?ref=%s", slashPath, sha)
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
