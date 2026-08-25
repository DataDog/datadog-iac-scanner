/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCacheRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, sub := range []string{CacheSubdirModules, CacheSubdirGitBare, CacheSubdirGitLocal} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeCacheEntry(t *testing.T, dir, name string, size int, age time.Duration) string {
	t.Helper()
	entry := filepath.Join(dir, name)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, "blob"), []byte(strings.Repeat("a", size)), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(entry, when, when); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestModuleCacheBudgetEvictsAcrossSubdirs(t *testing.T) {
	root := testCacheRoot(t)
	budget, err := NewModuleCacheBudget(root, 150)
	if err != nil {
		t.Fatal(err)
	}

	modulesDir := filepath.Join(root, CacheSubdirModules)
	gitDir := filepath.Join(root, CacheSubdirGitBare)
	stale := writeCacheEntry(t, modulesDir, "stale", 80, 2*time.Hour)
	writeCacheEntry(t, gitDir, "git", 80, time.Hour)

	budget.Admit("")

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("oldest aggregate entry should have been evicted, stat: %v", err)
	}
	if _, total := listAggregateCacheEntries(root); total > budget.MaxBytes() {
		t.Fatalf("aggregate cache size %d exceeds max %d", total, budget.MaxBytes())
	}
}

func TestModuleCacheBudgetRemovesOversizedEntryAfterLease(t *testing.T) {
	root := testCacheRoot(t)
	budget, err := NewModuleCacheBudget(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	oversized := writeCacheEntry(t, filepath.Join(root, CacheSubdirGitBare), "huge", 150, time.Hour)
	release := budget.Lease(oversized)
	if err := budget.EnsureEntryFits(oversized); !errors.Is(err, errCacheEntryTooLarge) {
		t.Fatalf("checking oversized entry: %v", err)
	}
	if _, err := os.Stat(oversized); err != nil {
		t.Fatalf("leased oversized entry was removed early: %v", err)
	}
	release()
	if _, err := os.Stat(oversized); !os.IsNotExist(err) {
		t.Fatalf("oversized entry should be removed after its final lease, stat: %v", err)
	}
}

func TestModuleCacheStoreLeaseProtectsEntryDuringUse(t *testing.T) {
	cache, _ := newTestModuleCache(t, 150)
	write := func(name string, size int) string {
		t.Helper()
		src := t.TempDir()
		if err := os.WriteFile(filepath.Join(src, name+".tf"), []byte(strings.Repeat("a", size)), 0o644); err != nil {
			t.Fatal(err)
		}
		return src
	}

	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("seed%d", i)
		dir, release, err := cache.store("example/"+name+"/aws", "1.0.0", write(name, 80), "")
		release()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, time.Now().Add(-time.Duration(i+1)*time.Hour), time.Now().Add(-time.Duration(i+1)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	live, liveRelease, err := cache.store("example/live/aws", "1.0.0", write("live", 80), "")
	if err != nil {
		t.Fatal(err)
	}
	defer liveRelease()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, release, storeErr := cache.store("example/newer/aws", "1.0.0", write("newer", 80), "")
		if storeErr != nil {
			t.Error(storeErr)
			return
		}
		release()
	}()

	time.Sleep(20 * time.Millisecond)
	if _, statErr := os.Stat(live); statErr != nil {
		t.Fatalf("leased cache entry was evicted during concurrent admit: %v", statErr)
	}
	<-done
}

func TestModuleCacheBudgetDoesNotEvictPinnedEntries(t *testing.T) {
	root := testCacheRoot(t)
	budget, err := NewModuleCacheBudget(root, 150)
	if err != nil {
		t.Fatal(err)
	}
	modulesDir := filepath.Join(root, CacheSubdirModules)
	stale := writeCacheEntry(t, modulesDir, "stale", 80, 2*time.Hour)
	live := writeCacheEntry(t, modulesDir, "live", 80, time.Hour)

	err = budget.WithPin(live, func() error {
		writeCacheEntry(t, modulesDir, "newer", 80, 0)
		budget.Admit(live)
		if _, statErr := os.Stat(live); statErr != nil {
			t.Fatalf("pinned entry was evicted during pin: %v", statErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale entry should have been evicted after pin released, stat: %v", err)
	}
}

func TestModuleCacheBudgetEvictsWhenLeaseEnds(t *testing.T) {
	root := testCacheRoot(t)
	budget, err := NewModuleCacheBudget(root, 150)
	if err != nil {
		t.Fatal(err)
	}
	modulesDir := filepath.Join(root, CacheSubdirModules)
	first := writeCacheEntry(t, modulesDir, "first", 80, time.Hour)
	second := writeCacheEntry(t, modulesDir, "second", 80, 0)
	releaseFirst := budget.Lease(first)
	releaseSecond := budget.Lease(second)

	budget.Admit(second)
	if _, total := listAggregateCacheEntries(root); total <= budget.MaxBytes() {
		t.Fatal("expected active leases to allow a temporary cache overage")
	}

	releaseFirst()
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("released entry should be evicted to restore the cache limit: %v", err)
	}
	if _, total := listAggregateCacheEntries(root); total > budget.MaxBytes() {
		t.Fatalf("cache size %d exceeds max %d after lease release", total, budget.MaxBytes())
	}
	releaseSecond()
}
