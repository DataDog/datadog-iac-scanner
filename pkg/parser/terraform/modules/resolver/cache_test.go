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
	"sync"
	"testing"
	"time"
)

func writeModuleSrc(t *testing.T, nFiles int) string {
	t.Helper()
	src := t.TempDir()
	for i := 0; i < nFiles; i++ {
		name := filepath.Join(src, fmt.Sprintf("f%02d.tf", i))
		if err := os.WriteFile(name, []byte(fmt.Sprintf("resource \"r\" \"n%d\" {}\n", i)), 0o644); err != nil {
			t.Fatalf("write src file: %v", err)
		}
	}
	return src
}

func countTFFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".tf" {
			n++
		}
	}
	return n
}

func TestModuleCacheConcurrentStoreLookupNeverPartial(t *testing.T) {
	const nFiles = 40
	src := writeModuleSrc(t, nFiles)

	cacheRoot := t.TempDir()
	c := &moduleCache{dir: cacheRoot}

	const source, version = "registry.example.com/ns/name/aws", "1.2.3"

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.store(source, version, src, ""); err != nil {
				errCh <- fmt.Errorf("store: %w", err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if dir, ok := c.lookup(source, version); ok {
					if got := countTFFiles(t, dir); got != nFiles {
						errCh <- fmt.Errorf("lookup saw partial cache entry: %d/%d files", got, nFiles)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	dir, ok := c.lookup(source, version)
	if !ok {
		t.Fatal("expected cache hit after stores")
	}
	if got := countTFFiles(t, dir); got != nFiles {
		t.Fatalf("final cache entry has %d files, want %d", got, nFiles)
	}
}

func TestModuleCacheSkipsSymlinks(t *testing.T) {
	src := t.TempDir()
	requirePath := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`resource "x" "y" {}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	requirePath(filepath.Join(src, "modules", "selected", "main.tf"))
	outside := filepath.Join(t.TempDir(), "outside.tf")
	requirePath(outside)
	if err := os.Symlink(outside, filepath.Join(src, "evil.tf")); err != nil {
		t.Fatal(err)
	}

	cache := &moduleCache{dir: t.TempDir()}
	dir, err := cache.store("example/module/aws", "1.0.0", src, "modules/selected")
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "modules", "selected", "main.tf")); err != nil {
		t.Fatalf("regular module file was not cached: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "evil.tf")); !os.IsNotExist(err) {
		t.Fatalf("symlink was copied into cache: %v", err)
	}
}

func TestModuleCacheSharesPackageAcrossSubdirs(t *testing.T) {
	src := t.TempDir()
	for _, sub := range []string{"modules/vpc", "modules/ec2"} {
		dir := filepath.Join(src, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "y" {}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cache := &moduleCache{dir: t.TempDir()}
	const version = "1.0.0"
	vpcSource := "git::https://github.com/acme/modules.git//modules/vpc?ref=abc"
	ec2Source := "git::https://github.com/acme/modules.git//modules/ec2?ref=abc"

	vpcDir, err := cache.store(vpcSource, version, src, "modules/vpc")
	if err != nil {
		t.Fatalf("store vpc: %v", err)
	}
	ec2Dir, err := cache.store(ec2Source, version, src, "modules/ec2")
	if err != nil {
		t.Fatalf("store ec2: %v", err)
	}
	if vpcDir != ec2Dir {
		t.Fatalf("expected one shared package cache dir, got %q and %q", vpcDir, ec2Dir)
	}
}

func TestModuleCacheKeyAliasesEquivalentSources(t *testing.T) {
	registryA := moduleCacheKey("terraform-aws-modules/vpc/aws", "1.0.0")
	registryB := moduleCacheKey("registry.terraform.io/terraform-aws-modules/vpc/aws", "1.0.0")
	if registryA != registryB {
		t.Fatalf("registry prefix aliases must share a cache key")
	}
	if moduleCacheKey("terraform-aws-modules/vpc/aws", "2.0.0") == registryA {
		t.Fatal("different versions must not share a cache key")
	}

	gitA := moduleCacheKey("git::https://github.com/org/repo.git?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	gitB := moduleCacheKey("git::https://github.com/org/repo?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	if gitA != gitB {
		t.Fatalf("git .git suffix aliases must share a cache key")
	}
	gitOther := moduleCacheKey("git::https://github.com/org/repo.git?ref=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "")
	if gitA == gitOther {
		t.Fatal("different git refs must not share a cache key")
	}
}

func TestModuleCacheEvictsOldestEntries(t *testing.T) {
	dir := t.TempDir()
	previous, err := NewModuleCacheWithDir(dir, 150)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, size int) string {
		t.Helper()
		src := t.TempDir()
		payload := strings.Repeat("a", size)
		if err := os.WriteFile(filepath.Join(src, name+".tf"), []byte(payload), 0o644); err != nil {
			t.Fatal(err)
		}
		return src
	}

	first, err := previous.store("example/one/aws", "1.0.0", write("one", 80), "")
	if err != nil {
		t.Fatalf("store one: %v", err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(first, past, past); err != nil {
		t.Fatal(err)
	}
	second, err := previous.store("example/two/aws", "1.0.0", write("two", 80), "")
	if err != nil {
		t.Fatalf("store two: %v", err)
	}
	older := time.Now().Add(-time.Hour)
	if err := os.Chtimes(second, older, older); err != nil {
		t.Fatal(err)
	}

	cache, err := NewModuleCacheWithDir(dir, 150)
	if err != nil {
		t.Fatal(err)
	}
	third, err := cache.store("example/three/aws", "1.0.0", write("three", 80), "")
	if err != nil {
		t.Fatalf("store three: %v", err)
	}

	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("oldest cache entry should have been evicted, stat: %v", err)
	}
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatalf("second cache entry should have been evicted, stat: %v", err)
	}
	if _, err := os.Stat(third); err != nil {
		t.Fatalf("kept cache entry missing: %v", err)
	}
	if _, total := listCacheEntries(cache.dir); total > cache.maxBytes {
		t.Fatalf("cache size %d exceeds max %d", total, cache.maxBytes)
	}
}

func TestModuleCacheHitsDoNotEvictSiblings(t *testing.T) {
	cache, err := NewModuleCacheWithDir(t.TempDir(), 10*1024)
	if err != nil {
		t.Fatal(err)
	}
	src := writeModuleSrc(t, 2)
	first, err := cache.store("example/one/aws", "1.0.0", src, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.store("example/two/aws", "1.0.0", src, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, storeErr := cache.store("example/one/aws", "1.0.0", src, "")
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		if got != first {
			t.Fatalf("hit returned %q, want %q", got, first)
		}
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("cached module missing after hits: %v", err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("sibling evicted on cache hit: %v", err)
	}
}

func TestModuleCacheDoesNotEvictInUseEntries(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, size int) string {
		t.Helper()
		src := t.TempDir()
		if err := os.WriteFile(filepath.Join(src, name+".tf"), []byte(strings.Repeat("a", size)), 0o644); err != nil {
			t.Fatal(err)
		}
		return src
	}

	previous, err := NewModuleCacheWithDir(dir, 150)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := previous.store("example/stale/aws", "1.0.0", write("stale", 80), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(stale, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	cache, err := NewModuleCacheWithDir(dir, 150)
	if err != nil {
		t.Fatal(err)
	}
	live, err := cache.store("example/live/aws", "1.0.0", write("live", 80), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.lookup("example/live/aws", "1.0.0"); !ok {
		t.Fatal("expected live cache hit")
	}
	if _, err := cache.store("example/newer/aws", "1.0.0", write("newer", 80), ""); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("unused previous-scan entry should have been evicted, stat: %v", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("in-use cache entry was evicted: %v", err)
	}
}

func TestModuleCacheRejectsEntryLargerThanLimit(t *testing.T) {
	cache, err := NewModuleCacheWithDir(t.TempDir(), 50)
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.tf"), []byte(strings.Repeat("a", 80)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.store("example/huge/aws", "1.0.0", src, ""); !errors.Is(err, errCacheEntryTooLarge) {
		t.Fatalf("store oversized package: %v", err)
	}
	entries, err := os.ReadDir(cache.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("oversized package was published as %s", entry.Name())
		}
	}
}

func TestEvictUnretainedDirsSkipsRetained(t *testing.T) {
	root := t.TempDir()
	writeDir := func(name string, size int, age time.Duration) string {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "blob"), []byte(strings.Repeat("a", size)), 0o644); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(dir, when, when); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	stale := writeDir("stale", 80, 2*time.Hour)
	live := writeDir("live", 80, time.Hour)
	evictUnretainedDirs(root, 100, map[string]bool{filepath.Clean(live): true})
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("unretained dir should have been evicted, stat: %v", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("retained dir was evicted: %v", err)
	}
}
