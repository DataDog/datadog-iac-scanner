/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
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
