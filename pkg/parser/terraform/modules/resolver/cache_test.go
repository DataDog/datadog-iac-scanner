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
		if !e.IsDir() {
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
			if _, err := c.store(source, version, src); err != nil {
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
