/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// ModuleCacheBudget tracks one byte limit shared across modules/, git-bare/, and git-local/.
type ModuleCacheBudget struct {
	root     string
	maxBytes int64

	mu                 sync.Mutex
	pins               map[string]int
	removeWhenUnpinned map[string]bool
	evictOnUnpin       bool
}

func NewModuleCacheBudget(root string, maxBytes int64) (*ModuleCacheBudget, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxCacheBytes
	}
	root = filepath.Clean(root)
	for _, sub := range []string{CacheSubdirModules, CacheSubdirGitBare, CacheSubdirGitLocal} {
		if err := os.MkdirAll(filepath.Join(root, sub), cacheDirPerms); err != nil {
			return nil, err
		}
	}
	return &ModuleCacheBudget{root: root, maxBytes: maxBytes}, nil
}

func (b *ModuleCacheBudget) MaxBytes() int64 {
	if b == nil {
		return 0
	}
	return b.maxBytes
}

func (b *ModuleCacheBudget) Root() string {
	if b == nil {
		return ""
	}
	return b.root
}

func (b *ModuleCacheBudget) Pin(path string) {
	if b == nil || path == "" {
		return
	}
	path = filepath.Clean(path)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil {
		b.pins = make(map[string]int)
	}
	b.pins[path]++
}

func (b *ModuleCacheBudget) Unpin(path string) {
	if b == nil || path == "" {
		return
	}
	path = filepath.Clean(path)
	b.mu.Lock()
	if b.pins[path] > 1 {
		b.pins[path]--
		b.mu.Unlock()
		return
	}
	delete(b.pins, path)
	if b.removeWhenUnpinned[path] {
		_ = os.RemoveAll(path)
		delete(b.removeWhenUnpinned, path)
	}
	shouldEvict := b.evictOnUnpin
	b.mu.Unlock()
	if shouldEvict {
		b.Admit("")
	}
}

func (b *ModuleCacheBudget) Lease(path string) func() {
	if b == nil || path == "" {
		return func() {}
	}
	b.Pin(path)
	var once sync.Once
	return func() {
		once.Do(func() {
			b.Unpin(path)
		})
	}
}

func (b *ModuleCacheBudget) WithPin(path string, fn func() error) error {
	release := b.Lease(path)
	defer release()
	return fn()
}

func (b *ModuleCacheBudget) EnsureEntryFits(path string) error {
	if b == nil || path == "" {
		return nil
	}
	path = filepath.Clean(path)
	b.mu.Lock()
	defer b.mu.Unlock()
	if cacheEntrySize(path) <= b.maxBytes {
		return nil
	}
	if b.removeWhenUnpinned == nil {
		b.removeWhenUnpinned = make(map[string]bool)
	}
	b.removeWhenUnpinned[path] = true
	if b.pins[path] == 0 {
		_ = os.RemoveAll(path)
		delete(b.removeWhenUnpinned, path)
	}
	return errCacheEntryTooLarge
}

func (b *ModuleCacheBudget) Admit(keep string) {
	if b == nil || b.maxBytes <= 0 {
		return
	}
	if keep != "" {
		keep = filepath.Clean(keep)
		if b.EnsureEntryFits(keep) != nil {
			keep = ""
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	entries, total := listAggregateCacheEntries(b.root)
	if total <= b.maxBytes {
		b.evictOnUnpin = false
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].modTime.Equal(entries[j].modTime) {
			return entries[i].path < entries[j].path
		}
		return entries[i].modTime.Before(entries[j].modTime)
	})
	for _, entry := range entries {
		if total <= b.maxBytes {
			break
		}
		path := filepath.Clean(entry.path)
		if keep != "" && path == keep {
			continue
		}
		if b.pins[path] > 0 {
			continue
		}
		if err := os.RemoveAll(entry.path); err != nil {
			continue
		}
		total -= entry.size
	}
	b.evictOnUnpin = total > b.maxBytes
}

func cacheEntrySize(path string) int64 {
	size, ok := readCacheSize(path)
	if ok {
		return size
	}
	return directorySize(path)
}

func listAggregateCacheEntries(root string) (entries []cacheEntry, total int64) {
	for _, sub := range []string{CacheSubdirModules, CacheSubdirGitBare, CacheSubdirGitLocal} {
		subEntries, subTotal := listCacheEntries(filepath.Join(root, sub))
		entries = append(entries, subEntries...)
		total += subTotal
	}
	return entries, total
}
