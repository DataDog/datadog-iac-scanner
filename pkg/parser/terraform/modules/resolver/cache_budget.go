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
	"strings"
	"sync"
)

var cacheBudgetSubdirs = []string{CacheSubdirModules, CacheSubdirGitBare, CacheSubdirGitLocal}

// ModuleCacheBudget is a soft byte limit shared across modules/, git-bare/, and
// git-local/. It bounds disk use only; per-scan package and total limits belong
// to ResourceBudget.
//
// A modules/ entry's size comes from its size file. Git entries have none and
// can hold thousands of files, so each is walked once and then kept current by
// the resolvers writing into it: Grow when the written bytes are known,
// Invalidate otherwise. Grow can recount bytes that an overlapping walk already
// saw, which errs toward evicting early.
//
// Sizes and pins are per process. Entries another process adds or removes are
// picked up by the next Admit, but its growth of an entry already measured here
// is not, and pins do not stop another process from evicting an entry in use.
type ModuleCacheBudget struct {
	root     string
	maxBytes int64

	mu                 sync.Mutex
	pins               map[string]int
	removeWhenUnpinned map[string]bool
	evictOnUnpin       bool
	sizes              map[string]int64
}

func NewModuleCacheBudget(root string, maxBytes int64) (*ModuleCacheBudget, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxCacheBytes
	}
	root = filepath.Clean(root)
	for _, sub := range cacheBudgetSubdirs {
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
		delete(b.sizes, path)
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
	if b.entrySizeLocked(path) <= b.maxBytes {
		return nil
	}
	if b.removeWhenUnpinned == nil {
		b.removeWhenUnpinned = make(map[string]bool)
	}
	b.removeWhenUnpinned[path] = true
	if b.pins[path] == 0 {
		_ = os.RemoveAll(path)
		delete(b.removeWhenUnpinned, path)
		delete(b.sizes, path)
	}
	return errCacheEntryTooLarge
}

// Grow adds bytes just written into an entry. An entry that has not been
// measured yet is left alone; its first check walks it.
func (b *ModuleCacheBudget) Grow(path string, bytes int64) {
	if b == nil || path == "" || bytes == 0 {
		return
	}
	path = filepath.Clean(path)
	b.mu.Lock()
	defer b.mu.Unlock()
	if size, ok := b.sizes[path]; ok {
		b.sizes[path] = max(size+bytes, 0)
	}
}

// Invalidate drops an entry's recorded size after a write whose size is not
// known, so the next check measures it again.
func (b *ModuleCacheBudget) Invalidate(path string) {
	if b == nil || path == "" {
		return
	}
	path = filepath.Clean(path)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sizes, path)
}

func (b *ModuleCacheBudget) entrySizeLocked(path string) int64 {
	if size, ok := b.sizes[path]; ok {
		return size
	}
	// A missing entry is not recorded: it may be published right after.
	if _, err := os.Lstat(path); err != nil {
		return 0
	}
	size := cacheEntrySize(path)
	if b.sizes == nil {
		b.sizes = make(map[string]int64)
	}
	b.sizes[path] = size
	return size
}

// listEntriesLocked lists the entries currently on disk, measuring only the
// ones without a recorded size, and forgets entries that no longer exist.
func (b *ModuleCacheBudget) listEntriesLocked() (entries []cacheEntry, total int64) {
	present := make(map[string]bool, len(b.sizes))
	for _, sub := range cacheBudgetSubdirs {
		dir := filepath.Join(b.root, sub)
		items, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, item := range items {
			if !item.IsDir() {
				if info, infoErr := item.Info(); infoErr == nil {
					total += info.Size()
				}
				continue
			}
			if strings.HasPrefix(item.Name(), ".") {
				continue
			}
			path := filepath.Join(dir, item.Name())
			present[path] = true
			size := b.entrySizeLocked(path)
			total += size
			entries = append(entries, cacheEntry{path: path, size: size})
		}
	}
	for path := range b.sizes {
		if !present[path] && b.isTopLevelEntry(path) {
			delete(b.sizes, path)
		}
	}
	return entries, total
}

func (b *ModuleCacheBudget) isTopLevelEntry(path string) bool {
	parent := filepath.Dir(path)
	for _, sub := range cacheBudgetSubdirs {
		if parent == filepath.Join(b.root, sub) {
			return true
		}
	}
	return false
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

	entries, total := b.listEntriesLocked()
	if total <= b.maxBytes {
		b.evictOnUnpin = false
		return
	}
	for i := range entries {
		if info, err := os.Lstat(entries[i].path); err == nil {
			entries[i].modTime = info.ModTime()
		}
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
		delete(b.sizes, path)
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
