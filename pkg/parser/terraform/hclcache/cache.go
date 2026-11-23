/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package hclcache shares parsed HCL native syntax trees across the phases of a
// Terraform scan (module discovery, legacy conversion, and tfeval) so each
// configuration file is lexed and parsed once instead of once per phase.
//
// Cached entries keep only the immutable *hclsyntax.Body (never duplicating raw
// file bytes) and are grouped by canonical directory so callers can evict roots
// in O(1) once evaluated and drop the entire cache before OPA payload build.
package hclcache

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/cespare/xxhash/v2"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"golang.org/x/sync/singleflight"
)

// DefaultMaxSourceBytes caps the total raw source bytes whose parsed ASTs a
// single scan cache retains at once (256 MiB of HCL source). Entries parsed
// while the cache is at its cap are returned uncached until ForgetDir or
// Release frees capacity, bounding live heap on pathological repositories.
const DefaultMaxSourceBytes int64 = 256 << 20

const sfKeyBase = 16

type contextKey struct{}

// Stats reports cache activity and live retention.
type Stats struct {
	Hits            int64
	Misses          int64
	BudgetSkips     int64
	Entries         int
	LiveSourceBytes int64
}

type fileEntry struct {
	length  int
	hash    uint64
	body    *hclsyntax.Body
	diags   hcl.Diagnostics
	charged int64
}

type parseResult struct {
	body  *hclsyntax.Body
	diags hcl.Diagnostics
}

// Cache memoizes *hclsyntax.Body parses for the lifetime of a scan.
// Returned *hclsyntax.Body trees are shared across callers and must be treated
// as read-only.
type Cache struct {
	mu           sync.RWMutex
	dirs         map[string]map[string]*fileEntry
	gen          uint64
	released     bool
	maxSrcBytes  int64
	liveSrcBytes int64
	sf           singleflight.Group

	hits        atomic.Int64
	misses      atomic.Int64
	budgetSkips atomic.Int64
}

// New creates a Cache with DefaultMaxSourceBytes retention budget.
func New() *Cache {
	return NewWithMaxSourceBytes(DefaultMaxSourceBytes)
}

// NewWithMaxSourceBytes creates a Cache retaining parsed bodies for at most
// maxBytes of raw HCL source at once. Non-positive values disable the cap.
func NewWithMaxSourceBytes(maxBytes int64) *Cache {
	return &Cache{
		maxSrcBytes: maxBytes,
	}
}

// WithCache attaches cache to ctx so Terraform scan phases share one parse cache.
func WithCache(ctx context.Context, cache *Cache) context.Context {
	if cache == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, cache)
}

// FromContext returns the scan-scoped Cache attached to ctx, or nil when none
// was configured.
func FromContext(ctx context.Context) *Cache {
	if ctx == nil {
		return nil
	}
	cache, _ := ctx.Value(contextKey{}).(*Cache)
	return cache
}

// ParseConfig parses native HCL bytes, reusing the scan-scoped Cache from ctx
// when present. When ctx carries no cache, it parses directly with path.
func ParseConfig(ctx context.Context, fsys vfs.FS, path string, src []byte) (*hclsyntax.Body, hcl.Diagnostics) {
	if cache := FromContext(ctx); cache != nil {
		return cache.ParseConfig(fsys, path, src)
	}
	return parseConfigUncached(src, path)
}

// ParseConfigString is ParseConfig for string content, avoiding a []byte copy
// on cache hits.
func ParseConfigString(ctx context.Context, fsys vfs.FS, path, src string) (*hclsyntax.Body, hcl.Diagnostics) {
	if cache := FromContext(ctx); cache != nil {
		return cache.ParseConfigString(fsys, path, src)
	}
	return parseConfigUncached([]byte(src), path)
}

// ParseConfig parses src for path, returning a cached *hclsyntax.Body when the
// canonical path and content fingerprint match.
func (c *Cache) ParseConfig(fsys vfs.FS, path string, src []byte) (*hclsyntax.Body, hcl.Diagnostics) {
	if c == nil || path == "" {
		return parseConfigUncached(src, path)
	}
	return c.parse(fsys, path, len(src), xxhash.Sum64(src), func() []byte { return src })
}

// ParseConfigString parses string content for path without copying to []byte
// on a cache hit.
func (c *Cache) ParseConfigString(fsys vfs.FS, path, src string) (*hclsyntax.Body, hcl.Diagnostics) {
	if c == nil || path == "" {
		return parseConfigUncached([]byte(src), path)
	}
	return c.parse(fsys, path, len(src), xxhash.Sum64String(src), func() []byte { return []byte(src) })
}

func (c *Cache) parse(
	fsys vfs.FS, path string, length int, hash uint64, bytesFn func() []byte,
) (*hclsyntax.Body, hcl.Diagnostics) {
	c.mu.RLock()
	released := c.released
	c.mu.RUnlock()
	if released {
		return parseConfigUncached(bytesFn(), canonicalPath(fsys, path))
	}

	canonical := canonicalPath(fsys, path)
	dir := filepath.Dir(canonical)

	if entry, ok := c.lookup(dir, canonical, length, hash); ok {
		c.hits.Add(1)
		return entry.body, entry.diags
	}

	sfKey := singleflightKey(canonical, length, hash)
	val, _, _ := c.sf.Do(sfKey, func() (any, error) {
		if entry, ok := c.lookup(dir, canonical, length, hash); ok {
			c.hits.Add(1)
			return parseResult{body: entry.body, diags: entry.diags}, nil
		}

		c.mu.RLock()
		startGen := c.gen
		isReleased := c.released
		c.mu.RUnlock()

		body, diags := parseConfigUncached(bytesFn(), canonical)
		if isReleased {
			return parseResult{body: body, diags: diags}, nil
		}
		c.misses.Add(1)
		c.store(startGen, dir, canonical, length, hash, body, diags)
		return parseResult{body: body, diags: diags}, nil
	})
	res := val.(parseResult)
	return res.body, res.diags
}

func (c *Cache) lookup(dir, canonical string, length int, hash uint64) (*fileEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.dirs == nil {
		return nil, false
	}
	files := c.dirs[dir]
	if files == nil {
		return nil, false
	}
	entry := files[canonical]
	if entry == nil || entry.length != length || entry.hash != hash {
		return nil, false
	}
	return entry, true
}

func (c *Cache) store(
	startGen uint64, dir, canonical string, length int, hash uint64,
	body *hclsyntax.Body, diags hcl.Diagnostics,
) {
	var charged int64
	if body != nil {
		charged = int64(length)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released || c.gen != startGen {
		return
	}

	var oldCharged int64
	if files := c.dirs[dir]; files != nil {
		if prev := files[canonical]; prev != nil {
			oldCharged = prev.charged
		}
	}

	if c.maxSrcBytes > 0 && charged > 0 && c.liveSrcBytes-oldCharged+charged > c.maxSrcBytes {
		c.budgetSkips.Add(1)
		return
	}

	if c.dirs == nil {
		c.dirs = make(map[string]map[string]*fileEntry)
	}
	files := c.dirs[dir]
	if files == nil {
		files = make(map[string]*fileEntry)
		c.dirs[dir] = files
	}
	files[canonical] = &fileEntry{
		length:  length,
		hash:    hash,
		body:    body,
		diags:   diags,
		charged: charged,
	}
	c.liveSrcBytes += charged - oldCharged
}

// ForgetDir drops all cached parses for files directly inside dir in O(1)
// relative to the total number of directories in the cache.
func (c *Cache) ForgetDir(fsys vfs.FS, dir string) {
	if c == nil || dir == "" {
		return
	}
	canonicalDir := canonicalPath(fsys, dir)

	c.mu.Lock()
	defer c.mu.Unlock()
	files := c.dirs[canonicalDir]
	if files == nil {
		return
	}
	for _, entry := range files {
		c.liveSrcBytes -= entry.charged
	}
	delete(c.dirs, canonicalDir)
}

// Release drops every cached parse, resets live byte accounting, and closes the
// cache so post-eval reparses do not retain new ASTs.
func (c *Cache) Release() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.dirs = nil
	c.liveSrcBytes = 0
	c.released = true
	c.gen++
	c.mu.Unlock()
}

// Stats returns a snapshot of cache hits, misses, and retained entries.
func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.RLock()
	entries := 0
	for _, files := range c.dirs {
		entries += len(files)
	}
	live := c.liveSrcBytes
	c.mu.RUnlock()
	return Stats{
		Hits:            c.hits.Load(),
		Misses:          c.misses.Load(),
		BudgetSkips:     c.budgetSkips.Load(),
		Entries:         entries,
		LiveSourceBytes: live,
	}
}

func parseConfigUncached(src []byte, filename string) (*hclsyntax.Body, hcl.Diagnostics) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() || file == nil {
		return nil, diags
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, diags
	}
	return body, diags
}

func canonicalPath(fsys vfs.FS, path string) string {
	if fsys != nil {
		if abs, err := fsys.Abs(path); err == nil {
			return filepath.Clean(abs)
		}
	}
	return filepath.Clean(path)
}

func singleflightKey(canonical string, length int, hash uint64) string {
	return canonical + "\x00" + strconv.Itoa(length) + "\x00" + strconv.FormatUint(hash, sfKeyBase)
}
