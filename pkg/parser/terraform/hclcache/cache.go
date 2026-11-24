/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package hclcache provides a prepare-phase, bounded cache of parsed HCL syntax
// files shared across Terraform file parsing, variable/locals resolution, and
// local data-source parsing.
//
// Entries are keyed by (slash-normalized cleaned path, byte length, content
// xxhash64) so virtual filesystems, modified files, and mixed path separators
// never observe stale ASTs. Returned *hcl.File and hcl.Diagnostics values are
// shared across callers and must be treated as immutable. Callers invoke Close
// once source preparation finishes so evaluation phases (such as tfeval, which
// manages its own per-root directory cache) neither retain nor refill cached
// ASTs during peak-memory execution.
package hclcache

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cespare/xxhash/v2"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"golang.org/x/sync/singleflight"
)

// DefaultMaxSourceBytes bounds the total source bytes represented by cached
// HCL ASTs. Because an hclsyntax AST expands roughly 10-15x over raw source
// bytes, 1 MiB of source keeps the cache heap tightly bounded (~10-15 MiB)
// while eliminating redundant parses within the same directory during source
// preparation.
const (
	DefaultMaxSourceBytes = 1 << 20 // 1 MiB of HCL source
	maxSingleEntryDivisor = 4
	// Bound entry count too because empty and tiny files use AST memory without
	// consuming enough source bytes to meaningfully constrain the cache.
	minEntryBudgetBytes = 256
	evictSampleLimit    = 32
)

type ctxKey struct{}

// WithCache attaches cache to ctx so downstream Terraform parsers share it.
func WithCache(ctx context.Context, cache *Cache) context.Context {
	if cache == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, cache)
}

// FromContext returns the HCL parse cache on ctx, or nil if none.
func FromContext(ctx context.Context) *Cache {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(ctxKey{}).(*Cache)
	return c
}

// ParseConfig parses src as HCL native syntax, reusing a cached *hcl.File when
// ctx carries an open Cache and the (path, size, content hash) matches.
func ParseConfig(ctx context.Context, src []byte, filename string) (*hcl.File, hcl.Diagnostics) {
	if c := FromContext(ctx); c != nil {
		return c.ParseConfig(src, filename)
	}
	return hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
}

// Stats reports point-in-time cache counters and occupancy.
type Stats struct {
	Hits        int64
	Misses      int64
	Entries     int
	SourceBytes int
}

type cacheKey struct {
	path string
	size int
	hash uint64
}

type cacheEntry struct {
	key         cacheKey
	sourceBytes int
	hits        atomic.Int64
	file        *hcl.File
	diags       hcl.Diagnostics
}

// Cache memoizes immutable *hcl.File parses within a bounded source-byte budget.
type Cache struct {
	maxBytes   int
	maxEntries int
	closed     atomic.Bool
	hits       atomic.Int64
	misses     atomic.Int64

	mu         sync.RWMutex
	entries    map[cacheKey]*cacheEntry
	totalBytes int
	flight     singleflight.Group
}

// New creates a Cache bounded by maxSourceBytes (defaults to DefaultMaxSourceBytes).
func New(maxSourceBytes int) *Cache {
	if maxSourceBytes <= 0 {
		maxSourceBytes = DefaultMaxSourceBytes
	}
	maxEntries := maxSourceBytes / minEntryBudgetBytes
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &Cache{
		maxBytes:   maxSourceBytes,
		maxEntries: maxEntries,
		entries:    make(map[cacheKey]*cacheEntry),
	}
}

// ParseConfig returns a cached parse for (filename, len(src), hash(src)) or
// parses once. After Close is called, ParseConfig bypasses the cache without
// retaining ASTs.
func (c *Cache) ParseConfig(src []byte, filename string) (*hcl.File, hcl.Diagnostics) {
	if c == nil || c.closed.Load() {
		return hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	}
	cleanPath := filepath.ToSlash(filepath.Clean(filename))
	key := cacheKey{
		path: cleanPath,
		size: len(src),
		hash: xxhash.Sum64(src),
	}

	c.mu.RLock()
	if entry, ok := c.entries[key]; ok {
		entry.hits.Add(1)
		c.mu.RUnlock()
		c.hits.Add(1)
		return entry.file, entry.diags
	}
	c.mu.RUnlock()

	flightKey := cleanPath + "\x00" + strconv.Itoa(key.size) + "\x00" + strconv.FormatUint(key.hash, 16)
	parsed := false
	cacheHit := false
	v, _, _ := c.flight.Do(flightKey, func() (any, error) {
		// A caller can miss the first lookup, get descheduled, and enter
		// singleflight after the previous parse has already completed. Recheck
		// under the flight so that this gap does not trigger a duplicate parse.
		c.mu.RLock()
		if entry, ok := c.entries[key]; ok {
			entry.hits.Add(1)
			c.mu.RUnlock()
			cacheHit = true
			return entry, nil
		}
		c.mu.RUnlock()

		parsed = true
		file, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
		entry := &cacheEntry{
			key:         key,
			sourceBytes: len(src),
			file:        file,
			diags:       diags,
		}
		entry.hits.Store(1)
		c.store(entry)
		return entry, nil
	})
	entry := v.(*cacheEntry)
	if parsed {
		c.misses.Add(1)
	} else if cacheHit {
		c.hits.Add(1)
	} else {
		// This caller shared the in-flight result with another caller.
		entry.hits.Add(1)
		c.hits.Add(1)
	}
	return entry.file, entry.diags
}

func (c *Cache) store(entry *cacheEntry) {
	if c.closed.Load() || entry.sourceBytes > c.maxBytes/maxSingleEntryDivisor {
		// Never store after Close or let a single huge file evict shared entries.
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return
	}
	if _, exists := c.entries[entry.key]; exists {
		return
	}
	for (c.totalBytes+entry.sourceBytes > c.maxBytes || len(c.entries) >= c.maxEntries) && len(c.entries) > 0 {
		c.evictOneLocked()
	}
	c.entries[entry.key] = entry
	c.totalBytes += entry.sourceBytes
}

// evictOneLocked prefers evicting single-hit entries over multi-hit entries to
// preserve files reused across variable, local-data, and resource parses.
func (c *Cache) evictOneLocked() {
	var victim *cacheEntry
	checked := 0
	for _, e := range c.entries {
		if victim == nil || e.hits.Load() < victim.hits.Load() {
			victim = e
			if e.hits.Load() <= 1 {
				break
			}
		}
		checked++
		if checked >= evictSampleLimit {
			break
		}
	}
	if victim == nil {
		return
	}
	delete(c.entries, victim.key)
	c.totalBytes -= victim.sourceBytes
}

// Close clears all cached entries and permanently disables further caching so
// subsequent ParseConfig calls do not retain ASTs in memory.
func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.closed.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
	c.totalBytes = 0
}

// Len returns the number of cached file entries.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Stats returns point-in-time hit/miss counters and current occupancy.
func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.RLock()
	entries := len(c.entries)
	sourceBytes := c.totalBytes
	c.mu.RUnlock()
	return Stats{
		Hits:        c.hits.Load(),
		Misses:      c.misses.Load(),
		Entries:     entries,
		SourceBytes: sourceBytes,
	}
}
