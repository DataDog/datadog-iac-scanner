/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// compactVirtualCache is a topdown.VirtualCache holding the same entries as
// OPA's own, keyed by the whole reference rather than by a trie of its terms.
// OPA's builds a node with a hash map of its own for every term of every
// reference it caches, so a rule calling a function once per resource, with
// each resource as an argument, holds several maps per call. This holds one
// entry.
type compactVirtualCache struct {
	frames []virtualCacheFrame
}

// virtualCacheFrame is the cache of one evaluation frame: entries by the hash
// of their reference, equal-hashed references in turn.
type virtualCacheFrame map[int][]virtualCacheEntry

type virtualCacheEntry struct {
	ref       ast.Ref
	value     *ast.Term
	undefined bool
}

var _ topdown.VirtualCache = (*compactVirtualCache)(nil)

func newCompactVirtualCache() *compactVirtualCache {
	c := &compactVirtualCache{}
	c.Push()
	return c
}

func (c *compactVirtualCache) Push() {
	c.frames = append(c.frames, virtualCacheFrame{})
}

func (c *compactVirtualCache) Pop() {
	c.frames = c.frames[:len(c.frames)-1]
}

func (c *compactVirtualCache) top() virtualCacheFrame {
	return c.frames[len(c.frames)-1]
}

// refHash hashes a reference by the values of its terms, as the terms of
// OPA's cache are compared.
func refHash(ref ast.Ref) int {
	h := 0
	for _, term := range ref {
		h = h*31 + term.Value.Hash()
	}
	return h
}

// sameRef reports whether a and b are the same reference, by the values of
// their terms.
func sameRef(a, b ast.Ref) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !ast.TermValueEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// Get returns, as OPA's cache does: nil and true for a reference cached as
// undefined, its value and false for one cached as defined, and nil and false
// for one not cached.
func (c *compactVirtualCache) Get(ref ast.Ref) (*ast.Term, bool) {
	for _, e := range c.top()[refHash(ref)] {
		if sameRef(e.ref, ref) {
			if e.undefined {
				return nil, true
			}
			return e.value, false
		}
	}
	return nil, false
}

// Put caches value for ref, a nil value caching ref as undefined. Like OPA's
// cache, a defined value is kept once a reference is cached as undefined.
func (c *compactVirtualCache) Put(ref ast.Ref, value *ast.Term) {
	frame := c.top()
	h := refHash(ref)
	entries := frame[h]
	for i := range entries {
		if sameRef(entries[i].ref, ref) {
			if value != nil {
				entries[i].value = value
			} else {
				entries[i].undefined = true
			}
			return
		}
	}
	// The reference is copied: a caller may reuse the slice it passed. Its
	// terms are kept, as OPA's cache keeps them.
	e := virtualCacheEntry{ref: append(ast.Ref(nil), ref...), value: value, undefined: value == nil}
	frame[h] = append(entries, e)
}

// Keys returns the references cached with a value in the active frame.
func (c *compactVirtualCache) Keys() []ast.Ref {
	var keys []ast.Ref
	for _, entries := range c.top() {
		for _, e := range entries {
			if e.value != nil {
				keys = append(keys, e.ref)
			}
		}
	}
	return keys
}
