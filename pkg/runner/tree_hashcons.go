/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"reflect"
	"sort"
	"strconv"
)

// treeConsKey is a 128-bit content key for hash-consing parsed document trees.
type treeConsKey [2]uint64

var treeConsBase = treeConsKey{1469598103934665603, 2166136261}

func (k treeConsKey) mix(x treeConsKey) treeConsKey {
	k[0] = (k[0] ^ x[0]) * 1099511628211
	k[1] = (k[1]<<7 ^ x[1]>>57) + x[0]*0x9E3779B97F4A7C15
	return k
}

func (k treeConsKey) mixString(s string) treeConsKey {
	for i := 0; i < len(s); i++ {
		k[0] = (k[0] ^ uint64(s[i])) * 1099511628211
		k[1] = (k[1] ^ uint64(s[i])) * 309485009
	}
	return k
}

// mixScalar mixes a canonical scalar into k; ok is false for any other type.
func (k treeConsKey) mixScalar(v interface{}) (key treeConsKey, ok bool) {
	switch t := v.(type) {
	case string:
		return k.mixString(t), true
	case bool:
		if t {
			return k.mixString("\x01"), true
		}
		return k.mixString("\x00"), true
	case nil:
		return k.mixString("\x02"), true
	case float64:
		// float64 is the only other scalar in canonical documents (see
		// normalizeDocumentValue).
		return k.mixString(strconv.FormatFloat(t, 'g', -1, 64)), true
	default:
		return k, false
	}
}

// treeHashCons canonicalizes structurally identical subtrees of sanitized
// documents: manifest corpora repeat the same label blocks, container specs and
// CRD skeletons across nearly every file (92% of container nodes on
// community-operators), so sharing each unique subtree collapses the tree heap.
// Children are consed bottom-up with the parent key mixed from the children's
// canonical keys (linear hashing); equality is verified shallowly by child
// pointers. Consed trees are read-only downstream — the one in-place mutator
// (module instantiation) only runs on Terraform, which is never consed — and the
// top-level map is not interned (Combine inserts id/file). Per-Service,
// cleared after prepare (ClearTreeCons).
//
// Subtrees holding a non-canonical value (e.g. parser-attached structs) can
// never compare equal, so they are recorded in opaque instead of a content
// bucket: registering them would pile every same-shaped subtree into one
// bucket that each insert scans linearly.
type treeHashCons struct {
	byContent map[treeConsKey][]interface{}
	hashes    map[uintptr]treeConsKey
	opaque    map[uintptr]struct{}
}

func newTreeHashCons() *treeHashCons {
	return &treeHashCons{
		byContent: make(map[treeConsKey][]interface{}),
		hashes:    make(map[uintptr]treeConsKey),
		opaque:    make(map[uintptr]struct{}),
	}
}

// visited reports whether the container at ptr was already consed.
func (cons *treeHashCons) visited(ptr uintptr) bool {
	if _, ok := cons.hashes[ptr]; ok {
		return true
	}
	_, ok := cons.opaque[ptr]
	return ok
}

// consChildren canonicalizes every child of the document's top-level map and
// returns the same map (with canonical children). The top-level itself is
// not interned: Combine later inserts per-file id/file keys into it.
func (cons *treeHashCons) consChildren(doc map[string]interface{}) map[string]interface{} {
	for k, child := range doc {
		doc[k] = cons.cons(child)
	}
	return doc
}

// cons canonicalizes a sanitized document subtree bottom-up, mutating the
// source to reference canonical children, and returns the canonical instance.
func (cons *treeHashCons) cons(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		ptr := reflect.ValueOf(t).Pointer()
		if cons.visited(ptr) {
			return t
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		key := treeConsBase
		shareable := true
		for _, k := range keys {
			consed := cons.cons(t[k])
			t[k] = consed
			h, ok := cons.hashOf(consed)
			shareable = shareable && ok
			key = key.mixString(k).mix(h)
		}
		if !shareable {
			cons.opaque[ptr] = struct{}{}
			return t
		}
		return cons.canonicalizeMap(key, t)
	case []interface{}:
		ptr := reflect.ValueOf(t).Pointer()
		if cons.visited(ptr) {
			return t
		}
		key := treeConsBase
		shareable := true
		for i := range t {
			consed := cons.cons(t[i])
			t[i] = consed
			h, ok := cons.hashOf(consed)
			shareable = shareable && ok
			key = key.mix(h)
		}
		if !shareable {
			cons.opaque[ptr] = struct{}{}
			return t
		}
		return cons.canonicalizeSlice(key, t)
	default:
		return v
	}
}

// hashOf returns the content key of an already-consed value; ok is false when
// the value is (or contains) a non-canonical value and so is never shared.
func (cons *treeHashCons) hashOf(v interface{}) (treeConsKey, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		h, ok := cons.hashes[reflect.ValueOf(t).Pointer()]
		return h, ok
	case []interface{}:
		h, ok := cons.hashes[reflect.ValueOf(t).Pointer()]
		return h, ok
	default:
		return treeConsBase.mixScalar(v)
	}
}

// canonicalizeMap returns the stored twin for a content key when the
// candidate is equal — verified by comparing key sets and canonical child
// pointers, which is shallow — or registers the map as canonical.
func (cons *treeHashCons) canonicalizeMap(key treeConsKey, v map[string]interface{}) interface{} {
	for _, existing := range cons.byContent[key] {
		if e, ok := existing.(map[string]interface{}); ok && sameCanonicalMap(e, v) {
			return e
		}
	}
	cons.byContent[key] = append(cons.byContent[key], v)
	cons.hashes[reflect.ValueOf(v).Pointer()] = key
	return v
}

func (cons *treeHashCons) canonicalizeSlice(key treeConsKey, v []interface{}) interface{} {
	for _, existing := range cons.byContent[key] {
		if e, ok := existing.([]interface{}); ok && sameCanonicalSlice(e, v) {
			return e
		}
	}
	cons.byContent[key] = append(cons.byContent[key], v)
	cons.hashes[reflect.ValueOf(v).Pointer()] = key
	return v
}

// sameCanonicalMap reports whether two maps with canonical children are
// equal, by key set and child identity.
func sameCanonicalMap(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !sameCanonicalValue(av, bv) {
			return false
		}
	}
	return true
}

func sameCanonicalSlice(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameCanonicalValue(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameCanonicalValue(a, b interface{}) bool {
	switch av := a.(type) {
	case map[string]interface{}:
		bv, ok := b.(map[string]interface{})
		return ok && reflect.ValueOf(av).Pointer() == reflect.ValueOf(bv).Pointer()
	case []interface{}:
		bv, ok := b.([]interface{})
		return ok && reflect.ValueOf(av).Pointer() == reflect.ValueOf(bv).Pointer()
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case nil:
		return b == nil
	default:
		// Non-canonical types never share: == can panic on uncomparable types.
		return false
	}
}
