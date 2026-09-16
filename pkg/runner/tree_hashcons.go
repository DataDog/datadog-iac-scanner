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

func (k treeConsKey) mixScalar(v interface{}) treeConsKey {
	switch t := v.(type) {
	case string:
		return k.mixString(t)
	case bool:
		if t {
			return k.mixString("\x01")
		}
		return k.mixString("\x00")
	case nil:
		return k.mixString("\x02")
	case float64:
		// float64 is the only other scalar in canonical documents (see
		// normalizeDocumentValue).
		return k.mixString(strconv.FormatFloat(t, 'g', -1, 64))
	default:
		// Non-canonical types (e.g. the CICD parser's ParsedExpression
		// structs) contribute only their type to the key: their values may be
		// uncomparable, so they are never shared — parents containing distinct
		// values of such a type compare as unequal in sameCanonicalValue and
		// stay unshared, which is safe, merely less deduplication.
		return k.mixString("\xff" + reflect.TypeOf(v).String())
	}
}

// treeHashCons canonicalizes structurally identical subtrees of sanitized
// documents. Parsed manifest corpora repeat the same label blocks, container
// specs and CRD skeletons across nearly every file — 92% of container nodes
// on community-operators are structural duplicates — so building each unique
// subtree once and sharing it collapses the retained tree heap several-fold.
//
// Children are consed bottom-up and each parent's content key is mixed from
// its children's canonical keys, so hashing is linear. Because children are
// canonical, equality of a candidate against a stored entry can be verified
// by comparing child pointers (shallow), never by deep traversal.
//
// The consed trees are read-only downstream: they flow into FileMetadata
// documents, the shared-parse cache and the OPA payload, none of which
// mutate nested children (module instantiation, the one in-place mutator,
// only runs on Terraform documents, which are never consed). The top-level
// document map is deliberately NOT interned because Combine inserts each
// file's id/file into it.
//
// The interner is per-Service and capped; it is cleared after the prepare
// phase (Service.ClearTreeCons) — nothing is consed afterwards, and dropping
// the maps keeps their overhead (which can reach tens of MB on large
// corpora) out of the memory-intensive eval phase. The shared trees stay
// alive via each FileMetadata's document copy.
type treeHashCons struct {
	byContent map[treeConsKey][]interface{}
	hashes    map[uintptr]treeConsKey
	entries   int
}

// treeConsMaxEntries bounds the interner for adversarial inputs; above the
// cap, consing stops and subtrees stay unshared.
const treeConsMaxEntries = 4 << 20 // ~4M distinct containers

func newTreeHashCons() *treeHashCons {
	return &treeHashCons{
		byContent: make(map[treeConsKey][]interface{}),
		hashes:    make(map[uintptr]treeConsKey),
	}
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
	if cons.entries >= treeConsMaxEntries {
		return v
	}
	switch t := v.(type) {
	case map[string]interface{}:
		ptr := reflect.ValueOf(t).Pointer()
		if _, ok := cons.hashes[ptr]; ok {
			return t // already canonical
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		key := treeConsBase
		for _, k := range keys {
			consed := cons.cons(t[k])
			t[k] = consed
			key = key.mixString(k).mix(cons.hashOf(consed))
		}
		return cons.canonicalizeMap(key, t)
	case []interface{}:
		ptr := reflect.ValueOf(t).Pointer()
		if _, ok := cons.hashes[ptr]; ok {
			return t
		}
		key := treeConsBase
		for i := range t {
			consed := cons.cons(t[i])
			t[i] = consed
			key = key.mix(cons.hashOf(consed))
		}
		return cons.canonicalizeSlice(key, t)
	default:
		return v
	}
}

// hashOf returns the content key of an already-consed value.
func (cons *treeHashCons) hashOf(v interface{}) treeConsKey {
	switch t := v.(type) {
	case map[string]interface{}:
		return cons.hashes[reflect.ValueOf(t).Pointer()]
	case []interface{}:
		return cons.hashes[reflect.ValueOf(t).Pointer()]
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
	if cons.entries < treeConsMaxEntries {
		cons.byContent[key] = append(cons.byContent[key], v)
		cons.entries++
		cons.hashes[reflect.ValueOf(v).Pointer()] = key
	}
	return v
}

func (cons *treeHashCons) canonicalizeSlice(key treeConsKey, v []interface{}) interface{} {
	for _, existing := range cons.byContent[key] {
		if e, ok := existing.([]interface{}); ok && sameCanonicalSlice(e, v) {
			return e
		}
	}
	if cons.entries < treeConsMaxEntries {
		cons.byContent[key] = append(cons.byContent[key], v)
		cons.entries++
		cons.hashes[reflect.ValueOf(v).Pointer()] = key
	}
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
		// Non-canonical types are never equal here: comparing arbitrary
		// values with == panics on uncomparable types (structs holding
		// slices), and the type-only content key means parents holding them
		// simply do not share.
		return false
	}
}
