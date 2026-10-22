/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"encoding/binary"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/cespare/xxhash/v2"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// evalCacheKey identifies a module evaluation by its filesystem context and inputs.
//
// The module address and call chain are deliberately absent. They describe where
// a module was called from, not what it evaluates to, so including them made a
// module reached by N distinct paths evaluate N times for identical results.
// rootDir remains because path.root can affect evaluated values. Callers re-stamp
// the address and chain onto cached results.
type evalCacheKey struct {
	dir         string
	rootDir     string
	packageRoot string
	inputs      inputsDigest // digest of the canonical encoding of the resolved input map
}

// evalCacheEntry holds the result of a completed module evaluation.
// visitedDirs is the set of child dirs that were added to allVisited *inside* this
// evaluation (not including the module dir itself, which is tracked by the caller).
//
// baseAddr and baseChainLen record the position the entry was first evaluated at,
// so a caller reaching the same module by another path can rewrite the recorded
// address and chain onto the result. Outputs need no rewrite because rootDir is
// part of the cache key.
type evalCacheEntry struct {
	resources []ResolvedResource
	// instances are the module calls evaluated inside this evaluation.
	instances    []ModuleInstance
	outputs      map[string]cty.Value
	visitedDirs  []string
	baseAddr     string
	baseChainLen int
	// evalDepth is the nesting depth this entry was evaluated at. A module cached
	// from a deeper call may have truncated descendants; shallower callers need a
	// fresh evaluation with more depth remaining.
	evalDepth int
}

// rebase returns the cached resources as they would have been recorded had the
// module been evaluated at addr/chain instead of the position it was first
// evaluated at.
//
// Attributes and Body are shared rather than copied. They are the expensive part
// of a resolved resource and they are identical for identical inputs, so sharing
// them is what makes reuse cheap; both are treated as read-only after evaluation.
func (entry *evalCacheEntry) rebase(addr string, chain []CallSite) []ResolvedResource {
	if entry.baseAddr == addr && entry.baseChainLen == len(chain) {
		return entry.resources
	}
	out := make([]ResolvedResource, len(entry.resources))
	for i := range entry.resources {
		r := entry.resources[i]
		r.ModuleAddress = rebaseAddr(r.ModuleAddress, entry.baseAddr, addr)
		r.CallChain = rebaseChain(r.CallChain, entry.baseChainLen, chain)
		out[i] = r
	}
	return out
}

// rebaseInstances returns the cached module calls as they would have been
// recorded at addr/chain, sharing them when that is where they were recorded.
func (entry *evalCacheEntry) rebaseInstances(addr string, chain []CallSite) []ModuleInstance {
	if len(entry.instances) == 0 || (entry.baseAddr == addr && entry.baseChainLen == len(chain)) {
		return entry.instances
	}
	out := make([]ModuleInstance, len(entry.instances))
	for i := range entry.instances {
		instance := entry.instances[i]
		instance.ModuleAddress = rebaseAddr(instance.ModuleAddress, entry.baseAddr, addr)
		instance.CallChain = rebaseChain(instance.CallChain, entry.baseChainLen, chain)
		out[i] = instance
	}
	return out
}

// rebaseAddr swaps the prefix a cached address was recorded under for the current
// one, keeping the part that describes position *within* the cached subtree.
func rebaseAddr(recorded, baseAddr, addr string) string {
	suffix := recorded
	if baseAddr != "" {
		suffix = strings.TrimPrefix(recorded, baseAddr)
		suffix = strings.TrimPrefix(suffix, ".")
	}
	if suffix == "" {
		return addr
	}
	return joinAddr(addr, suffix)
}

// rebaseChain replaces the leading hops a cached chain was recorded under with the
// current caller's hops, preserving the hops taken inside the cached subtree.
func rebaseChain(recorded []CallSite, baseLen int, chain []CallSite) []CallSite {
	if baseLen > len(recorded) {
		baseLen = len(recorded)
	}
	inner := recorded[baseLen:]
	if len(inner) == 0 {
		return cloneChain(chain)
	}
	out := make([]CallSite, 0, len(chain)+len(inner))
	out = append(out, chain...)
	out = append(out, inner...)
	return out
}

// inputsDigest identifies a resolved input map by two independent 64-bit
// digests of its canonical encoding, like docContentKey: a collision would
// silently reuse one module's evaluation for different inputs.
type inputsDigest struct{ a, b uint64 }

// keyMemo memoizes the digests of large collections for the root being
// evaluated. Inputs are passed down a module tree mostly unchanged, so one
// decoded configuration reaches every instance as the very same value; each
// entry holds that value so its storage cannot be freed and reused under the
// same identity while the entry exists. A nil memo memoizes nothing.
type keyMemo struct {
	entries map[collectionID]keyMemoEntry
}

type keyMemoEntry struct {
	value    cty.Value
	typeName string
	digest   inputsDigest
}

// inputsKey returns a stable digest of a set of resolved module inputs.
// Map keys are sorted; values are encoded by writeValue. The encoding is
// streamed into the digest rather than kept: a module input can be a large
// object, such as a decoded configuration file passed to every instance of a
// call, and the key of every evaluation is retained until its root is merged.
func (m *keyMemo) inputsKey(inputs map[string]cty.Value) inputsDigest {
	if len(inputs) == 0 {
		return inputsDigest{}
	}
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w := newKeyWriter()
	for _, k := range keys {
		w.WriteString(k)
		w.WriteString("=")
		m.writeValue(w, inputs[k])
		w.WriteString("\n")
	}
	return w.digest()
}

// keySink receives a key encoding.
type keySink interface{ WriteString(string) }

// keyWriter streams a key encoding into two independent digests.
type keyWriter struct{ a, b *xxhash.Digest }

func newKeyWriter() keyWriter {
	w := keyWriter{a: xxhash.New(), b: xxhash.New()}
	_, _ = w.b.WriteString("\x00tfeval-inputs\x00")
	return w
}

func (w keyWriter) WriteString(s string) {
	_, _ = w.a.WriteString(s)
	_, _ = w.b.WriteString(s)
}

func (w keyWriter) digest() inputsDigest { return inputsDigest{a: w.a.Sum64(), b: w.b.Sum64()} }

// digestedCollectionLen is the size from which a collection is encoded as the
// digest of its own encoding. Equal collections still encode equally, and the
// digest of a collection a scan passes around unchanged is computed once.
const digestedCollectionLen = 32

// writeValue encodes v for a cache key. The null check must precede the known
// check because null values are also considered known. All DynamicPseudoType
// values are unknown (IsKnown()==false), so they are handled by the unknown
// branch and the DynamicPseudoType case never needs a special guard.
func (m *keyMemo) writeValue(w keySink, v cty.Value) {
	if v.IsNull() {
		// Include the type so cty.NullVal(cty.String) and cty.NullVal(cty.Number)
		// do not collide.
		w.WriteString("null(" + v.Type().FriendlyName() + ")")
		return
	}
	if !v.IsKnown() {
		w.WriteString("?" + v.Type().FriendlyName())
		return
	}
	// Walk collections instead of cty/json: JSON collapses list/set and map/object
	// to the same shape, including nested wholly-known values inside partial keys.
	if isCollectionOrStructural(v.Type()) {
		if v.LengthInt() >= digestedCollectionLen {
			d := m.collectionDigest(v)
			var buf [17]byte
			binary.LittleEndian.PutUint64(buf[1:9], d.a)
			binary.LittleEndian.PutUint64(buf[9:], d.b)
			w.WriteString(string(buf[:]))
			return
		}
		m.writeCollection(w, v)
		return
	}
	if v.Type() == cty.Number {
		w.WriteString(ctyutil.NumberText(v))
		return
	}
	data, err := ctyjson.Marshal(v, v.Type())
	if err != nil {
		w.WriteString("?" + v.Type().FriendlyName())
		return
	}
	w.WriteString(string(data))
}

func (m *keyMemo) writeCollection(w keySink, v cty.Value) {
	t := v.Type()
	w.WriteString(t.FriendlyName())
	open, closing := "[", "]"
	if t.IsObjectType() || t.IsMapType() {
		open, closing = "{", "}"
	}
	w.WriteString(open)
	// ElementIterator sorts map/object keys, so the encoding is insertion-order stable.
	for it := v.ElementIterator(); it.Next(); {
		key, elem := it.Element()
		if t.IsObjectType() || t.IsMapType() {
			w.WriteString(strconv.Quote(key.AsString()))
			w.WriteString(":")
		}
		m.writeValue(w, elem)
		w.WriteString(",")
	}
	w.WriteString(closing)
}

// collectionDigest is the digest of a collection's own encoding, memoized by
// the identity of the collection's storage.
func (m *keyMemo) collectionDigest(v cty.Value) inputsDigest {
	id, ok := collectionIdentity(v)
	typeName := v.Type().FriendlyName()
	if ok && m != nil {
		if e, hit := m.entries[id]; hit && e.typeName == typeName {
			return e.digest
		}
	}
	w := newKeyWriter()
	m.writeCollection(w, v)
	d := w.digest()
	if ok && m != nil {
		if m.entries == nil {
			m.entries = make(map[collectionID]keyMemoEntry)
		}
		m.entries[id] = keyMemoEntry{value: v, typeName: typeName, digest: d}
	}
	return d
}

// collectionID identifies a collection value by the storage cty keeps it in.
type collectionID struct {
	ptr uintptr
	n   int
}

// collectionIdentity returns the identity of the map or slice holding a
// collection's elements. cty values are immutable and share that storage
// when they are copied, so the same identity means the same elements.
func collectionIdentity(v cty.Value) (collectionID, bool) {
	rv := reflect.ValueOf(v).FieldByName("v")
	if !rv.IsValid() {
		return collectionID{}, false
	}
	if rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return collectionID{}, false
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Map, reflect.Slice:
		if p := rv.Pointer(); p != 0 {
			return collectionID{ptr: p, n: rv.Len()}, true
		}
	}
	return collectionID{}, false
}

func isCollectionOrStructural(t cty.Type) bool {
	return t.IsListType() || t.IsSetType() || t.IsTupleType() || t.IsMapType() || t.IsObjectType()
}
