/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"encoding/binary"
	"hash/maphash"
	"reflect"
	"sort"
	"strconv"
	"strings"

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
	inputs      inputsDigest
}

// evalCacheEntry holds the result of a completed module evaluation.
// visitedDirs is the set of child dirs that were added to allVisited *inside* this
// evaluation (not including the module dir itself, which is tracked by the caller).
//
// The resources are not held by the entry: they are the range [start, end) of
// the result the evaluation appended them to, which outlives the entry. An
// entry costs the same whatever the size of the subtree it stands for.
//
// baseAddr and baseChainLen record the position the entry was first evaluated at,
// so a caller reaching the same module by another path can rewrite the recorded
// address and chain onto the result. Outputs need no rewrite because rootDir is
// part of the cache key.
type evalCacheEntry struct {
	result     *[]ResolvedResource
	start, end int
	// instances are the module calls evaluated inside this evaluation.
	instances    []ModuleInstance
	outputs      map[string]cty.Value
	visitedDirs  []string
	baseAddr     string
	baseChainLen int
}

// appendRebased appends to out the cached resources as they would have been
// recorded had the module been evaluated at addr/chain instead of the
// position it was first evaluated at.
//
// Attributes and Body are shared rather than copied. They are the expensive part
// of a resolved resource and they are identical for identical inputs, so sharing
// them is what makes reuse cheap; both are treated as read-only after evaluation.
// Every resource of one module instance shares its chain and address, so each
// distinct one is rebased once.
func (entry *evalCacheEntry) appendRebased(out *[]ResolvedResource, addr string, chain []CallSite) {
	cached := (*entry.result)[entry.start:entry.end]
	if entry.baseAddr == addr && entry.baseChainLen == len(chain) {
		*out = append(*out, cached...)
		return
	}
	type chainID struct {
		first *CallSite
		n     int
	}
	chains := map[chainID][]CallSite{}
	addrs := map[string]string{}
	for i := range cached {
		r := cached[i]
		rebased, ok := addrs[r.ModuleAddress]
		if !ok {
			rebased = rebaseAddr(r.ModuleAddress, entry.baseAddr, addr)
			addrs[r.ModuleAddress] = rebased
		}
		r.ModuleAddress = rebased
		var id chainID
		if len(r.CallChain) > 0 {
			id = chainID{&r.CallChain[0], len(r.CallChain)}
		}
		rebasedChain, ok := chains[id]
		if !ok {
			rebasedChain = rebaseChain(r.CallChain, entry.baseChainLen, chain)
			chains[id] = rebasedChain
		}
		r.CallChain = rebasedChain
		*out = append(*out, r)
	}
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

// inputsDigest identifies a resolved input map by two independent 64-bit digests
// of its canonical encoding. A single digest could collide and silently reuse
// one module's evaluation for different inputs.
type inputsDigest struct{ a, b uint64 }

// keyMemo memoizes digests of large collections for one evaluator. The same
// decoded configuration is handed to every instance of a module loop, and cty
// shares the collection's storage across those copies. Each entry keeps the
// value so that storage cannot be reused under the same identity.
type keyMemo struct {
	entries map[collectionID]keyMemoEntry
}

type keyMemoEntry struct {
	value  cty.Value
	digest inputsDigest
}

// inputsKey returns a stable digest of a set of resolved module inputs.
// Map keys are sorted. The encoding is streamed into the digest rather than
// retained: the key of every evaluation is kept until the root is merged, and
// a module input can be a decoded configuration passed to every instance.
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
		m.writeValue(w, inputs[k], true)
		w.WriteString("\n")
	}
	return w.digest()
}

// keySink receives a key encoding.
type keySink interface{ WriteString(string) }

// The seeds stay secret for the process. Inputs come from the repository, and a
// fixed hash would let a crafted payload collide and reuse another evaluation.
var keySeedA, keySeedB = maphash.MakeSeed(), maphash.MakeSeed()

// keyWriter streams a key encoding into two independent digests.
type keyWriter struct{ a, b maphash.Hash }

func newKeyWriter() *keyWriter {
	w := &keyWriter{}
	w.a.SetSeed(keySeedA)
	w.b.SetSeed(keySeedB)
	return w
}

func (w *keyWriter) WriteString(s string) {
	_, _ = w.a.WriteString(s)
	_, _ = w.b.WriteString(s)
}

func (w *keyWriter) digest() inputsDigest { return inputsDigest{a: w.a.Sum64(), b: w.b.Sum64()} }

// writeValue encodes v for a cache key. The null check must precede the known
// check because null values are also considered known. All DynamicPseudoType
// values are unknown (IsKnown()==false), so they are handled by the unknown
// branch and the DynamicPseudoType case never needs a special guard.
func (m *keyMemo) writeValue(w keySink, v cty.Value, digestCollection bool) {
	if v.IsNull() {
		// Include the type so cty.NullVal(cty.String) and cty.NullVal(cty.Number)
		// do not collide.
		w.WriteString("null(")
		writeType(w, v.Type())
		w.WriteString(")")
		return
	}
	if !v.IsKnown() {
		w.WriteString("?")
		writeType(w, v.Type())
		return
	}
	// Walk collections instead of cty/json: JSON collapses list/set and map/object
	// to the same shape, including nested wholly-known values inside partial keys.
	if isCollectionOrStructural(v.Type()) {
		if digestCollection {
			d := m.collectionDigest(v)
			var buf [16]byte
			binary.LittleEndian.PutUint64(buf[:8], d.a)
			binary.LittleEndian.PutUint64(buf[8:], d.b)
			w.WriteString("\x00")
			w.WriteString(string(buf[:]))
			return
		}
		m.writeCollection(w, v)
		return
	}
	data, err := ctyjson.Marshal(v, v.Type())
	if err != nil {
		if v.Type() == cty.Number {
			w.WriteString("number(")
			w.WriteString(v.AsBigFloat().Text('g', -1))
			w.WriteString(")")
			return
		}
		w.WriteString("marshal-error(")
		writeType(w, v.Type())
		w.WriteString(")")
		return
	}
	w.WriteString(string(data))
}

func (m *keyMemo) writeCollection(w keySink, v cty.Value) {
	t := v.Type()
	writeType(w, t)
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
		m.writeValue(w, elem, false)
		w.WriteString(",")
	}
	w.WriteString(closing)
}

// collectionDigest is the digest of a collection's own encoding, memoized by
// the identity of the collection's storage.
func (m *keyMemo) collectionDigest(v cty.Value) inputsDigest {
	id, ok := collectionIdentity(v)
	// Empty slices of different types can share one runtime pointer, so their
	// identity is not safe to reuse. They are cheap to encode directly.
	memoize := ok && m != nil && id.n > 0
	if memoize {
		if e, hit := m.entries[id]; hit {
			return e.digest
		}
	}
	w := newKeyWriter()
	m.writeCollection(w, v)
	d := w.digest()
	if memoize {
		if m.entries == nil {
			m.entries = make(map[collectionID]keyMemoEntry)
		}
		m.entries[id] = keyMemoEntry{value: v, digest: d}
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
	rv := reflect.ValueOf(&v).Elem().FieldByName("v")
	if !rv.IsValid() || (rv.Kind() == reflect.Interface && rv.IsNil()) {
		return collectionID{}, false
	}
	if rv.Kind() == reflect.Interface {
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

// writeType encodes a type without collapsing every object to "object" or
// every tuple to "tuple". Attribute and element order is stable.
func writeType(w keySink, t cty.Type) {
	switch {
	case t.IsObjectType():
		attrs := t.AttributeTypes()
		names := make([]string, 0, len(attrs))
		for name := range attrs {
			names = append(names, name)
		}
		sort.Strings(names)
		optional := t.OptionalAttributes()
		w.WriteString("object{")
		for _, name := range names {
			w.WriteString(strconv.Quote(name))
			w.WriteString(":")
			writeType(w, attrs[name])
			if _, ok := optional[name]; ok {
				w.WriteString("?")
			}
			w.WriteString(",")
		}
		w.WriteString("}")
	case t.IsTupleType():
		w.WriteString("tuple[")
		for _, elem := range t.TupleElementTypes() {
			writeType(w, elem)
			w.WriteString(",")
		}
		w.WriteString("]")
	case t.IsListType():
		w.WriteString("list of ")
		writeType(w, t.ElementType())
	case t.IsSetType():
		w.WriteString("set of ")
		writeType(w, t.ElementType())
	case t.IsMapType():
		w.WriteString("map of ")
		writeType(w, t.ElementType())
	default:
		w.WriteString(t.FriendlyName())
	}
}

func isCollectionOrStructural(t cty.Type) bool {
	return t.IsListType() || t.IsSetType() || t.IsTupleType() || t.IsMapType() || t.IsObjectType()
}
