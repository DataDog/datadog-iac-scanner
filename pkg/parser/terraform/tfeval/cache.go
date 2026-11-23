/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"encoding/binary"
	"hash/maphash"
	"maps"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
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

// evalCacheEntry holds a module evaluation and its native effects. Entries with
// stoppedDirs or externalStops are partial and belong only to the current root's cache;
// the evaluator-wide cache contains completed entries only.
// visitedDirs is the complete set of directories evaluated below this module,
// independent of previously visited siblings. The caller tracks the module itself.
//
// baseAddr and baseChain record the position the entry was first evaluated at,
// so a caller reaching the same module by another path can rewrite the recorded
// address and chain onto the result. Outputs need no rewrite because rootDir is
// part of the cache key.
type evalCacheEntry struct {
	resources []ResolvedResource
	// instances are the module calls evaluated inside this evaluation.
	instances         []ModuleInstance
	outputs           map[string]cty.Value
	visitedDirs       []string
	baseAddr          string
	baseChain         []CallSite
	stoppedDirs       []string
	enteredIdentities []string
	externalStops     []string
}

// rebase returns the cached resources as they would have been recorded had the
// module been evaluated at addr/chain instead of the position it was first
// evaluated at.
//
// Attributes and Body are shared rather than copied. They are the expensive part
// of a resolved resource and they are identical for identical inputs, so sharing
// them is what makes reuse cheap; both are treated as read-only after evaluation.
func (entry *evalCacheEntry) rebase(addr string, chain []CallSite) []ResolvedResource {
	if entry.baseAddr == addr && sameCallChain(entry.baseChain, chain) {
		return entry.resources
	}
	out := make([]ResolvedResource, len(entry.resources))
	for i := range entry.resources {
		r := entry.resources[i]
		r.ModuleAddress = rebaseAddr(r.ModuleAddress, entry.baseAddr, addr)
		r.CallChain = rebaseChain(r.CallChain, len(entry.baseChain), chain)
		out[i] = r
	}
	return out
}

// rebaseInstances returns the cached module calls as they would have been
// recorded at addr/chain, sharing them when that is where they were recorded.
func (entry *evalCacheEntry) rebaseInstances(addr string, chain []CallSite) []ModuleInstance {
	if len(entry.instances) == 0 || (entry.baseAddr == addr && sameCallChain(entry.baseChain, chain)) {
		return entry.instances
	}
	out := make([]ModuleInstance, len(entry.instances))
	for i := range entry.instances {
		instance := entry.instances[i]
		instance.ModuleAddress = rebaseAddr(instance.ModuleAddress, entry.baseAddr, addr)
		instance.CallChain = rebaseChain(instance.CallChain, len(entry.baseChain), chain)
		out[i] = instance
	}
	return out
}

// sameCallChain includes the caller scopes: equal addresses and depths can
// belong to different parent evaluations after their sibling inputs refine.
func sameCallChain(first, second []CallSite) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		a, b := &first[i], &second[i]
		if a.ModuleName != b.ModuleName || a.Source != b.Source || a.Version != b.Version ||
			a.CalledFrom != b.CalledFrom || a.CalledLine != b.CalledLine || a.CalledEndLine != b.CalledEndLine ||
			a.CalledColumn != b.CalledColumn || a.CalledEndColumn != b.CalledEndColumn ||
			a.Body != b.Body || a.Caller != b.Caller || !a.InstanceKey.RawEquals(b.InstanceKey) {
			return false
		}
	}
	return true
}

// evaluationRun owns partial results for one recursive root evaluation.
// Reuse depends on the cycle decisions made by a subtree, not its exact callers.
// Native values may be reused between caller scopes; their call chains are rebound.
type evaluationRun struct {
	partial map[evalCacheKey][]partialEvalCacheEntry
	effects *evaluationEffects
}

type partialEvalCacheEntry struct {
	inputs map[string]cty.Value
	result *evalCacheEntry
}

func (r *evaluationRun) partialResult(key *evalCacheKey, inputs map[string]cty.Value, visiting map[string]bool) *evalCacheEntry {
	for _, entry := range r.partial[*key] {
		if !maps.EqualFunc(entry.inputs, inputs, cty.Value.RawEquals) {
			continue
		}
		compatible := true
		for _, dir := range entry.result.externalStops {
			if !visiting[dir] {
				compatible = false
				break
			}
		}
		if !compatible {
			continue
		}
		for _, dir := range entry.result.enteredIdentities {
			if visiting[dir] {
				compatible = false
				break
			}
		}
		if compatible {
			return entry.result
		}
	}
	return nil
}

func (r *evaluationRun) rememberPartial(key *evalCacheKey, inputs map[string]cty.Value, entry *evalCacheEntry) {
	if r.partial == nil {
		r.partial = make(map[evalCacheKey][]partialEvalCacheEntry)
	}
	r.partial[*key] = append(r.partial[*key], partialEvalCacheEntry{inputs: maps.Clone(inputs), result: entry})
}

// Each effects frame records a directory's initial global state on its first
// stop, even if a sibling or earlier root already marked that directory. This
// keeps repeated stops compact and lets speculative pre-passes roll back alone.
type evaluationEffects struct {
	parent  *evaluationEffects
	stops   map[string]bool
	entered map[string]bool
	blocked map[string]bool
}

func (f *evaluationEffects) recordDecision(dir string, blocked bool) {
	if blocked {
		if f.blocked == nil {
			f.blocked = make(map[string]bool)
		}
		f.blocked[dir] = true
	} else {
		if f.entered == nil {
			f.entered = make(map[string]bool)
		}
		f.entered[dir] = true
	}
}

func (r *evaluationRun) beginEffects() *evaluationEffects {
	frame := &evaluationEffects{parent: r.effects}
	r.effects = frame
	return frame
}

func (r *evaluationRun) recordStop(dir string, notEvaluated map[string]bool) {
	if r.effects.stops == nil {
		r.effects.stops = make(map[string]bool)
	}
	if _, seen := r.effects.stops[dir]; !seen {
		r.effects.stops[dir] = notEvaluated[dir]
	}
	notEvaluated[dir] = true
}

func (r *evaluationRun) finishEffects(frame *evaluationEffects, notEvaluated map[string]bool, commit bool) {
	r.effects = frame.parent
	// Pre-pass reporting effects roll back, but their cycle decisions can affect
	// published outputs. Keep those dependencies in the enclosing evaluation.
	if frame.parent != nil {
		for dir := range frame.entered {
			frame.parent.recordDecision(dir, false)
		}
		for dir := range frame.blocked {
			frame.parent.recordDecision(dir, true)
		}
	}
	if !commit {
		for dir, existed := range frame.stops {
			if !existed {
				delete(notEvaluated, dir)
			}
		}
		return
	}
	if frame.parent == nil || len(frame.stops) == 0 {
		return
	}
	if frame.parent.stops == nil {
		frame.parent.stops = make(map[string]bool)
	}
	for dir, existed := range frame.stops {
		if _, recorded := frame.parent.stops[dir]; !recorded {
			frame.parent.stops[dir] = existed
		}
	}
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
// A canceled ctx stops the encoding and ok comes back false: the caller then
// skips the cache. Marked values are also ineligible: their metadata must not
// be erased or treated as equivalent to an unmarked input. Values unsupported
// by the encoding are likewise evaluated without cache reuse.
func (m *keyMemo) inputsKey(ctx context.Context, inputs map[string]cty.Value) (key inputsDigest, ok bool) {
	if ctx.Err() != nil {
		return inputsDigest{}, false
	}
	if len(inputs) == 0 {
		return inputsDigest{}, true
	}
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w := newKeyWriter()
	for _, k := range keys {
		if ctx.Err() != nil {
			return inputsDigest{}, false
		}
		w.WriteString(k)
		w.WriteString("=")
		if !m.writeValue(ctx, w, inputs[k], true) {
			return inputsDigest{}, false
		}
		w.WriteString("\n")
	}
	return w.digest(), true
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
func (m *keyMemo) writeValue(ctx context.Context, w keySink, v cty.Value, digestCollection bool) bool {
	if ctx.Err() != nil || v.IsMarked() {
		return false
	}
	if v.IsNull() {
		// Include the type so cty.NullVal(cty.String) and cty.NullVal(cty.Number)
		// do not collide.
		w.WriteString("null(")
		if !writeType(w, v.Type()) {
			return false
		}
		w.WriteString(")")
		return true
	}
	if !v.IsKnown() {
		w.WriteString("?")
		return writeType(w, v.Type())
	}
	// Walk collections instead of cty/json: JSON collapses list/set and map/object
	// to the same shape, including nested wholly-known values inside partial keys.
	if isCollectionOrStructural(v.Type()) {
		if digestCollection {
			d, ok := m.collectionDigest(ctx, v)
			if !ok {
				return false
			}
			var buf [16]byte
			binary.LittleEndian.PutUint64(buf[:8], d.a)
			binary.LittleEndian.PutUint64(buf[8:], d.b)
			w.WriteString("\x00")
			w.WriteString(string(buf[:]))
			return true
		}
		return m.writeCollection(ctx, w, v)
	}
	if v.Type() == cty.Number {
		// Decimal formatting can scale with the exponent rather than the
		// stored value. The binary encoding also preserves precision and
		// signed zero: those affect arithmetic and formatting even when
		// cty considers two numbers equal. AsBigFloat returns an owned copy.
		encoded, err := v.AsBigFloat().GobEncode()
		if err != nil {
			return false
		}
		w.WriteString("number(")
		w.WriteString(strconv.Itoa(len(encoded)))
		w.WriteString(":")
		w.WriteString(string(encoded))
		w.WriteString(")")
		return true
	}
	switch v.Type() {
	case cty.Bool:
		w.WriteString(strconv.FormatBool(v.True()))
	case cty.String:
		w.WriteString(strconv.Quote(v.AsString()))
	default:
		// Capsule values may JSON-marshal like an ordinary primitive while
		// retaining different native semantics. They are not safe cache keys.
		return false
	}
	return true
}

func (m *keyMemo) writeCollection(ctx context.Context, w keySink, v cty.Value) bool {
	t := v.Type()
	if !writeType(w, t) {
		return false
	}
	open, closing := "[", "]"
	if t.IsObjectType() || t.IsMapType() {
		open, closing = "{", "}"
	}
	w.WriteString(open)
	// ElementIterator sorts map/object keys, so the encoding is insertion-order stable.
	for it := v.ElementIterator(); it.Next(); {
		if ctx.Err() != nil {
			return false
		}
		key, elem := it.Element()
		if t.IsObjectType() || t.IsMapType() {
			w.WriteString(strconv.Quote(key.AsString()))
			w.WriteString(":")
		}
		if !m.writeValue(ctx, w, elem, false) {
			return false
		}
		w.WriteString(",")
	}
	w.WriteString(closing)
	return true
}

// collectionDigest is the digest of a collection's own encoding, memoized by
// the identity of the collection's storage.
func (m *keyMemo) collectionDigest(ctx context.Context, v cty.Value) (inputsDigest, bool) {
	id, ok := collectionIdentity(v)
	// Empty slices of different types can share one runtime pointer, so their
	// identity is not safe to reuse. They are cheap to encode directly.
	memoize := ok && m != nil && id.n > 0
	if memoize {
		if e, hit := m.entries[id]; hit {
			return e.digest, true
		}
	}
	w := newKeyWriter()
	if !m.writeCollection(ctx, w, v) {
		return inputsDigest{}, false
	}
	d := w.digest()
	if memoize {
		if m.entries == nil {
			m.entries = make(map[collectionID]keyMemoEntry)
		}
		m.entries[id] = keyMemoEntry{value: v, digest: d}
	}
	return d, true
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
func writeType(w keySink, t cty.Type) bool {
	// A capsule's friendly name does not establish its native type identity.
	if t.IsCapsuleType() {
		return false
	}
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
			if !writeType(w, attrs[name]) {
				return false
			}
			if _, ok := optional[name]; ok {
				w.WriteString("?")
			}
			w.WriteString(",")
		}
		w.WriteString("}")
	case t.IsTupleType():
		w.WriteString("tuple[")
		for _, elem := range t.TupleElementTypes() {
			if !writeType(w, elem) {
				return false
			}
			w.WriteString(",")
		}
		w.WriteString("]")
	case t.IsListType():
		w.WriteString("list of ")
		return writeType(w, t.ElementType())
	case t.IsSetType():
		w.WriteString("set of ")
		return writeType(w, t.ElementType())
	case t.IsMapType():
		w.WriteString("map of ")
		return writeType(w, t.ElementType())
	default:
		w.WriteString(t.FriendlyName())
	}
	return true
}

func isCollectionOrStructural(t cty.Type) bool {
	return t.IsListType() || t.IsSetType() || t.IsTupleType() || t.IsMapType() || t.IsObjectType()
}
