/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"github.com/zclconf/go-cty/cty"
)

// elementPair is one key and value of a collection.
type elementPair struct {
	key, value cty.Value
}

// equalValues reports whether a and b are equal as RawEquals does, without
// walking the collections they share the storage of.
//
// Evaluation passes compare what they rebuilt against the previous pass, and
// what they rebuild mostly wraps the same values: every instance of a for_each
// over a decoded configuration holds that configuration. RawEquals walks it and
// re-compares its type at every level, once per instance and pass.
func equalValues(a, b cty.Value) bool {
	return (*keyMemo)(nil).equal(a, b)
}

func (m *keyMemo) equal(a, b cty.Value) bool {
	if rawOnly(a, b) {
		return a.RawEquals(b)
	}
	ta, tb := a.Type(), b.Type()
	switch {
	case ta.IsObjectType() && tb.IsObjectType():
		return sharesStorage(a, b) || m.equalObjects(a, b)
	case ta.IsSetType() && tb.IsSetType():
		return sharesStorage(a, b) || m.equalSets(a, b)
	case sameCollectionKind(ta, tb):
		return sharesStorage(a, b) || m.equalElements(a, b)
	}
	return a.RawEquals(b)
}

// rawOnly reports whether a or b can only be compared by RawEquals: neither
// marked, unknown nor null values expose their elements.
func rawOnly(a, b cty.Value) bool {
	return a.IsMarked() || b.IsMarked() || !a.IsKnown() || !b.IsKnown() || a.IsNull() || b.IsNull()
}

func sameCollectionKind(ta, tb cty.Type) bool {
	return ta.IsTupleType() && tb.IsTupleType() ||
		ta.IsListType() && tb.IsListType() ||
		ta.IsMapType() && tb.IsMapType()
}

func (m *keyMemo) equalObjects(a, b cty.Value) bool {
	attrs, other := a.Type().AttributeTypes(), b.Type().AttributeTypes()
	if len(attrs) != len(other) {
		return false
	}
	for name := range attrs {
		if _, ok := other[name]; !ok || !m.equal(a.GetAttr(name), b.GetAttr(name)) {
			return false
		}
	}
	return true
}

// equalElements compares tuples, lists or maps of the same kind.
func (m *keyMemo) equalElements(a, b cty.Value) bool {
	if a.LengthInt() != b.LengthInt() {
		return false
	}
	if a.LengthInt() == 0 {
		// Only the element type tells empty lists and maps apart.
		return a.Type().Equals(b.Type())
	}
	for ia, ib := a.ElementIterator(), b.ElementIterator(); ia.Next() && ib.Next(); {
		ka, va := ia.Element()
		kb, vb := ib.Element()
		if !ka.RawEquals(kb) || !m.equal(va, vb) {
			return false
		}
	}
	return true
}

// equalSets compares sets element by element in their sorted order.
func (m *keyMemo) equalSets(a, b cty.Value) bool {
	sa, sb := m.setElements(a), m.setElements(b)
	if len(sa) != len(sb) {
		return false
	}
	if len(sa) == 0 {
		return a.Type().Equals(b.Type())
	}
	for i := range sa {
		if !m.equalElement(sa[i].value, sb[i].value) {
			return false
		}
	}
	return true
}

// equalElement compares one set element. A known, non-null primitive compares
// without a walk; anything else may be unknown, null or marked, which the
// primitive accessors panic on.
func (m *keyMemo) equalElement(a, b cty.Value) bool {
	ta := a.Type()
	if rawOnly(a, b) || !ta.IsPrimitiveType() || !ta.Equals(b.Type()) {
		return m.equal(a, b)
	}
	switch ta {
	case cty.String:
		return a.AsString() == b.AsString()
	case cty.Number:
		// Cmp treats 0.1 at two precisions as equal. cty compares the integer
		// or the decimal text, and a pass stops when this comparison matches.
		return a.RawEquals(b)
	case cty.Bool:
		return a.True() == b.True()
	}
	return a.RawEquals(b)
}

// setElements returns a set's elements in ElementIterator order, sorted once
// per set the memo holds. Counted sets hold at most keyMemoPairsCap elements.
// Two sets over that cap stay cached, so comparing them does not sort either
// again. Remembering a set never drops a collection digest.
func (m *keyMemo) setElements(v cty.Value) []elementPair {
	id, ok := collectionIdentity(v)
	memoize := ok && m != nil && id.n > 0
	if memoize {
		if pairs, hit := m.cachedSet(id); hit {
			return pairs
		}
	}
	pairs := make([]elementPair, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		k, val := it.Element()
		pairs = append(pairs, elementPair{k, val})
	}
	if !memoize {
		return pairs
	}
	// A set rebuilt every pass has a new identity, so it is recorded once and
	// never kept. The second sight of a stable set is the one worth storing.
	if _, seen := m.seenSets[id]; !seen {
		m.rememberSeen(id, v)
		return pairs
	}
	delete(m.seenSets, id)
	m.rememberSet(id, v, pairs)
	return pairs
}

// rememberSeen records a set sorted once, in the slot of the oldest record
// once keyMemoSeenSetsCap are recorded. A slot whose id was since stored or
// recorded again in another slot holds nothing to drop.
func (m *keyMemo) rememberSeen(id collectionID, v cty.Value) {
	if m.seenSets == nil {
		m.seenSets = make(map[collectionID]seenSet)
	}
	slot := len(m.seenOrder)
	if slot < keyMemoSeenSetsCap {
		m.seenOrder = append(m.seenOrder, id)
	} else {
		slot = m.seenNext
		m.seenNext = (slot + 1) % keyMemoSeenSetsCap
		if old, ok := m.seenSets[m.seenOrder[slot]]; ok && old.slot == slot {
			delete(m.seenSets, m.seenOrder[slot])
		}
		m.seenOrder[slot] = id
	}
	m.seenSets[id] = seenSet{value: v, slot: slot}
}

func (m *keyMemo) cachedSet(id collectionID) ([]elementPair, bool) {
	if e, hit := m.sets[id]; hit {
		return e.pairs, true
	}
	for i := range m.oversized {
		if m.oversized[i].used && m.oversized[i].id == id {
			return m.oversized[i].entry.pairs, true
		}
	}
	return nil, false
}

func (m *keyMemo) rememberSet(id collectionID, v cty.Value, pairs []elementPair) {
	entry := setMemoEntry{value: v, pairs: pairs}
	if len(pairs) > keyMemoPairsCap {
		m.rememberOversized(id, entry)
		return
	}
	if m.pairs+len(pairs) > keyMemoPairsCap {
		return
	}
	if m.sets == nil {
		m.sets = make(map[collectionID]setMemoEntry)
	}
	m.sets[id] = entry
	m.pairs += len(pairs)
}

func (m *keyMemo) rememberOversized(id collectionID, entry setMemoEntry) {
	for i := range m.oversized {
		if m.oversized[i].used && m.oversized[i].id == id {
			m.oversized[i].entry = entry
			return
		}
	}
	slot := m.oversizedNext
	m.oversized[slot] = oversizedSet{id: id, entry: entry, used: true}
	m.oversizedNext = (slot + 1) % len(m.oversized)
}

// forEachElements walks a for_each collection, a set through the evaluator's
// key memo.
func (e *Evaluator) forEachElements(v cty.Value) func() (cty.Value, cty.Value, bool) {
	if v.Type().IsSetType() {
		pairs := e.keyMemo.setElements(v)
		i := 0
		return func() (cty.Value, cty.Value, bool) {
			if i >= len(pairs) {
				return cty.NilVal, cty.NilVal, false
			}
			el := pairs[i]
			i++
			return el.key, el.value, true
		}
	}
	it := v.ElementIterator()
	return func() (cty.Value, cty.Value, bool) {
		if !it.Next() {
			return cty.NilVal, cty.NilVal, false
		}
		k, val := it.Element()
		return k, val, true
	}
}

// sharesStorage reports whether a and b hold their elements in the same
// storage. cty values are immutable and derive their element types from those
// elements, so the same non-empty storage under the same kind of type means
// the same value.
func sharesStorage(a, b cty.Value) bool {
	ida, ok := collectionIdentity(a)
	if !ok || ida.n == 0 {
		return false
	}
	idb, ok := collectionIdentity(b)
	return ok && ida == idb
}
