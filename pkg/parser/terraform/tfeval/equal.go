/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"github.com/zclconf/go-cty/cty"
)

// equalValues reports whether a and b are equal as RawEquals does, without
// walking the collections they share the storage of.
//
// Evaluation passes compare what they rebuilt against the previous pass, and
// what they rebuild mostly wraps the same values: every instance of a for_each
// over a decoded configuration holds that configuration. RawEquals walks it and
// re-compares its type at every level, once per instance and pass.
func equalValues(a, b cty.Value) bool {
	if a.IsMarked() || b.IsMarked() || !a.IsKnown() || !b.IsKnown() || a.IsNull() || b.IsNull() {
		return a.RawEquals(b)
	}
	ta, tb := a.Type(), b.Type()
	switch {
	case ta.IsObjectType() && tb.IsObjectType():
		return sharesStorage(a, b) || equalObjects(a, b)
	case ta.IsTupleType() && tb.IsTupleType(),
		ta.IsListType() && tb.IsListType(),
		ta.IsMapType() && tb.IsMapType():
		return sharesStorage(a, b) || equalElements(a, b)
	}
	return a.RawEquals(b)
}

func equalObjects(a, b cty.Value) bool {
	attrs, other := a.Type().AttributeTypes(), b.Type().AttributeTypes()
	if len(attrs) != len(other) {
		return false
	}
	for name := range attrs {
		if _, ok := other[name]; !ok || !equalValues(a.GetAttr(name), b.GetAttr(name)) {
			return false
		}
	}
	return true
}

// equalElements compares tuples, lists or maps of the same kind.
func equalElements(a, b cty.Value) bool {
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
		if !ka.RawEquals(kb) || !equalValues(va, vb) {
			return false
		}
	}
	return true
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
