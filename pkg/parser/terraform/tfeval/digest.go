package tfeval

import (
	"encoding/json"
	"fmt"
	"sort"

	"math/big"

	"github.com/zclconf/go-cty/cty"
)

// byteMask masks the low byte of a word.
const byteMask uint64 = 0xff

// digest is a 128-bit fingerprint of a cty value. It folds a value the way
// equalValues compares it, so values digesting equally are equal, and values
// digesting differently are different. The second word keeps a single 64-bit
// collision from silently reporting two different values as equal.
type digest struct{ a, b uint64 }

// digestEntry pairs a digest with whether it may be trusted for equality.
// ok is false when the folded value held a kind the digester does not model,
// or when no digest was computed at all.
type digestEntry struct {
	d  digest
	ok bool
}

// The digester folds cty values into digests with no per-node allocation:
// two independent byte streams finalized with a splitmix-style mixer. The
// streams only have to separate different values (a false difference costs
// the caller one extra bounded pass; a false equality would skip a needed
// pass), not to be cryptographic.

const (
	hashPrimeA = 0x100000001b3
	hashPrimeB = 0x9E3779B97F4A7C15
	hashSeedA  = 0xcbf29ce484222325
	hashSeedB  = 0x27d4eb2f165667c5
)

// hasher folds strings and words into two independent streams.
type hasher struct{ a, b uint64 }

func newHasher() hasher { return hasher{a: hashSeedA, b: hashSeedB} }

func (h *hasher) mixByte(c uint64) {
	h.a = (h.a ^ c) * hashPrimeA
	h.b = (h.b + c) * hashPrimeB
}

// mixString folds a length-delimited string, so "ab"+"c" and "a"+"bc" fold
// differently.
func (h *hasher) mixString(s string) {
	h.mixInt(int64(len(s)))
	for i := 0; i < len(s); i++ {
		h.mixByte(uint64(s[i]))
	}
}

func (h *hasher) mix64(v uint64) {
	for i := 0; i < 8; i++ {
		h.mixByte((v >> (8 * i)) & byteMask)
	}
}

func (h *hasher) mixInt(v int64) { h.mix64(uint64(v)) }

// mixDigest folds one 128-bit word pair.
func (h *hasher) mixDigest(d digest) {
	h.mix64(d.a)
	h.mix64(d.b)
}

// tagPrefix keeps fold sections from colliding with value bytes.
const tagPrefix uint64 = 0x7461670000000000

// mixTag delimits a fold section.
func (h *hasher) mixTag(t byte) { h.mix64(tagPrefix | uint64(t)) }

// digest finalizes both streams.
func (h *hasher) digest() digest {
	return digest{a: splitmix64(h.a), b: splitmix64(h.b ^ h.a)}
}

func splitmix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

// Fold section tags.
const (
	tagNil      byte = 1
	tagUnknown  byte = 2
	tagNull     byte = 3
	tagString   byte = 4
	tagNumber   byte = 5
	tagBool     byte = 6
	tagTuple    byte = 7
	tagList     byte = 8
	tagSet      byte = 9
	tagMap      byte = 10
	tagObject   byte = 11
	tagMarked   byte = 12
	tagBoolTrue byte = 13

	// Reference-injection fold tags.
	tagRefType      byte = 20
	tagRefCount     byte = 21
	tagRefForEach   byte = 22
	tagRefExpanded  byte = 23
	tagRefSingle    byte = 24
	tagRefEphemeral byte = 25
	tagRefBody      byte = 26
	tagRefAttr      byte = 27
	tagRefBlock     byte = 28
	tagRefDynElem   byte = 29
	tagRefDynMemo   byte = 30
	tagRefDynWrite  byte = 31
)

// passDigester folds cty values into digests for one reference pass. It
// memoizes collection digests by the storage cty keeps them in: evaluation
// shares the storage of repeated values, so a scan pass digests the unique
// collections, not every instance's copy. The kind tag is part of the memo
// key, because a tuple and a list of the same elements can share storage
// while being different values.
type passDigester struct {
	memo map[collectionKind]digest
}

// collectionKind is a collection's storage identity plus the value kind it
// was folded as.
type collectionKind struct {
	id  collectionID
	tag byte
}

func newPassDigester() *passDigester {
	return &passDigester{memo: make(map[collectionKind]digest)}
}

// valueDigest folds v. ok is false when v holds a value kind the digester does
// not model, so a caller cannot decide equality from digests alone.
var dbgDigestCalls, dbgDigestElems int64

// DbgDigestCalls exposes the temporary digest counters for debugging.
func DbgDigestCalls() int64 { return dbgDigestCalls }

// DbgDigestElems exposes the temporary element counter for debugging.
func DbgDigestElems() int64 { return dbgDigestElems }

func (d *passDigester) valueDigest(v cty.Value) (digest, bool) {
	if v == cty.NilVal {
		h := newHasher()
		h.mixTag(tagNil)
		return h.digest(), true
	}
	if v.IsMarked() {
		// RawEquals compares the marks of every node, so each node folds its
		// own marks and recurses without them.
		h := newHasher()
		h.mixTag(tagMarked)
		h.mixMarks(v.Marks())
		inner, _ := v.Unmark()
		dg, ok := d.valueDigest(inner)
		if !ok {
			return digest{}, false
		}
		h.mixDigest(dg)
		return h.digest(), true
	}
	if !v.IsKnown() {
		h := newHasher()
		h.mixTag(tagUnknown)
		h.mixString(v.Type().GoString())
		return h.digest(), true
	}
	if v.IsNull() {
		h := newHasher()
		h.mixTag(tagNull)
		h.mixString(v.Type().GoString())
		return h.digest(), true
	}
	t := v.Type()
	switch {
	case t == cty.String:
		h := newHasher()
		h.mixTag(tagString)
		h.mixString(v.AsString())
		return h.digest(), true
	case t == cty.Number:
		h := newHasher()
		h.mixTag(tagNumber)
		d.mixNumber(&h, v.AsBigFloat())
		return h.digest(), true
	case t == cty.Bool:
		h := newHasher()
		if v.True() {
			h.mixTag(tagBoolTrue)
		} else {
			h.mixTag(tagBool)
		}
		return h.digest(), true
	case t.IsTupleType():
		return d.collectionDigest(v, tagTuple)
	case t.IsListType():
		return d.collectionDigest(v, tagList)
	case t.IsSetType():
		// Sets iterate in storage order, so equal sets can digest differently;
		// that only costs the caller an extra pass, never a wrong answer.
		return d.collectionDigest(v, tagSet)
	case t.IsMapType():
		return d.collectionDigest(v, tagMap)
	case t.IsObjectType():
		return d.objectDigest(v)
	}
	return digest{}, false
}

// mixNumber folds a number exactly without rendering it when it is an integer
// that fits int64, the common case. Everything else is rendered exactly, so
// equal numbers fold equally and different numbers fold differently up to a
// hash collision.
func (d *passDigester) mixNumber(h *hasher, bf *big.Float) {
	switch {
	case bf.IsInf():
		if bf.Signbit() {
			h.mixString("-inf")
		} else {
			h.mixString("+inf")
		}
	default:
		if i, acc := bf.Int64(); acc == big.Exact {
			h.mixString("i")
			h.mix64(uint64(i))
			return
		}
		h.mixString("f")
		h.mixString(bf.Text('e', -1))
	}
}

// collectionDigest folds a tuple, list, set or map from its storage.
func (d *passDigester) collectionDigest(v cty.Value, tag byte) (digest, bool) {
	h := newHasher()
	h.mixTag(tag)
	dbgDigestElems += int64(v.LengthInt())
	if id, ok := collectionIdentity(v); ok && id.n > 0 {
		key := collectionKind{id: id, tag: tag}
		if dg, cached := d.memo[key]; cached {
			return dg, true
		}
		n := v.LengthInt()
		h.mixInt(int64(n))
		for it := v.ElementIterator(); it.Next(); {
			k, ev := it.Element()
			if tag == tagMap {
				h.mixString(k.AsString())
			}
			dg, ok := d.valueDigest(ev)
			if !ok {
				return digest{}, false
			}
			h.mixDigest(dg)
		}
		dg := h.digest()
		d.memo[key] = dg
		return dg, true
	}
	// Empty collections (and values whose storage cannot be identified) are
	// cheap to encode directly.
	n := v.LengthInt()
	h.mixInt(int64(n))
	for it := v.ElementIterator(); it.Next(); {
		k, ev := it.Element()
		if tag == tagMap {
			h.mixString(k.AsString())
		}
		dg, ok := d.valueDigest(ev)
		if !ok {
			return digest{}, false
		}
		h.mixDigest(dg)
	}
	return h.digest(), true
}

// objectDigest folds an object from its sorted attribute names, so the fold
// does not depend on map iteration order.
func (d *passDigester) objectDigest(v cty.Value) (digest, bool) {
	if id, ok := collectionIdentity(v); ok && id.n > 0 {
		key := collectionKind{id: id, tag: tagObject}
		if dg, cached := d.memo[key]; cached {
			return dg, true
		}
		dg, ok := d.uncachedObjectDigest(v)
		if !ok {
			return digest{}, false
		}
		d.memo[key] = dg
		return dg, true
	}
	return d.uncachedObjectDigest(v)
}

func (d *passDigester) uncachedObjectDigest(v cty.Value) (digest, bool) {
	h := newHasher()
	h.mixTag(tagObject)
	attrs := v.Type().AttributeTypes()
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h.mixString(name)
		dg, ok := d.valueDigest(v.GetAttr(name))
		if !ok {
			return digest{}, false
		}
		h.mixDigest(dg)
	}
	return h.digest(), true
}

// mixMarks folds a mark set: the sorted elements, so equal mark sets fold
// equally. Mark values are rendered; a rendering that differs for equal values
// only costs the caller an extra pass.
func (h *hasher) mixMarks(marks cty.ValueMarks) {
	names := make([]string, 0, len(marks))
	for key, value := range marks {
		k, _ := key.(string)
		names = append(names, k+"|"+renderMark(value))
	}
	sort.Strings(names)
	for _, name := range names {
		h.mixString(name)
	}
}

// renderMark renders one mark's value deterministically.
func renderMark(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
