/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package value converts evaluated Terraform values into rule input, with
// unknown values replaced by a per-scan placeholder.
package value

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// placeholderPrefix starts every placeholder. The NUL byte cannot appear in a
// value a configuration writes, so a placeholder never collides with one.
const placeholderPrefix = "\u0000dd-unknown-"

// NewPlaceholder returns a fresh placeholder: a prefix and 128 random bits.
// Rules compare it by exact match only.
func NewPlaceholder() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return placeholderPrefix + hex.EncodeToString(b[:])
}

// UnknownMarker stands for an unknown value inside a string that still has
// known parts: a computed policy-document leaf, a jsonencode template part, or
// an interpolation inside a JSON heredoc. Substitute turns each mark into the
// per-scan placeholder when the value is projected.
const UnknownMarker = "\u0000dd-unknown-part"

// JSONUnknownMarker is UnknownMarker as a JSON encoder writes it (\u0000…).
const JSONUnknownMarker = `\u0000dd-unknown-part`

// HasUnknownMarker reports whether s holds UnknownMarker, raw or JSON-escaped.
func HasUnknownMarker(s string) bool {
	return strings.Contains(s, UnknownMarker) || strings.Contains(s, JSONUnknownMarker)
}

// Substitute replaces each unknown mark in s with the placeholder, keeping any
// known surrounding text. In JSON text the placeholder is escaped the way JSON
// writes a NUL, so the document stays valid. changed reports whether s held a
// marker.
func Substitute(s, placeholder string) (out string, changed bool) {
	switch {
	case strings.Contains(s, UnknownMarker):
		return strings.ReplaceAll(s, UnknownMarker, placeholder), true
	case strings.Contains(s, JSONUnknownMarker):
		escaped := strings.ReplaceAll(placeholder, "\u0000", `\u0000`)
		return strings.ReplaceAll(s, JSONUnknownMarker, escaped), true
	}
	return s, false
}

// Present reports whether v is set: a null value is absent from rule input.
func Present(v cty.Value) bool {
	v, _ = v.UnmarkDeep()
	return !v.IsKnown() || !v.IsNull()
}

// Converter turns cty values into plain Go values (string, bool, int64,
// float64, *big.Float for numbers that fit neither, []any, map[string]any):
//   - an unknown value is the placeholder;
//   - a known string that holds UnknownMarker keeps its other characters and
//     replaces each mark with the placeholder;
//   - known collections keep their known elements and keys, unknown elements
//     and values are the placeholder;
//   - null object attributes and map values are absent, null list elements
//     stay null.
type Converter struct {
	Placeholder string
}

// Go converts v. A null v gives nil.
func (c Converter) Go(v cty.Value) any {
	v, _ = v.UnmarkDeep()
	return c.goValue(v)
}

func (c Converter) goValue(v cty.Value) any {
	if !v.IsKnown() {
		return c.Placeholder
	}
	if v.IsNull() {
		return nil
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		s, _ := Substitute(v.AsString(), c.Placeholder)
		return s
	case ty == cty.Bool:
		return v.True()
	case ty == cty.Number:
		return Number(v.AsBigFloat())
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		return c.goList(v)
	case ty.IsMapType() || ty.IsObjectType():
		return c.goMap(v)
	case ty == cty.DynamicPseudoType:
		return c.Placeholder
	}
	return nil
}

func (c Converter) goList(v cty.Value) []any {
	out := make([]any, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		out = append(out, c.goValue(e))
	}
	return out
}

func (c Converter) goMap(v cty.Value) map[string]any {
	out := make(map[string]any, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		k, e := it.Element()
		if e.IsKnown() && e.IsNull() {
			continue
		}
		out[k.AsString()] = c.goValue(e)
	}
	return out
}

// Number returns n as an int64 when it is an integer that fits, else as a
// float64 when that is exact, else n itself.
func Number(n *big.Float) any {
	if n.IsInt() {
		if i, acc := n.Int64(); acc == big.Exact {
			return i
		}
	}
	if f, acc := n.Float64(); acc == big.Exact {
		return f
	}
	return n
}
