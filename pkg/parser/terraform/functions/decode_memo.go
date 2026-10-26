/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"hash/maphash"
	"sync"
	"unsafe"

	ctyyaml "github.com/zclconf/go-cty-yaml"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

const (
	fnJSONDecode = "jsondecode"
	fnYAMLDecode = "yamldecode"
)

// decodeKey names a decoded input by a digest of its content; the input is
// not kept, as that would pin every large string for the rest of the scan.
type decodeKey struct {
	fn   string
	n    int
	a, b uint64
}

// The seeds stay secret for the process. A fixed hash of repository content
// would let a crafted payload collide and reuse another file's decoded value.
var decodeSeedA, decodeSeedB = maphash.MakeSeed(), maphash.MakeSeed()

func decodeKeyOf(fn, input string) decodeKey {
	var a, b maphash.Hash
	a.SetSeed(decodeSeedA)
	b.SetSeed(decodeSeedB)
	_, _ = a.WriteString(fn)
	_, _ = a.WriteString("\x00")
	_, _ = a.WriteString(input)
	_, _ = b.WriteString(fn)
	_, _ = b.WriteString("\x00")
	_, _ = b.WriteString(input)
	return decodeKey{fn: fn, n: len(input), a: a.Sum64(), b: b.Sum64()}
}

// valueResult is a decode or render: the value a call returns, or its error.
type valueResult struct {
	value cty.Value
	err   error
}

func estimateDecode(_ decodeKey, r valueResult) (int, bool) {
	if r.err != nil {
		return retainedEntry + estimateError(r.err), true
	}
	return retainedEntry + estimateValue(r.value), true
}

// stringID is the identity of a string's bytes. Two strings with one identity
// hold the same bytes, and while one of them is alive no other string can take
// its identity.
type stringID struct {
	data *byte
	n    int
}

func idOf(s string) stringID {
	// The bytes of a string a kept result holds identify that result. Strings
	// are immutable, so the pointer stays that string's while the result is kept.
	return stringID{data: unsafe.StringData(s), n: len(s)} //nolint:gosec // G103
}

type idKey struct {
	fn string
	id stringID
}

// decodeKeys finds the key of a decode input without hashing it when the
// input is a string a kept file result holds, as in jsondecode(file(...)):
// every call then passes the same string, which the kept result keeps alive
// for the rest of the scan.
type decodeKeys struct {
	mu     sync.Mutex
	pinned map[stringID]struct{}
	keys   map[idKey]decodeKey
}

func (d *decodeKeys) pin(s string) {
	d.mu.Lock()
	d.pinned[idOf(s)] = struct{}{}
	d.mu.Unlock()
}

func (d *decodeKeys) keyOf(fn, input string) decodeKey {
	k := idKey{fn: fn, id: idOf(input)}
	d.mu.Lock()
	key, ok := d.keys[k]
	_, pinned := d.pinned[k.id]
	d.mu.Unlock()
	if ok {
		return key
	}
	key = decodeKeyOf(fn, input)
	if pinned {
		d.mu.Lock()
		if _, ok := d.pinned[k.id]; ok {
			d.keys[k] = key
		}
		d.mu.Unlock()
	}
	return key
}

// largeDecodeInput reports the string a decode should remember. Marks are
// absent here: function.Call removes them before Type and Impl and applies
// them to the returned value, so the memo holds the unmarked value.
func largeDecodeInput(args []cty.Value) (string, bool) {
	if len(args) != 1 || !args[0].IsKnown() || args[0].IsNull() || !args[0].Type().Equals(cty.String) {
		return "", false
	}
	input := args[0].AsString()
	if len(input) < minMemoizedSize {
		return "", false
	}
	return input, true
}

func memoizeDecode(
	memo *scanMemo,
	name string,
	original function.Function,
	unmarshal func(string, cty.Type) (cty.Value, error),
) function.Function {
	return function.New(&function.Spec{
		Description: original.Description(),
		Params:      original.Params(),
		VarParam:    original.VarParam(),
		Type:        original.ReturnTypeForValues,
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			input, ok := largeDecodeInput(args)
			if !ok {
				// Type already parsed the input to find retType; calling the
				// original function would parse it again.
				return unmarshal(args[0].AsString(), retType)
			}
			got := memo.decodes.lookupOrCompute(memo.keys.keyOf(name, input), func() valueResult {
				value, err := original.Call(args)
				return valueResult{value: value, err: err}
			})
			return got.value, got.err
		},
	})
}

func unmarshalJSON(src string, ty cty.Type) (cty.Value, error) {
	return ctyjson.Unmarshal([]byte(src), ty)
}

func unmarshalYAML(src string, ty cty.Type) (cty.Value, error) {
	return ctyyaml.Standard.Unmarshal([]byte(src), ty)
}

func decodeFuncs(memo *scanMemo) map[string]function.Function {
	return map[string]function.Function{
		fnJSONDecode: memoizeDecode(memo, fnJSONDecode, stdlib.JSONDecodeFunc, unmarshalJSON),
		fnYAMLDecode: memoizeDecode(memo, fnYAMLDecode, ctyyaml.YAMLDecodeFunc, unmarshalYAML),
	}
}
