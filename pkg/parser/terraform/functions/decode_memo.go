/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"hash/maphash"
	"sync"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

const (
	// minMemoizedDecode is the smallest input whose decode is remembered:
	// decoding a smaller one costs about what finding it in the memo does.
	minMemoizedDecode = 4 << 10 // 4 KiB
	// decodeMemoBudget bounds the bytes the decoded values of one scan may
	// hold, estimated from the size of their inputs. Past it, results are
	// computed and not remembered.
	decodeMemoBudget = 64 << 20 // 64 MiB
	// decodeBytesPerInputByte estimates how much a decoded value holds per
	// byte of the document it came from.
	decodeBytesPerInputByte = 8
)

// decodeKey names a decode input by a digest of its content, so the input is
// not kept alive for the rest of the scan.
type decodeKey struct {
	fn   string
	n    int
	a, b uint64
}

// The seeds stay secret for the process: a fixed hash of repository content
// would let a crafted file collide with another one and reuse its decoded value.
var decodeSeedA, decodeSeedB = maphash.MakeSeed(), maphash.MakeSeed()

func decodeKeyOf(fn, input string) decodeKey {
	var a, b maphash.Hash
	a.SetSeed(decodeSeedA)
	b.SetSeed(decodeSeedB)
	for _, h := range []*maphash.Hash{&a, &b} {
		_, _ = h.WriteString(fn)
		_ = h.WriteByte(0)
		_, _ = h.WriteString(input)
	}
	return decodeKey{fn: fn, n: len(input), a: a.Sum64(), b: b.Sum64()}
}

type decoded struct {
	value cty.Value
	err   error
}

// decodeMemo remembers the result of jsondecode and yamldecode calls on large
// inputs for the life of one scan. A module called for many instances typically
// decodes the same document, read from one file, once per instance; cty values
// are immutable, so every call can share the one result.
type decodeMemo struct {
	mu       sync.Mutex
	results  map[decodeKey]decoded
	inflight map[decodeKey]*decodeCall
	bytes    int
}

// decodeCall is one decode shared by every caller that asks for it while it runs.
type decodeCall struct {
	once sync.Once
	r    decoded
}

func (m *decodeMemo) lookup(key decodeKey) (decoded, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.results[key]
	return r, ok
}

// remember stores r when it fits the budget. A small input is never stored.
func (m *decodeMemo) remember(key decodeKey, r decoded) bool {
	if key.n < minMemoizedDecode {
		return false
	}
	cost := key.n * decodeBytesPerInputByte
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.results[key]; ok {
		return true
	}
	if m.bytes+cost > decodeMemoBudget {
		return false
	}
	if m.results == nil {
		m.results = make(map[decodeKey]decoded)
	}
	m.results[key] = r
	m.bytes += cost
	return true
}

// obtain returns the decode of input. Callers that arrive while it is running
// wait for that decode instead of starting another one.
func (m *decodeMemo) obtain(name string, original function.Function, input string, args []cty.Value) decoded {
	key := decodeKeyOf(name, input)
	m.mu.Lock()
	if r, ok := m.results[key]; ok {
		m.mu.Unlock()
		return r
	}
	c := m.inflight[key]
	if c == nil {
		c = &decodeCall{}
		if m.inflight == nil {
			m.inflight = map[decodeKey]*decodeCall{}
		}
		m.inflight[key] = c
	}
	m.mu.Unlock()

	c.once.Do(func() {
		value, err := original.Call(args)
		c.r = decoded{value: value, err: err}
		if err == nil {
			m.remember(key, c.r)
		}
		m.mu.Lock()
		delete(m.inflight, key)
		m.mu.Unlock()
	})
	return c.r
}

// memoizeDecode wraps a decode function so large inputs are decoded once per
// scan. A known input is decoded in the value callback. The type callback
// reports a remembered result's type and otherwise dynamic, so it does not
// parse; an input that is not a known string still uses the original type
// callback, which can tell string, bool or number from a known prefix.
// Marks are removed before the call and applied to what it returns, so the
// memo holds the unmarked value.
func (m *decodeMemo) memoizeDecode(name string, original function.Function) function.Function {
	return function.New(&function.Spec{
		Description: original.Description(),
		Params:      original.Params(),
		VarParam:    original.VarParam(),
		Type: func(args []cty.Value) (cty.Type, error) {
			input, ok := knownDecodeInput(args)
			if !ok {
				return original.ReturnTypeForValues(args)
			}
			if r, ok := m.lookup(decodeKeyOf(name, input)); ok {
				return r.value.Type(), nil
			}
			return cty.DynamicPseudoType, nil
		},
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			input, ok := knownDecodeInput(args)
			if !ok {
				return original.Call(args)
			}
			r := m.obtain(name, original, input, args)
			return r.value, r.err
		},
	})
}

func knownDecodeInput(args []cty.Value) (string, bool) {
	if len(args) != 1 || !args[0].IsKnown() || args[0].IsNull() || !args[0].Type().Equals(cty.String) {
		return "", false
	}
	return args[0].AsString(), true
}
