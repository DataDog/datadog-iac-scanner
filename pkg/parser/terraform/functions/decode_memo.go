/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"container/list"
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// A configuration commonly decodes a large data file, as in
// jsondecode(file("config.json")), and the scan evaluates that expression many
// times over: once per root reading the file, once per module evaluation, and
// once more every time a finding needs the line information of the file
// holding it, which is parsed again for each rule. Decoding a document of a
// few megabytes takes the better part of a second, so the decoding functions
// return the value they decoded the first time for a large input they already
// decoded. Values are immutable, so sharing one is safe.

const (
	// minMemoizedDecodeInput is the size from which decoding is worth
	// remembering.
	minMemoizedDecodeInput = 64 << 10
	// maxMemoizedDecodeInput bounds the inputs whose values are kept, least
	// recently used first out. A decoded value takes about ten times the
	// memory of its input.
	maxMemoizedDecodeInput = 16 << 20
)

type decodeKey struct {
	fn   string
	a, b uint64
	n    int
}

type decodeEntry struct {
	key   decodeKey
	value cty.Value
	err   error
}

type decodeMemo struct {
	mu      sync.Mutex
	entries map[decodeKey]*list.Element
	order   *list.List
	size    int
	// pending are the decodes under way; a caller decoding the same input
	// waits for the first rather than decoding it again alongside it.
	pending map[decodeKey]*pendingDecode
}

type pendingDecode struct {
	done  chan struct{}
	entry *decodeEntry
}

var decodeResults = &decodeMemo{
	entries: map[decodeKey]*list.Element{}, order: list.New(), pending: map[decodeKey]*pendingDecode{},
}

// ReleaseDecodeMemo drops the remembered values.
func ReleaseDecodeMemo() {
	decodeResults.mu.Lock()
	defer decodeResults.mu.Unlock()
	decodeResults.entries = map[decodeKey]*list.Element{}
	decodeResults.order.Init()
	decodeResults.size = 0
}

// decode returns the remembered value of key, or computes it once however
// many callers ask for it at the same time.
func (m *decodeMemo) decode(key decodeKey, compute func() *decodeEntry) *decodeEntry {
	m.mu.Lock()
	if entry, ok := m.lookupLocked(key); ok {
		m.mu.Unlock()
		return entry
	}
	if p, ok := m.pending[key]; ok {
		m.mu.Unlock()
		<-p.done
		if p.entry == nil {
			// The first decode did not finish.
			return compute()
		}
		return p.entry
	}
	p := &pendingDecode{done: make(chan struct{})}
	m.pending[key] = p
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.pending, key)
		m.mu.Unlock()
		close(p.done)
	}()
	p.entry = compute()
	m.put(p.entry)
	return p.entry
}

func decodeKeyOf(fn, input string) decodeKey {
	b := xxhash.New()
	_, _ = b.WriteString("\x00datadog-iac-scanner\x00")
	_, _ = b.WriteString(input)
	return decodeKey{fn: fn, a: xxhash.Sum64String(input), b: b.Sum64(), n: len(input)}
}

// lookupLocked returns the remembered entry of key; m.mu must be held.
func (m *decodeMemo) lookupLocked(key decodeKey) (*decodeEntry, bool) {
	el, ok := m.entries[key]
	if !ok {
		return nil, false
	}
	m.order.MoveToFront(el)
	return el.Value.(*decodeEntry), true
}

func (m *decodeMemo) put(entry *decodeEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[entry.key]; ok || entry.key.n > maxMemoizedDecodeInput {
		return
	}
	m.entries[entry.key] = m.order.PushFront(entry)
	m.size += entry.key.n
	for m.size > maxMemoizedDecodeInput {
		last := m.order.Back()
		old := last.Value.(*decodeEntry)
		m.order.Remove(last)
		delete(m.entries, old.key)
		m.size -= old.key.n
	}
}

// memoizeDecode wraps fn, a function decoding the string it is given, so that
// a large input decoded before returns the value decoded then.
func memoizeDecode(name string, fn function.Function) function.Function {
	decode := func(args []cty.Value) (*decodeEntry, bool) {
		if len(args) != 1 || !args[0].IsKnown() || args[0].IsNull() || !args[0].Type().Equals(cty.String) {
			return nil, false
		}
		input := args[0].AsString()
		if len(input) < minMemoizedDecodeInput {
			return nil, false
		}
		key := decodeKeyOf(name, input)
		return decodeResults.decode(key, func() *decodeEntry {
			value, err := fn.Call(args)
			return &decodeEntry{key: key, value: value, err: err}
		}), true
	}
	return function.New(&function.Spec{
		Description: fn.Description(),
		Params:      fn.Params(),
		VarParam:    fn.VarParam(),
		Type: func(args []cty.Value) (cty.Type, error) {
			if entry, ok := decode(args); ok {
				if entry.err != nil {
					return cty.NilType, entry.err
				}
				return entry.value.Type(), nil
			}
			return fn.ReturnTypeForValues(args)
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			if entry, ok := decode(args); ok {
				return entry.value, entry.err
			}
			return fn.Call(args)
		},
	})
}
