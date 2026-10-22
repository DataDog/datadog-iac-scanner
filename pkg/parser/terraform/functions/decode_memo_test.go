/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"container/list"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

func largeJSON(entries int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < entries; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"service%05d": {"owner": "team%d", "alerts": ["a", "b"], "tier": %d}`, i, i%7, i%3)
	}
	b.WriteString("}")
	return b.String()
}

func TestMemoizeDecode_ReturnsTheValueDecodedBefore(t *testing.T) {
	t.Cleanup(ReleaseDecodeMemo)
	ReleaseDecodeMemo()
	jsondecode := TerraformFuncs["jsondecode"]
	input := cty.StringVal(largeJSON(2000))
	require.GreaterOrEqual(t, len(input.AsString()), minMemoizedDecodeInput)

	want, err := stdlib.JSONDecodeFunc.Call([]cty.Value{input})
	require.NoError(t, err)
	first, err := jsondecode.Call([]cty.Value{input})
	require.NoError(t, err)
	second, err := jsondecode.Call([]cty.Value{input})
	require.NoError(t, err)
	require.True(t, want.RawEquals(first))
	require.True(t, want.RawEquals(second))
	require.Len(t, decodeResults.entries, 1)

	// A small input is decoded every time.
	small, err := jsondecode.Call([]cty.Value{cty.StringVal(`{"a": 1}`)})
	require.NoError(t, err)
	require.True(t, cty.ObjectVal(map[string]cty.Value{"a": cty.NumberIntVal(1)}).RawEquals(small))
	require.Len(t, decodeResults.entries, 1)
}

func TestMemoizeDecode_KeepsTheError(t *testing.T) {
	t.Cleanup(ReleaseDecodeMemo)
	invalid := cty.StringVal(strings.TrimSuffix(largeJSON(2000), "}") + ",")
	_, want := stdlib.JSONDecodeFunc.Call([]cty.Value{invalid})
	require.Error(t, want)
	for i := 0; i < 2; i++ {
		_, err := TerraformFuncs["jsondecode"].Call([]cty.Value{invalid})
		require.EqualError(t, err, want.Error())
	}
}

func TestMemoizeDecode_UnknownAndMarkedInputs(t *testing.T) {
	t.Cleanup(ReleaseDecodeMemo)
	got, err := TerraformFuncs["jsondecode"].Call([]cty.Value{cty.UnknownVal(cty.String)})
	require.NoError(t, err)
	require.False(t, got.IsKnown())

	marked := cty.StringVal(largeJSON(2000)).Mark("sensitive")
	got, err = TerraformFuncs["jsondecode"].Call([]cty.Value{marked})
	require.NoError(t, err)
	require.True(t, got.HasMark("sensitive"))
}

func TestDecodeMemo_BoundedByInputSize(t *testing.T) {
	m := &decodeMemo{entries: map[decodeKey]*list.Element{}, order: list.New(), pending: map[decodeKey]*pendingDecode{}}
	third := maxMemoizedDecodeInput / 3
	for i := 0; i < 3; i++ {
		m.put(&decodeEntry{key: decodeKey{fn: "f", a: uint64(i), n: third}})
	}
	_, ok := m.get(decodeKey{fn: "f", a: 0, n: third})
	require.True(t, ok)
	// The least recently used entry makes room for a new one.
	m.put(&decodeEntry{key: decodeKey{fn: "f", a: 3, n: third}})
	require.LessOrEqual(t, m.size, maxMemoizedDecodeInput)
	_, ok = m.get(decodeKey{fn: "f", a: 1, n: third})
	require.False(t, ok)
	for _, a := range []uint64{0, 2, 3} {
		_, ok = m.get(decodeKey{fn: "f", a: a, n: third})
		require.True(t, ok, a)
	}
	m.put(&decodeEntry{key: decodeKey{fn: "f", a: 4, n: maxMemoizedDecodeInput + 1}})
	_, ok = m.get(decodeKey{fn: "f", a: 4, n: maxMemoizedDecodeInput + 1})
	require.False(t, ok, "an input larger than the bound is not kept")
}

func TestDecodeMemo_ConcurrentCallersDecodeOnce(t *testing.T) {
	m := &decodeMemo{entries: map[decodeKey]*list.Element{}, order: list.New(), pending: map[decodeKey]*pendingDecode{}}
	key := decodeKey{fn: "f", a: 1, n: minMemoizedDecodeInput}
	var calls atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := m.decode(key, func() *decodeEntry {
				calls.Add(1)
				<-release
				return &decodeEntry{key: key, value: cty.True}
			})
			require.True(t, got.value.True())
		}()
	}
	for len(m.pendingKeys()) == 0 {
		runtime.Gosched()
	}
	close(release)
	wg.Wait()
	require.Equal(t, int32(1), calls.Load())
}

func (m *decodeMemo) pendingKeys() []decodeKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]decodeKey, 0, len(m.pending))
	for k := range m.pending {
		keys = append(keys, k)
	}
	return keys
}

func (m *decodeMemo) get(key decodeKey) (*decodeEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lookupLocked(key)
}
