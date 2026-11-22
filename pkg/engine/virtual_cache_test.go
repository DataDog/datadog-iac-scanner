/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/stretchr/testify/require"
)

// Exercise the cache interface independently of evaluation, including nested
// frames and undefined entries. Keep this parity test when upgrading OPA.
func TestIdentityVirtualCacheFramesMatchOPA(t *testing.T) {
	want, got := topdown.NewVirtualCache(), newIdentityVirtualCache()
	refs := []ast.Ref{
		ast.MustParseRef("data.p"),
		ast.MustParseRef("data.p.child"),
		ast.MustParseRef("data.missing"),
	}
	compare := func() {
		t.Helper()
		for _, ref := range refs {
			wv, wu := want.Get(ref)
			gv, gu := got.Get(ref)
			require.Equal(t, wu, gu, ref.String())
			require.Equal(t, wv, gv, ref.String())
		}
		keys := func(c topdown.VirtualCache) []string {
			var out []string
			for _, key := range c.Keys() {
				out = append(out, key.String())
			}
			return out
		}
		require.ElementsMatch(t, keys(want), keys(got))
	}
	put := func(ref ast.Ref, value *ast.Term) {
		t.Helper()
		want.Put(ref, value)
		got.Put(ref, value)
		compare()
	}
	compare()
	put(refs[0], ast.MustParseTerm(`{"x": [1, 2]}`))
	put(refs[1], ast.MustParseTerm("false"))
	put(refs[2], nil)
	want.Push()
	got.Push()
	compare()
	put(refs[0], ast.MustParseTerm("null"))
	put(refs[2], ast.MustParseTerm("42"))
	want.Push()
	got.Push()
	put(refs[1], nil)
	want.Pop()
	got.Pop()
	compare()
	want.Pop()
	got.Pop()
	compare()
}

func BenchmarkVirtualCacheDocumentLookup(b *testing.B) {
	for _, size := range []int{100, 1000} {
		doc := ast.NewObject()
		for i := range size {
			doc.Insert(ast.IntNumberTerm(i), ast.ArrayTerm(ast.IntNumberTerm(i), ast.StringTerm("value")))
		}
		for name, newCache := range map[string]func() topdown.VirtualCache{
			"OPA":      topdown.NewVirtualCache,
			"identity": newIdentityVirtualCache,
		} {
			b.Run(fmt.Sprintf("%s/%d", name, size), func(b *testing.B) {
				cache := newCache()
				stored := ast.Ref{ast.VarTerm("data"), ast.StringTerm("f"), ast.NewTerm(doc)}
				// Separate terms wrapping the same immutable value occur during eval.
				lookup := ast.Ref{ast.VarTerm("data"), ast.StringTerm("f"), ast.NewTerm(doc)}
				value := ast.BooleanTerm(true)
				cache.Put(stored, value)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if result, _ := cache.Get(lookup); result != value {
						b.Fatal("cache miss")
					}
				}
			})
		}
	}
}
