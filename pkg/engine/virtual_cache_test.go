/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/stretchr/testify/require"
)

// The compact cache answers every lookup as OPA's own does, whatever was put
// in it, defined or undefined, in whichever frame.
func TestCompactVirtualCache_AnswersAsOPAsCache(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	terms := []*ast.Term{
		ast.RefTerm(ast.VarTerm("data"), ast.StringTerm("lib"), ast.StringTerm("f")).Value.(ast.Ref)[0],
		ast.StringTerm("f"), ast.StringTerm("g"), ast.IntNumberTerm(1), ast.IntNumberTerm(2),
		ast.ObjectTerm(ast.Item(ast.StringTerm("k"), ast.StringTerm("v"))),
		ast.ObjectTerm(ast.Item(ast.StringTerm("k"), ast.StringTerm("v"))), // equal to the one before
		ast.ArrayTerm(ast.StringTerm("a"), ast.IntNumberTerm(1)),
	}
	ref := func() ast.Ref {
		r := make(ast.Ref, 1+rng.Intn(3))
		for i := range r {
			r[i] = terms[rng.Intn(len(terms))]
		}
		return r
	}
	keys := func(rs []ast.Ref) []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = r.String()
		}
		sort.Strings(out)
		return out
	}
	opa, compact := topdown.NewVirtualCache(), newCompactVirtualCache()
	depth := 1
	for step := range 5000 {
		switch op := rng.Intn(10); {
		case op < 4:
			r := ref()
			var value *ast.Term
			if rng.Intn(3) > 0 {
				value = ast.IntNumberTerm(rng.Intn(100))
			}
			opa.Put(r, value)
			compact.Put(r, value)
			// A caller reusing the slice it passed changes nothing cached.
			r[0] = ast.StringTerm("reused")
		case op < 8:
			r := ref()
			wantValue, wantUndefined := opa.Get(r)
			gotValue, gotUndefined := compact.Get(r)
			require.Equal(t, wantUndefined, gotUndefined, "step %d: %v", step, r)
			require.Equal(t, fmt.Sprint(wantValue), fmt.Sprint(gotValue), "step %d: %v", step, r)
		case op == 8 && depth < 4:
			opa.Push()
			compact.Push()
			depth++
		case op == 9 && depth > 1:
			opa.Pop()
			compact.Pop()
			depth--
		}
		if step%250 == 0 {
			require.Equal(t, keys(opa.Keys()), keys(compact.Keys()), "step %d", step)
		}
	}
}
