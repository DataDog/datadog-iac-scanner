package unknowngate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/stretchr/testify/require"
)

func TestBatchConfirmationSharesDeterministicProbes(t *testing.T) {
	const candidateCount = 16
	var policy string
	policy = `package datadog
import rego.v1

DatadogPolicy contains {"kind": "always"} if true
DatadogPolicy contains {"kind": kind} if {
	some kind in input.kinds
	count(input.items) == 2
}
`
	g := newTestGate(t, testPlaceholder, policy)
	kinds := make([]string, candidateCount)
	for i := range kinds {
		kinds[i] = fmt.Sprintf("candidate-%d", i)
	}
	kindsJSON, err := json.Marshal(kinds)
	require.NoError(t, err)
	input := mustValue(t, `{"items":["`+testPlaceholder+`","`+testPlaceholder+`"],"kinds":`+string(kindsJSON)+`}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, candidateCount+1)

	ph := newPlaceholder(testPlaceholder)
	jobs := make([]job, len(results))
	scopes := make([][]ast.Value, len(results))
	for i, result := range results {
		id, mask := ph.identity(result)
		jobs[i] = job{index: i, cand: Candidate{Result: result}, id: id, mask: mask}
		scopes[i] = []ast.Value{input}
	}
	sub := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	out := make([]Verdict, len(jobs))
	decided, err := sub.batchRound(jobs, scopes, []ast.Value{input}, batchReplacement{replacement: replacement{remove: true}, listOnly: true}, out)
	require.NoError(t, err)
	require.Equal(t, candidateCount, decided)
	require.Equal(t, 3, sub.evals, "one combined round plus one eval per shared occurrence")

	for i, result := range results {
		kind := string(result.(ast.Object).Get(ast.StringTerm("kind")).Value.(ast.String))
		if kind == "always" {
			require.False(t, out[i].Uncertain)
			continue
		}
		require.True(t, out[i].Uncertain, kind)
		require.Equal(t, StageSubstitution, out[i].Stage)
	}
}

func TestBatchConfirmationStopsWhenAllCandidatesAreUncertain(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"kind": kind} if {
	some kind in input.kinds
	count(input.items) == 2
}
`)
	input := mustValue(t, `{"items":["`+testPlaceholder+`","`+testPlaceholder+`"],"kinds":["one","two"]}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 2)

	ph := newPlaceholder(testPlaceholder)
	jobs := make([]job, len(results))
	scopes := make([][]ast.Value, len(results))
	for i, result := range results {
		id, mask := ph.identity(result)
		jobs[i] = job{index: i, cand: Candidate{Result: result}, id: id, mask: mask}
		scopes[i] = []ast.Value{input}
	}
	sub := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	out := make([]Verdict, len(jobs))
	_, err = sub.batchRound(jobs, scopes, []ast.Value{input}, batchReplacement{replacement: replacement{remove: true}, listOnly: true}, out)
	require.NoError(t, err)
	require.Equal(t, 2, sub.evals, "combined round plus one shared confirmation; later probes are skipped")
	for _, verdict := range out {
		require.True(t, verdict.Uncertain)
	}
}

func TestNondeterministicBuiltinDisablesConfirmationBatching(t *testing.T) {
	unused := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

unused_time() := time.now_ns()
DatadogPolicy contains {"rule": "ordinary"} if true
`)
	require.False(t, unused.nondeterministic, "an unreachable nondeterministic helper is irrelevant")

	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"kind": "always"} if time.now_ns() >= 0
DatadogPolicy contains {"kind": kind} if {
	some kind in input.kinds
	count(input.items) == 2
	time.now_ns() >= 0
}
`)
	require.True(t, g.nondeterministic, "a reachable nondeterministic builtin must select the fallback")
	input := mustValue(t, `{"items":["`+testPlaceholder+`","`+testPlaceholder+`"],"kinds":["one","two"]}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 3)
	ph := newPlaceholder(testPlaceholder)
	jobs := make([]job, len(results))
	scopes := make([][]ast.Value, len(results))
	for i, result := range results {
		id, mask := ph.identity(result)
		jobs[i] = job{index: i, cand: Candidate{Result: result}, id: id, mask: mask}
		scopes[i] = []ast.Value{input}
	}
	sub := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	_, err = sub.batchRound(jobs, scopes, []ast.Value{input}, batchReplacement{replacement: replacement{remove: true}, listOnly: true}, make([]Verdict, len(jobs)))
	require.NoError(t, err)
	require.Equal(t, 5, sub.evals, "nondeterministic policies keep per-candidate probes")
}

type transactionFailureStore struct {
	storage.Store
	calls   int
	failAt  int
	failure error
}

func (s *transactionFailureStore) NewTransaction(ctx context.Context, params ...storage.TransactionParams) (storage.Transaction, error) {
	s.calls++
	if s.calls == s.failAt {
		return nil, s.failure
	}
	return s.Store.NewTransaction(ctx, params...)
}

func TestBatchedConfirmationPreservesTransactionErrors(t *testing.T) {
	for _, tc := range []struct {
		name          string
		includeAlways bool
		wantError     bool
		wantEvals     int
	}{
		{name: "all results uncertain", wantEvals: 2},
		{name: "known result still needs checking", includeAlways: true, wantError: true, wantEvals: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := `package datadog
import rego.v1
DatadogPolicy contains {"kind": kind} if {
	some kind in input.kinds
	count(input.items) == 2
}
`
			if tc.includeAlways {
				policy += `DatadogPolicy contains {"kind": "always"} if true
`
			}
			sentinel := errors.New("transaction failure")
			store := &transactionFailureStore{Store: inmem.New(), failAt: 3, failure: sentinel}
			g := newMultiModuleGateWithStore(t, testPlaceholder, map[string]string{"rule.rego": policy}, store)
			input := mustValue(t, `{"items":["`+testPlaceholder+`","`+testPlaceholder+`"],"kinds":["one","two"]}`)
			results, err := g.Results(context.Background(), input)
			require.NoError(t, err)
			store.calls = 0 // Count only the combined round and its confirmation probes.
			ph := newPlaceholder(testPlaceholder)
			jobs := make([]job, len(results))
			scopes := make([][]ast.Value, len(results))
			for i, result := range results {
				id, mask := ph.identity(result)
				jobs[i] = job{index: i, cand: Candidate{Result: result}, id: id, mask: mask}
				scopes[i] = []ast.Value{input}
			}
			sub := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
			_, err = sub.batchRound(jobs, scopes, []ast.Value{input}, batchReplacement{replacement: replacement{remove: true}, listOnly: true}, make([]Verdict, len(jobs)))
			require.Equal(t, tc.wantEvals, sub.evals)
			require.Equal(t, tc.wantEvals, store.calls)
			if tc.wantError {
				require.ErrorIs(t, err, sentinel)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBatchedConfirmationPreservesCancellation(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
DatadogPolicy contains {"rule": "x"} if true
`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ph := newPlaceholder(testPlaceholder)
	sub := &substitution{g: g, ctx: ctx, input: mustValue(t, `{"items":["`+testPlaceholder+`"]}`), ph: ph}
	_, _, err := sub.confirmationIdentities(sub.input, occurrences(sub.input, ph)[0], replacement{value: ast.String("known")})
	require.ErrorIs(t, err, context.Canceled)
}
