package unknowngate

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/stretchr/testify/require"
)

func TestPartialProofIndependentAndUnknownCondition(t *testing.T) {
	const placeholder = "__partial_proof_unknown__"
	module := ast.MustParseModule(`package datadog

DatadogPolicy contains {"_dd_id": "independent", "path": []} if input.doc.kind == "docker"
DatadogPolicy contains {"_dd_id": "conditional", "path": []} if input.doc.value != "no"
`)
	gate, err := New(Options{
		Placeholder:        placeholder,
		Modules:            map[string]*ast.Module{"rule.rego": module},
		Query:              "data.datadog.DatadogPolicy",
		EnablePartialProof: true,
	})
	require.NoError(t, err)
	input := ast.MustParseTerm(`{"doc":{"kind":"docker","value":"` + placeholder + `","open":["known","` + placeholder + `"]}}`).Value
	results, err := gate.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 2)
	var independent, conditional ast.Value
	for _, result := range results {
		obj := result.(ast.Object)
		id := obj.Get(ast.StringTerm("_dd_id")).Value.(ast.String)
		if id == "independent" {
			independent = result
		} else if id == "conditional" {
			conditional = result
		}
	}
	require.NotNil(t, independent)
	require.NotNil(t, conditional)
	report, err := gate.Check(context.Background(), input, []Candidate{{Result: independent}, {Result: conditional}})
	require.NoError(t, err)
	require.Len(t, report.Verdicts, 2)
	require.False(t, report.Verdicts[0].Uncertain)
	require.Equal(t, StageNone, report.Verdicts[0].Stage)
	require.True(t, report.Verdicts[1].Uncertain)
	require.NotEqual(t, StagePartialProof, report.Verdicts[1].Stage)
	require.Equal(t, 0, report.PartialProofs, "a different output may appear for another unknown value")
}

func TestPartialProofUnknownReferenceShapes(t *testing.T) {
	const placeholder = "__partial_shape_unknown__"
	root := ast.NewObject()
	root.Insert(ast.StringTerm("open_array"), ast.NewTerm(ast.NewArray(ast.StringTerm("known"), ast.StringTerm(placeholder))))
	nested := ast.NewObject()
	nested.Insert(ast.StringTerm("known_value"), ast.StringTerm(placeholder))
	root.Insert(ast.StringTerm("nested"), ast.NewTerm(nested))
	compoundKey := ast.NewObject()
	compoundKey.Insert(ast.StringTerm("prefix-"+placeholder+"-suffix"), ast.IntNumberTerm(1))
	root.Insert(ast.StringTerm("compound_key"), ast.NewTerm(compoundKey))
	root.Insert(ast.StringTerm("embedded_text"), ast.StringTerm("prefix-"+placeholder+"-suffix"))
	root.Insert(ast.StringTerm("embedded_array_text"), ast.NewTerm(ast.NewArray(ast.StringTerm("prefix-"+placeholder+"-suffix"))))
	root.Insert(ast.StringTerm("set"), ast.NewTerm(ast.NewSet(ast.StringTerm("known"), ast.StringTerm("prefix-"+placeholder+"-suffix"))))
	refs := unknownInputRefs(root, newPlaceholder(placeholder))
	paths := make([]string, len(refs))
	for i, ref := range refs {
		paths[i] = ref.String()
	}
	require.ElementsMatch(t, []string{
		"input.open_array",
		"input.nested.known_value",
		"input.compound_key",
		"input.embedded_text",
		"input.embedded_array_text[0]",
		"input.set",
	}, paths)
}

func TestPartialProofPreservesNativeIdentity(t *testing.T) {
	const placeholder = "__partial_identity_unknown__"
	gate := newPartialProofGate(t, placeholder, `package datadog

DatadogPolicy contains {"_dd_id": "one", "path": []} if input.doc.kind == "docker"
DatadogPolicy contains {"_dd_id": "two", "path": [], "key": "stable"} if input.doc.kind == "docker"
`)
	input := mustValue(t, `{"doc":{"kind":"docker","noise":"`+placeholder+`"}}`)
	results, err := gate.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 2)
	report, err := gate.Check(context.Background(), input, []Candidate{{Result: findResultByID(t, results, "one")}, {Result: findResultByID(t, results, "two")}})
	require.NoError(t, err)
	require.Equal(t, 2, report.PartialProofs)
	require.Equal(t, 1, report.PartialProofEvals, "the complete result set is proved once for the check")

	offModule := ast.MustParseModule(`package datadog

DatadogPolicy contains {"_dd_id": "one", "path": []} if input.doc.kind == "docker"
DatadogPolicy contains {"_dd_id": "two", "path": [], "key": "stable"} if input.doc.kind == "docker"
	`)
	offGate, err := New(Options{Placeholder: placeholder, Modules: map[string]*ast.Module{"rule.rego": offModule}, Query: "data.datadog.DatadogPolicy", Store: inmem.New()})
	require.NoError(t, err)
	offReport, err := offGate.Check(context.Background(), input, []Candidate{{Result: findResultByID(t, results, "one")}, {Result: findResultByID(t, results, "two")}})
	require.NoError(t, err)
	require.Zero(t, offReport.PartialProofEvals)
	require.Equal(t, []bool{offReport.Verdicts[0].Uncertain, offReport.Verdicts[1].Uncertain}, []bool{report.Verdicts[0].Uncertain, report.Verdicts[1].Uncertain}, "the shortcut must preserve the no-shortcut certainty result")

	for _, tc := range []struct {
		name  string
		id    string
		newID string
		key   string
		path  string
	}{
		{name: "id mismatch", id: "one", newID: "wrong"},
		{name: "path mismatch", id: "one", newID: "one", path: "wrong"},
		{name: "key mismatch", id: "two", newID: "two", key: "wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := findResultByID(t, results, tc.id)
			wrong := mutateResultIdentity(t, original, tc.newID, tc.key, tc.path)
			got, err := gate.Check(context.Background(), input, []Candidate{{Result: wrong}})
			require.NoError(t, err)
			require.True(t, got.Verdicts[0].Uncertain)
			require.Zero(t, got.PartialProofEvals, "a different identity must not reach the PE shortcut")
		})
	}

}

func TestPartialProofUsesEachCheckInputAndHandlesWithAndAliases(t *testing.T) {
	const placeholder = "__partial_check_input_unknown__"
	gate := newPartialProofGate(t, placeholder, `package datadog

DatadogPolicy contains {"_dd_id": "conditional", "path": []} if {
	value := input.doc.value
	value != "no"
}
`)
	knownInput := mustValue(t, `{"doc":{"value":"yes","noise":"`+placeholder+`"}}`)
	knownResults, err := gate.Results(context.Background(), knownInput)
	require.NoError(t, err)
	report, err := gate.Check(context.Background(), knownInput, []Candidate{{Result: knownResults[0]}})
	require.NoError(t, err)
	require.Equal(t, 1, report.PartialProofs)

	changedInput := mustValue(t, `{"doc":{"value":"`+placeholder+`","noise":"known"}}`)
	changedResults, err := gate.Results(context.Background(), changedInput)
	require.NoError(t, err)
	report, err = gate.Check(context.Background(), changedInput, []Candidate{{Result: changedResults[0]}})
	require.NoError(t, err)
	require.True(t, report.Verdicts[0].Uncertain, "an unknown at a new path on a later Check must not use stale refs")
	require.Zero(t, report.PartialProofs)

	withGate := newPartialProofGate(t, placeholder, `package datadog
DatadogPolicy contains {"_dd_id": "with", "path": []} if {
	input.doc.value == "forced" with input.doc.value as "forced"
}
`)
	withInput := mustValue(t, `{"doc":{"value":"`+placeholder+`"}}`)
	withResults, err := withGate.Results(context.Background(), withInput)
	require.NoError(t, err)
	require.Len(t, withResults, 1)
	withReport, err := withGate.Check(context.Background(), withInput, []Candidate{{Result: withResults[0]}})
	require.NoError(t, err)
	require.Zero(t, withReport.PartialProofs, "the conservative saved-expression guard may fall back for with overrides")
	require.False(t, withReport.Verdicts[0].Uncertain)
}

func TestPartialProofRejectsUnknownAndSetConflictBranches(t *testing.T) {
	const placeholder = "__partial_conflict_unknown__"
	for i, source := range []string{
		`package datadog
DatadogPolicy contains {"_dd_id": "alias", "path": []} if {
	value := input.doc.value
	value != "no"
}

`,
		`package datadog
DatadogPolicy contains {"_dd_id": "negated", "path": []} if not input.doc.value == "no"
`,
		`package datadog
items contains "yes" if input.doc.value != "no"
items contains "no" if input.doc.value == "yes"
DatadogPolicy contains {"_dd_id": "conflict", "path": []} if count(items) == 1
`,
	} {
		t.Run([]string{"alias", "negation", "set conflict"}[i], func(t *testing.T) {
			gate := newPartialProofGate(t, placeholder, source)
			input := mustValue(t, `{"doc":{"value":"`+placeholder+`"}}`)
			results, err := gate.Results(context.Background(), input)
			require.NoError(t, err)
			require.Len(t, results, 1)
			baseline, err := gate.eval(context.Background(), gate.plain, gate.plainBody, input, nil)
			require.NoError(t, err)
			proved, err := gate.proveFullResult(context.Background(), input, unknownInputRefs(input, newPlaceholder(placeholder)), baseline)
			require.NoError(t, err)
			require.False(t, proved, "unknown aliases, negation, or conflicting set branches must remain residual")
		})
	}
}

func TestPartialProofPropagatesBaselineBuiltinErrors(t *testing.T) {
	const placeholder = "__partial_baseline_builtin_error__"
	gate := newPartialProofGate(t, placeholder, `package datadog
DatadogPolicy contains {"_dd_id": "stable", "path": []} if input.doc.kind == "docker"
DatadogPolicy contains {"_dd_id": "number", "path": []} if to_number(input.doc.value) == 1
`)
	input := mustValue(t, `{"doc":{"kind":"docker","value":"`+placeholder+`"}}`)
	results, err := gate.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	_, err = gate.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.ErrorContains(t, err, "partial proof baseline produced builtin errors")
}

func TestPartialProofSkipsNondeterministicPolicies(t *testing.T) {
	const placeholder = "__partial_nondeterministic_unknown__"
	gate := newPartialProofGate(t, placeholder, `package datadog
DatadogPolicy contains {"_dd_id": "clock", "path": []} if {
	time.now_ns(now)
	now >= 0
	input.doc.kind == "docker"
}
`)
	require.True(t, gate.nondeterministic)
	input := mustValue(t, `{"doc":{"kind":"docker","noise":"`+placeholder+`"}}`)
	results, err := gate.Results(context.Background(), input)
	require.NoError(t, err)
	report, err := gate.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.NoError(t, err)
	require.Zero(t, report.PartialProofEvals)
	require.Zero(t, report.PartialProofs)
}

func TestPartialProofPropagatesBaselineStoreErrors(t *testing.T) {
	const placeholder = "__partial_failure_unknown__"
	source := `package datadog
DatadogPolicy contains {"_dd_id": "candidate", "path": []} if input.doc.kind == "docker"
`
	for _, tc := range []struct {
		name    string
		failAt  int
		failure error
	}{
		{name: "baseline store error", failAt: 2, failure: errors.New("partial proof baseline transaction failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := &failOnTransactionStore{Store: inmem.New(), failAt: tc.failAt, failure: tc.failure}
			gate := newPartialProofGateWithStore(t, placeholder, source, store)
			input := mustValue(t, `{"doc":{"kind":"docker","noise":"`+placeholder+`"}}`)
			results, err := gate.Results(ctx, input)
			require.NoError(t, err)
			store.transactions = 0
			_, err = gate.Check(ctx, input, []Candidate{{Result: results[0]}})
			require.ErrorIs(t, err, tc.failure)
		})
	}
}

func TestPartialProofIsConcurrentForPrivateStore(t *testing.T) {
	const placeholder = "__partial_concurrent_unknown__"
	gate := newPartialProofGateWithStore(t, placeholder, `package datadog
DatadogPolicy contains {"_dd_id": "candidate", "path": []} if input.doc.kind == "docker"
`, inmem.New())
	input := mustValue(t, `{"doc":{"kind":"docker","noise":"`+placeholder+`"}}`)
	results, err := gate.Results(context.Background(), input)
	require.NoError(t, err)
	const workers = 8
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report, err := gate.Check(context.Background(), input, []Candidate{{Result: results[0]}})
			if err == nil && (len(report.Verdicts) != 1 || report.PartialProofs != 1 || report.Verdicts[0].Uncertain) {
				err = errors.New("concurrent check did not preserve the partial proof")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func newPartialProofGate(t *testing.T, placeholder, source string) *Gate {
	t.Helper()
	return newPartialProofGateWithStore(t, placeholder, source, inmem.New())
}

func newPartialProofGateWithStore(t *testing.T, placeholder, source string, store storage.Store) *Gate {
	t.Helper()
	gate, err := New(Options{
		Placeholder:        placeholder,
		Modules:            map[string]*ast.Module{"rule.rego": ast.MustParseModule(source)},
		Query:              "data.datadog.DatadogPolicy",
		Store:              store,
		EnablePartialProof: true,
	})
	require.NoError(t, err)
	return gate
}

func findResultByID(t *testing.T, results []ast.Value, id string) ast.Value {
	t.Helper()
	for _, result := range results {
		object, ok := result.(ast.Object)
		if !ok {
			continue
		}
		term := object.Get(ast.StringTerm(fieldBlock))
		if term != nil && term.Value == ast.String(id) {
			return result
		}
	}
	t.Fatalf("missing result %q", id)
	return nil
}

func mutateResultIdentity(t *testing.T, result ast.Value, id, key, path string) ast.Value {
	t.Helper()
	object := result.(ast.Object)
	mutated := ast.NewObject()
	_ = object.Iter(func(k, v *ast.Term) error {
		switch k.Value {
		case ast.String(fieldBlock):
			mutated.Insert(k, ast.StringTerm(id))
		case ast.String(fieldPath):
			if path != "" {
				mutated.Insert(k, ast.NewTerm(ast.NewArray(ast.StringTerm(path))))
			} else {
				mutated.Insert(k, v)
			}
		case ast.String(fieldKey):
			if key != "" {
				mutated.Insert(k, ast.StringTerm(key))
			} else {
				mutated.Insert(k, v)
			}
		default:
			mutated.Insert(k, v)
		}
		return nil
	})
	return mutated
}
