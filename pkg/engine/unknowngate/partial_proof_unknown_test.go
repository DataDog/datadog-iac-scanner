package unknowngate

import (
	"context"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/stretchr/testify/require"
)

func TestPartialProofRejectsUnknownBranches(t *testing.T) {
	const placeholder = "__adversarial_full_result_unknown__"
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "duplicate output with unknown builtin branch",
			source: `package datadog
DatadogPolicy contains {"_dd_id": "stable", "path": []} if input.doc.kind == "docker"
DatadogPolicy contains {"_dd_id": "stable", "path": []} if {
  parts := split(input.doc.value, "/")
  count(parts) >= 1
}
`,
		},
		{
			name: "different identity with unknown builtin branch",
			source: `package datadog
DatadogPolicy contains {"_dd_id": "stable", "path": []} if input.doc.kind == "docker"
DatadogPolicy contains {"_dd_id": "other", "path": []} if {
  parts := split(input.doc.value, "/")
  count(parts) >= 2
}
`,
		},
		{
			name: "complete virtual document conflict",
			source: `package datadog
value := 1
value := 2 if input.doc.value == "conflict"
DatadogPolicy contains {"_dd_id": "stable", "path": []} if value == 1
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gate := newPartialProofGate(t, placeholder, tc.source)
			input := mustValue(t, `{"doc":{"kind":"docker","value":"`+placeholder+`"}}`)
			baseline, err := gate.evalErrs(context.Background(), input, new([]topdown.Error))
			require.NoError(t, err)
			require.NotNil(t, baseline)

			proved, err := gate.proveFullResult(
				context.Background(), input, unknownInputRefs(input, newPlaceholder(placeholder)), baseline,
			)
			require.NoError(t, err)
			require.False(t, proved, "an unknown-dependent branch must prevent full-result certification")
		})
	}
}

func TestPartialProofKeepsIndependentKnownResult(t *testing.T) {
	const placeholder = "__adversarial_known_control__"
	gate := newPartialProofGate(t, placeholder, `package datadog
DatadogPolicy contains {"_dd_id": "stable", "path": []} if input.doc.kind == "docker"
DatadogPolicy contains {"_dd_id": "conditional", "path": []} if input.doc.value == "enabled"
`)
	input := mustValue(t, `{"doc":{"kind":"docker","value":"off","noise":"`+placeholder+`"}}`)
	baseline, err := gate.evalErrs(context.Background(), input, new([]topdown.Error))
	require.NoError(t, err)
	require.NotNil(t, baseline)

	proved, err := gate.proveFullResult(
		context.Background(), input, unknownInputRefs(input, newPlaceholder(placeholder)), baseline,
	)
	require.NoError(t, err)
	require.True(t, proved, "an unused unknown field must not block an independent known result")

	results, err := gate.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	identity, _ := newPlaceholder(placeholder).identity(results[0])
	require.NotNil(t, identity)
	_, ok := identity.(ast.Object)
	require.True(t, ok)
}

func TestPartialProofPropagatesTransactionFailures(t *testing.T) {
	const placeholder = "__adversarial_transaction_unknown__"
	gateSource := `package datadog
DatadogPolicy contains {"_dd_id": "stable", "path": []} if input.doc.kind == "docker"
`
	for _, tc := range []struct {
		name    string
		failure error
		cancel  bool
	}{
		{name: "proof store failure", failure: errors.New("full-result proof transaction failed")},
		{name: "proof cancellation", failure: context.Canceled, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := &failOnTransactionStore{Store: inmem.New(), failAt: 3, failure: tc.failure}
			if tc.cancel {
				store.cancel = cancel
			}
			gate := newPartialProofGateWithStore(t, placeholder, gateSource, store)
			input := mustValue(t, `{"doc":{"kind":"docker","noise":"`+placeholder+`"}}`)
			results, err := gate.Results(ctx, input)
			require.NoError(t, err)
			require.Len(t, results, 1)
			store.transactions = 0

			_, err = gate.Check(ctx, input, []Candidate{{Result: results[0]}})
			require.ErrorIs(t, err, tc.failure)
			require.Equal(t, 3, store.transactions, "trace, baseline evaluation, then full-result proof")
		})
	}
}
