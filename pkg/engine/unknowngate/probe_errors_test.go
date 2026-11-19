package unknowngate

import (
	"context"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/stretchr/testify/require"
)

type failOnTransactionStore struct {
	storage.Store
	transactions int
	failAt       int
	failure      error
	cancel       context.CancelFunc
}

func (s *failOnTransactionStore) NewTransaction(ctx context.Context, params ...storage.TransactionParams) (storage.Transaction, error) {
	s.transactions++
	if s.transactions == s.failAt {
		if s.cancel != nil {
			s.cancel()
		}
		return nil, s.failure
	}
	return s.Store.NewTransaction(ctx, params...)
}

func probeCheckGate(t testing.TB, store storage.Store) *Gate {
	t.Helper()
	sources := map[string]string{
		"lib.rego": `package generic.lib
import rego.v1

read(_arg) := data.other.value if data.test.enabled
`,
		"rule.rego": `package datadog
import rego.v1

allowed if {
	input.value == "known"
	data.generic.lib.read("ignored", name)
	name == "never"
}

DatadogPolicy contains {"rule": "probe", "name": "always"} if not allowed
`,
	}
	g := newMultiModuleGateWithStore(t, testPlaceholder, sources, store)
	// A tracer-only check isolates stage 1: any second transaction can only be a helper probe.
	g.tracerOnly = true
	return g
}

func TestCheckPropagatesProbeStoreError(t *testing.T) {
	sentinel := errors.New("probe transaction failed")
	store := &failOnTransactionStore{
		Store:   inmem.NewFromObject(map[string]any{"test": map[string]any{"enabled": true}, "other": map[string]any{"value": "x"}}),
		failAt:  2,
		failure: sentinel,
	}
	g := probeCheckGate(t, store)
	input := mustValue(t, `{"value":"`+testPlaceholder+`"}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	store.transactions = 0
	store.failAt = 2
	candidate := Candidate{Result: results[0]}

	_, err = g.Check(context.Background(), input, []Candidate{candidate})

	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 2, store.transactions, "one transaction for tracing and one for the probe")
}

func TestCheckPropagatesCancellationFromProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &failOnTransactionStore{
		Store:   inmem.NewFromObject(map[string]any{"test": map[string]any{"enabled": true}, "other": map[string]any{"value": "x"}}),
		failAt:  2,
		failure: context.Canceled,
		cancel:  cancel,
	}
	g := probeCheckGate(t, store)
	input := mustValue(t, `{"value":"`+testPlaceholder+`"}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	store.transactions = 0
	store.failAt = 2
	candidate := Candidate{Result: results[0]}

	_, err = g.Check(ctx, input, []Candidate{candidate})

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 2, store.transactions, "cancellation must arise in the helper probe")
}
