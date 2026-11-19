package unknowngate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSubstitutionValuesKeepsUnknownFunctionHeadConstants(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

blocked("secret") if true
unrelated("hidden") if true

DatadogPolicy contains {"rule": "sample"} if {
	not blocked(input.value)
	unrelated("hidden")
}
`)

	input := mustValue(t, `{"value":"`+testPlaceholder+`"}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Contains(t, valueStrings(g.values), `"secret"`)
	require.NotContains(t, valueStrings(g.values), `"hidden"`, "a known function argument does not need its head constant")
	fullReport, err := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.NoError(t, err)
	require.True(t, fullReport.Verdicts[0].Uncertain, "the full gate suppresses the unknown candidate")

	ph := newPlaceholder(testPlaceholder)
	id, mask := ph.identity(results[0])
	jobs := []job{{index: 0, cand: Candidate{Result: results[0]}, id: id, mask: mask}}
	out := make([]Verdict, 1)
	sub := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	require.NoError(t, sub.batch(jobs, out))
	require.True(t, out[0].Uncertain, "the Stage 2 secret replacement removes the candidate")
	require.Equal(t, StageSubstitution, out[0].Stage)

	knownInput := mustValue(t, `{"value":"public"}`)
	knownResults, err := g.Results(context.Background(), knownInput)
	require.NoError(t, err)
	require.Len(t, knownResults, 1)
	knownReport, err := g.Check(context.Background(), knownInput, []Candidate{{Result: knownResults[0]}})
	require.NoError(t, err)
	require.False(t, knownReport.Verdicts[0].Uncertain, "a known non-placeholder control stays certain")
}
