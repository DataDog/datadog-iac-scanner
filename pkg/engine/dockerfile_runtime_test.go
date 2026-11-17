package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeCommandSyntaxIsKnownWhileExecutionIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name, condition string
		kept            int
	}{
		{"known syntax", `instruction.syntax.form == "shell"`, 1},
		{"unproven command absence", `not has_command(instruction.execution)`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := withDockerContractVersion("1", `package datadog
has_command(execution) if { some call in execution.calls; call.name == "tool" }
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/1", "path":[]} if {
 instruction := input.document[0]._dockerfile.instructions[1]
 `+tc.condition+`
}`)
			d, query, loader, results := dockerGateRun(t, []string{"FROM alpine\nCMD echo runtime\n"}, []string{"fixture"}, dockerGateTestLibrary, rule)
			items, err := resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, 1, "both predicates produce a candidate before certainty validation")
			require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(context.Background(), dockerGateContext(query), d, d.payload, results))
			items, err = resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, tc.kept)
		})
	}
}
