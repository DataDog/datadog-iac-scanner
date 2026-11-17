package docker

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstructionIndexTracksTopLevelSourcePositions(t *testing.T) {
	result := parseAnalysis(t, `ARG BASE=alpine
FROM ${BASE} AS build
RUN echo build
ONBUILD RUN echo deferred
FROM build AS final
CMD ["echo", "final"]
`)
	require.Len(t, result.Instructions, 6)
	for i, instruction := range result.Instructions {
		require.Equal(t, i, instruction.Index, "index should match the original top-level position")
	}
	onbuild := result.Instructions[3]
	require.NotNil(t, onbuild.Trigger)
	require.Equal(t, -1, onbuild.Trigger.Index, "nested ONBUILD instructions are outside the source file's instruction array")

	serialized, err := json.Marshal(result)
	require.NoError(t, err)
	var decoded struct {
		Instructions []map[string]interface{} `json:"instructions"`
	}
	require.NoError(t, json.Unmarshal(serialized, &decoded))
	require.Len(t, decoded.Instructions, len(result.Instructions))
	for i, instruction := range decoded.Instructions {
		value, present := instruction["index"]
		require.True(t, present, "serialized instruction %d must include index", i)
		require.Equal(t, float64(i), value)
	}
	require.Equal(t, float64(-1), decoded.Instructions[3]["trigger"].(map[string]interface{})["index"])
}
