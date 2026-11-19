package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalysisMarksOnlyTopLevelFinalStageInstructions(t *testing.T) {
	result := parseAnalysis(t, `ARG BASE=alpine
FROM ${BASE} AS build
CMD ["echo", "build"]
ENTRYPOINT echo build
FROM ${BASE} AS final
CMD ["echo", "final"]
ENTRYPOINT echo final
ONBUILD CMD ["echo", "deferred"]
`)
	require.Len(t, result.Stages, 2)
	require.False(t, result.Instructions[0].FinalStage, "pre-FROM instructions are outside a stage")

	var earlierCMD, earlierEntrypoint, finalCMD, finalEntrypoint, onbuild *Instruction
	for i := range result.Instructions {
		instruction := &result.Instructions[i]
		switch {
		case instruction.Kind == "cmd" && instruction.Stage == 0:
			earlierCMD = instruction
		case instruction.Kind == "entrypoint" && instruction.Stage == 0:
			earlierEntrypoint = instruction
		case instruction.Kind == "cmd" && instruction.Stage == 1:
			finalCMD = instruction
		case instruction.Kind == "entrypoint" && instruction.Stage == 1:
			finalEntrypoint = instruction
		case instruction.Kind == "onbuild":
			onbuild = instruction
		}
	}
	require.NotNil(t, earlierCMD)
	require.NotNil(t, earlierEntrypoint)
	require.NotNil(t, finalCMD)
	require.NotNil(t, finalEntrypoint)
	require.NotNil(t, onbuild)
	require.False(t, earlierCMD.FinalStage)
	require.False(t, earlierEntrypoint.FinalStage)
	require.True(t, finalCMD.FinalStage)
	require.True(t, finalEntrypoint.FinalStage)
	require.True(t, onbuild.FinalStage, "the top-level ONBUILD declaration is in the final stage")
	require.NotNil(t, onbuild.Trigger)
	require.False(t, onbuild.Trigger.FinalStage, "the deferred nested trigger is not a selected top-level instruction")
	require.True(t, result.Contexts[onbuild.Trigger.Context].Deferred)
}

func TestAnalysisWithoutStagesHasNoFinalStageInstructions(t *testing.T) {
	result := parseAnalysis(t, "ARG BASE=alpine\nARG OTHER\n")
	require.Empty(t, result.Stages)
	require.Len(t, result.Instructions, 2)
	for _, instruction := range result.Instructions {
		require.False(t, instruction.FinalStage)
	}
}

func TestFinalStageFactDoesNotChangeCommandForm(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine AS build
CMD ["/bin/echo", "build"]
FROM alpine AS final
CMD ["/bin/echo", "json"]
ENTRYPOINT echo shell
`)
	var jsonCMD, shellEntrypoint *Instruction
	for i := range result.Instructions {
		instruction := &result.Instructions[i]
		if instruction.Kind == "cmd" && instruction.Stage == 1 {
			jsonCMD = instruction
		}
		if instruction.Kind == "entrypoint" && instruction.Stage == 1 {
			shellEntrypoint = instruction
		}
	}
	require.NotNil(t, jsonCMD)
	require.NotNil(t, jsonCMD.Execution)
	require.True(t, jsonCMD.FinalStage)
	require.Equal(t, "exec", jsonCMD.Execution.Form)
	require.Equal(t, []string{"/bin/echo", "json"}, jsonCMD.Execution.Argv)
	require.NotNil(t, shellEntrypoint)
	require.NotNil(t, shellEntrypoint.Execution)
	require.True(t, shellEntrypoint.FinalStage)
	require.Equal(t, "shell", shellEntrypoint.Execution.Form)
	require.Equal(t, "echo shell", shellEntrypoint.Execution.Script)
}
