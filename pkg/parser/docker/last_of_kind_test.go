package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLastOfKindInStageMarksLastInstructionOfEachKind(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
CMD first
ENTRYPOINT first
RUN true
CMD second
ENTRYPOINT second
`)
	var cmds, entrypoints, runs []int
	for index, instruction := range result.Instructions {
		switch instruction.Kind {
		case "cmd":
			cmds = append(cmds, index)
		case "entrypoint":
			entrypoints = append(entrypoints, index)
		case "run":
			runs = append(runs, index)
		}
	}
	require.Len(t, cmds, 2)
	require.False(t, result.Instructions[cmds[0]].LastOfKindInStage)
	require.True(t, result.Instructions[cmds[1]].LastOfKindInStage)
	require.Len(t, entrypoints, 2)
	require.False(t, result.Instructions[entrypoints[0]].LastOfKindInStage)
	require.True(t, result.Instructions[entrypoints[1]].LastOfKindInStage)
	require.Len(t, runs, 1)
	require.True(t, result.Instructions[runs[0]].LastOfKindInStage,
		"last-of-kind facts are tracked independently by instruction kind")
}

func TestLastOfKindInStageResetsAtStageBoundaries(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine AS first
CMD first-stage-one
CMD first-stage-two
FROM alpine AS second
CMD second-stage
`)
	var cmds []Instruction
	for _, instruction := range result.Instructions {
		if instruction.Kind == "cmd" {
			cmds = append(cmds, instruction)
		}
	}
	require.Len(t, cmds, 3)
	require.False(t, cmds[0].LastOfKindInStage)
	require.True(t, cmds[1].LastOfKindInStage)
	require.True(t, cmds[2].LastOfKindInStage,
		"a kind with one instruction in a later stage is last within that stage")
}

func TestLastOfKindInStageDoesNotCountNestedOnbuildTrigger(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
CMD executable
ONBUILD CMD deferred
`)
	cmd := instructionByKind(t, result, "cmd")
	onbuild := instructionByKind(t, result, "onbuild")
	require.NotNil(t, onbuild.Trigger)
	require.Equal(t, "cmd", onbuild.Trigger.Kind)
	require.True(t, cmd.LastOfKindInStage,
		"a deferred nested trigger is not a top-level CMD")
	require.False(t, onbuild.Trigger.LastOfKindInStage,
		"nested deferred instructions do not participate in top-level source ordering")
}
