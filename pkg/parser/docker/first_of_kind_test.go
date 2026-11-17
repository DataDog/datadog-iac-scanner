package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFirstOfKindInStageMarksFirstInstructionOfEachKind(t *testing.T) {
	result := parseAnalysis(t, "FROM alpine\nHEALTHCHECK CMD true\nRUN true\nHEALTHCHECK NONE\n")
	var healthchecks, runs []int
	for index, instruction := range result.Instructions {
		switch instruction.Kind {
		case "healthcheck":
			healthchecks = append(healthchecks, index)
		case "run":
			runs = append(runs, index)
		}
	}
	require.Len(t, healthchecks, 2)
	require.True(t, result.Instructions[healthchecks[0]].FirstOfKindInStage)
	require.False(t, result.Instructions[healthchecks[1]].FirstOfKindInStage)
	require.Len(t, runs, 1)
	require.True(t, result.Instructions[runs[0]].FirstOfKindInStage,
		"the first-of-kind fact is independent for each instruction kind")
}

func TestFirstOfKindInStageResetsAtStageBoundaries(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine AS first
HEALTHCHECK CMD true
HEALTHCHECK NONE
FROM alpine AS second
HEALTHCHECK CMD true
`)
	var healthchecks []Instruction
	for _, instruction := range result.Instructions {
		if instruction.Kind == "healthcheck" {
			healthchecks = append(healthchecks, instruction)
		}
	}
	require.Len(t, healthchecks, 3)
	require.True(t, healthchecks[0].FirstOfKindInStage)
	require.False(t, healthchecks[1].FirstOfKindInStage)
	require.True(t, healthchecks[2].FirstOfKindInStage,
		"the first HEALTHCHECK in a later stage is first within that stage")
}

func TestFirstOfKindInStageDoesNotCountNestedOnbuildTrigger(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
HEALTHCHECK CMD true
ONBUILD HEALTHCHECK CMD true
`)
	healthcheck := instructionByKind(t, result, "healthcheck")
	onbuild := instructionByKind(t, result, "onbuild")
	require.NotNil(t, onbuild.Trigger)
	require.Equal(t, "healthcheck", onbuild.Trigger.Kind)
	require.True(t, healthcheck.FirstOfKindInStage,
		"a deferred nested trigger is not a top-level HEALTHCHECK")
	require.True(t, onbuild.FirstOfKindInStage)
	require.False(t, onbuild.Trigger.FirstOfKindInStage,
		"nested deferred instructions do not participate in top-level ordering facts")
}
