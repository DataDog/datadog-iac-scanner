package docker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOnbuildUserMakesOnlyDerivedStagesUnknown(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine AS base
USER 1000
ONBUILD USER nobody
FROM base AS child
RUN echo child
FROM child AS grandchild
USER root
`)
	baseContext := analysis.Contexts[analysis.Instructions[2].Context]
	childContext := analysis.Contexts[analysis.Instructions[3].Context]
	grandchildContext := analysis.Contexts[analysis.Instructions[6].Context]
	require.True(t, baseContext.UserSet)
	require.Equal(t, "1000", baseContext.User.Text)
	require.False(t, baseContext.UserInstructionUnknown)
	require.Equal(t, []int{2}, analysis.Stages[1].InheritedOnbuild)
	require.True(t, childContext.UserSet)
	require.False(t, childContext.User.Known)
	require.True(t, childContext.UserInstructionUnknown)
	require.Equal(t, -1, childContext.UserInstruction)
	require.True(t, grandchildContext.UserSet)
	require.True(t, grandchildContext.User.Known)
	require.Equal(t, "root", grandchildContext.User.Text)
	require.False(t, grandchildContext.UserInstructionUnknown)
	require.Equal(t, 6, grandchildContext.UserInstruction)
}

func TestOnbuildHealthcheckShellEnvAndWorkdirInvalidateChildOnly(t *testing.T) {
	tests := []struct {
		name    string
		onbuild string
		child   string
		check   func(*testing.T, *Analysis, int)
	}{
		{
			name:    "healthcheck",
			onbuild: "ONBUILD HEALTHCHECK NONE",
			child:   "RUN echo child",
			check: func(t *testing.T, analysis *Analysis, childIndex int) {
				context := analysis.Contexts[analysis.Instructions[childIndex].Context]
				require.True(t, context.HealthcheckSet)
				require.False(t, context.Healthcheck.Known)
			},
		},
		{
			name:    "shell",
			onbuild: `ONBUILD SHELL ["powershell", "-Command"]`,
			child:   "RUN Write-Output child",
			check: func(t *testing.T, analysis *Analysis, childIndex int) {
				context := analysis.Contexts[analysis.Instructions[childIndex].Context]
				require.False(t, context.ShellKnown)
				require.Empty(t, analysis.Instructions[childIndex].Execution.Shell)
				require.False(t, analysis.Instructions[childIndex].Execution.ShellKnown)
			},
		},
		{
			name:    "environment",
			onbuild: "ONBUILD ENV MODE=trigger",
			child:   "ENV MODE=local",
			check: func(t *testing.T, analysis *Analysis, childIndex int) {
				context := analysis.Contexts[analysis.Instructions[childIndex].Context]
				require.Equal(t, "local", context.EnvironmentValues["MODE"].Text)
				require.True(t, context.EnvironmentValues["MODE"].Known)
			},
		},
		{
			name:    "workdir",
			onbuild: "ONBUILD WORKDIR /trigger",
			child:   "WORKDIR /local",
			check: func(t *testing.T, analysis *Analysis, childIndex int) {
				context := analysis.Contexts[analysis.Instructions[childIndex].Context]
				require.Equal(t, "/local", context.Workdir.Text)
				require.True(t, context.Workdir.Known)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analysis := parseAnalysis(t, "FROM alpine AS base\n"+test.onbuild+"\nFROM base AS child\n"+test.child+"\n")
			childFrom := analysis.Instructions[2]
			baseContext := analysis.Contexts[analysis.Instructions[1].Context]
			childContext := analysis.Contexts[childFrom.Context]
			require.Len(t, analysis.Stages[1].InheritedOnbuild, 1)
			if test.name == "healthcheck" {
				require.False(t, baseContext.HealthcheckSet, "base context remains independent")
			}
			test.check(t, analysis, 3)
			if test.name == "environment" {
				require.NotContains(t, baseContext.EnvironmentValues, "MODE")
				require.Empty(t, childContext.EnvironmentValues)
			}
		})
	}
}

func TestOnbuildRunOpensChildRunInventoryWithoutInheritingKnownNames(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine AS base
RUN echo base
ONBUILD RUN curl https://example.test
FROM base AS child
RUN wget https://example.test
`)
	require.Equal(t, []string{"echo"}, knownStageCommands(analysis.Stages[0].RunCommands))
	require.Equal(t, []string{"wget"}, knownStageCommands(analysis.Stages[1].RunCommands))
	require.Len(t, unknownStageCommands(analysis.Stages[1].RunCommands), 1)
	require.Equal(t, []int{2}, analysis.Stages[1].InheritedOnbuild)
}

func TestDeferredUserDoesNotClaimParentInstructionAsItsSource(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine AS base
ONBUILD USER nobody
`)
	triggerContext := analysis.Contexts[analysis.Instructions[1].Trigger.Context]
	require.True(t, triggerContext.Deferred)
	require.True(t, triggerContext.UserInstructionUnknown)
	require.Equal(t, -1, triggerContext.UserInstruction)
}

func TestLaterOnbuildTriggerUsesPriorTriggerEffects(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine AS base
USER root
ONBUILD USER nobody
ONBUILD WORKDIR /trigger
`)
	secondTrigger := analysis.Instructions[3].Trigger
	require.NotNil(t, secondTrigger)
	context := analysis.Contexts[secondTrigger.Context]
	require.False(t, context.User.Known)
	require.True(t, context.UserInstructionUnknown)
	require.Equal(t, "/trigger", context.Workdir.Text)
	require.True(t, context.Workdir.Known)
}

func TestUnknownOnbuildTriggerOpensChildRunInventory(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine AS base
ONBUILD MYSTERY command
FROM base AS child
RUN echo known
`)
	require.True(t, analysis.Instructions[1].ParseOK, "outer ONBUILD syntax is valid")
	require.Equal(t, "mystery", analysis.Instructions[1].TriggerKind)
	require.Equal(t, []string{"echo"}, knownStageCommands(analysis.Stages[1].RunCommands))
	require.Len(t, unknownStageCommands(analysis.Stages[1].RunCommands), 1)
	context := analysis.Contexts[analysis.Instructions[2].Context]
	require.True(t, context.UserSetUnknown)
	require.True(t, context.HealthcheckSetUnknown)
}

func TestFailedGlobalArgDoesNotLeaveKnownGlobalArgumentFrame(t *testing.T) {
	analysis := parseAnalysis(t, `ARG =invalid
FROM alpine
`)
	require.False(t, analysis.Instructions[0].ParseOK)
	require.Equal(t, -2, analysis.GlobalArguments)
}

func TestForbiddenOnbuildInstructionsDoNotPanicAndInvalidateChild(t *testing.T) {
	for _, trigger := range []string{"ONBUILD FROM scratch", "ONBUILD MAINTAINER nobody"} {
		t.Run(trigger, func(t *testing.T) {
			analysis := parseAnalysis(t, "FROM alpine AS base\n"+trigger+"\nFROM base AS child\n")
			require.Len(t, analysis.Stages[1].InheritedOnbuild, 1)
			context := analysis.Contexts[analysis.Instructions[2].Context]
			require.True(t, context.UserSetUnknown)
			require.True(t, context.HealthcheckSetUnknown)
		})
	}
}

func TestFailedFromInstructionHasUnknownImage(t *testing.T) {
	analysis := parseAnalysis(t, "FROM alpine\nFROM\n")
	failed := analysis.Instructions[1]
	require.False(t, failed.ParseOK)
	require.NotNil(t, failed.Image)
	require.Equal(t, unknownFact, failed.Image.Kind)
	require.False(t, failed.Image.Reference.Known)
}

func TestFailedShellClearsPreviouslyKnownInterpreter(t *testing.T) {
	analysis := parseAnalysis(t, `FROM alpine
SHELL ["/bin/bash", "-c"]
SHELL []
RUN echo uncertain
`)
	failedShell := analysis.Instructions[2]
	run := analysis.Instructions[3]
	require.False(t, failedShell.ParseOK)
	require.False(t, run.Execution.ShellKnown)
	require.False(t, analysis.Contexts[run.Context].ShellKnown)
	require.Empty(t, analysis.Contexts[run.Context].Shell)
}
