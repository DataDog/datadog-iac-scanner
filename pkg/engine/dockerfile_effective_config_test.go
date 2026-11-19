package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerEffectiveExternalConfigReadsRemainUnknown(t *testing.T) {
	for _, tc := range []struct {
		name, content, condition string
	}{
		{"context user name absence", "FROM alpine\n", `not context.user_name.value`},
		{"context workdir absence", "FROM alpine\n", `not context.workdir.value`},
		{"context healthcheck absence", "FROM alpine\n", `not context.healthcheck.configured`},
		{"context shell absence", "FROM alpine\n", `not context.shell[0]`},
		{"external env key absence", "FROM alpine\n", `not context.environment_values.FOO`},
		{"dynamic healthcheck execution absence", "ARG BASE=base\nFROM alpine AS base\nHEALTHCHECK CMD true\nFROM $BASE\n", `not context.healthcheck.execution.form`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireDockerEffectiveConfigFindings(t, tc.content, tc.condition, 1, 0)
		})
	}
}

func TestDockerEffectiveTriggerContextUnknownAndKnown(t *testing.T) {
	for _, tc := range []struct {
		name, content, condition string
		wantAfter                int
	}{
		{
			"external base trigger context remains unknown",
			"FROM alpine\nONBUILD RUN echo deferred\n",
			`not trigger_context.user.value`,
			0,
		},
		{
			"explicit local user remains known in trigger context",
			"FROM alpine\nUSER app\nONBUILD RUN echo deferred\n",
			`trigger_context.user.value == "app"`,
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := withDockerContractVersion("1", `package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/0", "path":[]} if {
 model := input.document[0]._dockerfile
 some instruction in model.instructions
 instruction.kind == "onbuild"
 trigger_context := model.contexts[instruction.trigger.context]
 `+tc.condition+`
}`)
			d, query, loader, results := dockerGateRun(t, []string{tc.content}, []string{"fixture"}, dockerGateTestLibrary, rule)
			items, err := resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, 1)
			require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
				context.Background(), dockerGateContext(query), d, d.payload, results,
			))
			items, err = resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, tc.wantAfter)
		})
	}
}

func TestDockerEffectiveExternalConfigKeepsDirectivePresenceKnown(t *testing.T) {
	for _, tc := range []struct {
		name, condition string
	}{
		{"no local USER directive", `context.user_set != true`},
		{"no local HEALTHCHECK directive", `context.healthcheck_set != true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireDockerEffectiveConfigFindings(t, "FROM alpine\n", tc.condition, 1, 1)
		})
	}
}

func TestDockerEffectiveLocalConfigAndInheritanceRemainKnown(t *testing.T) {
	for _, tc := range []struct {
		name, content, condition string
	}{
		{
			"explicit local values",
			"FROM alpine\nUSER app\nWORKDIR /srv\nSHELL [\"/bin/bash\", \"-c\"]\nHEALTHCHECK CMD true\n",
			`context.user.value == "app"; context.workdir.value == "/srv"; context.shell[0] == "/bin/bash"; context.healthcheck.configured == true`,
		},
		{
			"locally inherited values",
			"FROM alpine AS base\nUSER app\nWORKDIR /srv\nSHELL [\"/bin/bash\", \"-c\"]\nHEALTHCHECK CMD true\nFROM base\n",
			`context.user.value == "app"; context.workdir.value == "/srv"; context.shell[0] == "/bin/bash"; context.healthcheck.configured == true`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireDockerEffectiveConfigFindings(t, tc.content, tc.condition, 1, 1)
		})
	}
}

func requireDockerEffectiveConfigFindings(t *testing.T, content, condition string, wantBefore, wantAfter int) {
	t.Helper()
	rule := withDockerContractVersion("1", `package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/0", "path":[]} if {
 model := input.document[0]._dockerfile
 stage := model.stages[count(model.stages)-1]
 context := model.contexts[stage.context]
 `+condition+`
}`)
	d, query, loader, results := dockerGateRun(t, []string{content}, []string{"fixture"}, dockerGateTestLibrary, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, wantBefore, "rule candidate count before uncertainty gating")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, wantAfter, "rule finding count after uncertainty gating")
}
