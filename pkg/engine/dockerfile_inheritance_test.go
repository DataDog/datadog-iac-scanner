package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerUnknownBaseCannotCertifyConfigurationAbsence(t *testing.T) {
	const dynamic = "ARG BASE=builder\nFROM alpine AS builder\nUSER app\nHEALTHCHECK CMD true\nFROM $BASE AS final\n"
	for _, tc := range []struct {
		name, content, check string
		want                 int
	}{
		{"unknown inherited user directive", dynamic, `context.user_set != true`, 0},
		{"unknown inherited healthcheck directive", dynamic, `context.healthcheck_set != true`, 0},
		{"unknown inherited user value", dynamic, `context.user.value != "app"`, 0},
		{"instruction resolves effective context", dynamic, `model.contexts[model.instructions[count(model.instructions)-1].context].user_set != true`, 0},
		{"unknown inherited environment", "ARG BASE=builder\nFROM alpine AS builder\nENV FOO=bar\nFROM $BASE\n", `not context.environment_values.FOO`, 0},
		{"unknown inherited username presence", dynamic, `not context.user_name.value`, 0},
		{"known external absence", "FROM alpine\n", `context.user_set != true`, 1},
		{"known local inheritance", "FROM alpine AS builder\nUSER app\nFROM builder\n", `context.user_set != true`, 0},
		{"explicit value after unknown base", dynamic + "USER root\n", `context.user.value == "root"`, 1},
		{"independent stage sharing original context", "ARG BASE\nFROM alpine AS first\nFROM $BASE AS uncertain\nFROM alpine AS final\n", `context.user_set != true`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := withDockerContractVersion("1", `package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/0", "path":[]} if {
 model := input.document[0]._dockerfile
 stage := model.stages[count(model.stages)-1]
 context := model.contexts[stage.context]
 `+tc.check+`
}`)
			d, query, loader, results := dockerGateRun(t, []string{tc.content}, []string{"fixture"}, dockerGateTestLibrary, rule)
			require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(context.Background(), dockerGateContext(query), d, d.payload, results))
			items, err := resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, tc.want)
		})
	}
}
