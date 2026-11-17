package engine

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestProjectDockerUnknownContextSetters(t *testing.T) {
	const placeholder = "opaque-context-uncertainty"
	facts := map[string]interface{}{
		"global_arguments": -2,
		"bindings":         []interface{}{map[string]interface{}{"parent": -2}, map[string]interface{}{"parent": -1}},
		"contexts": []interface{}{
			map[string]interface{}{
				"user_set": false, "user_set_unknown": true,
				"user_instruction": -1, "user_instruction_unknown": true,
				"healthcheck_set": false, "healthcheck_set_unknown": true,
			},
			map[string]interface{}{
				"user_set": true, "user_set_unknown": false,
				"user_instruction": 3, "user_instruction_unknown": false,
				"healthcheck_set": true, "healthcheck_set_unknown": false,
			},
			map[string]interface{}{"deferred": true, "user_instruction": 4},
			map[string]interface{}{"environment": -2, "arguments": -2, "user_instruction": -1},
		},
	}

	projectDockerUnknownContextSetters(facts, placeholder)

	contexts := facts["contexts"].([]interface{})
	unknown := contexts[0].(map[string]interface{})
	require.Equal(t, placeholder, unknown["user_set"])
	require.Equal(t, placeholder, unknown["user_instruction"])
	require.Equal(t, placeholder, unknown["healthcheck_set"])
	for _, marker := range []string{"user_set_unknown", "user_instruction_unknown", "healthcheck_set_unknown"} {
		require.NotContains(t, unknown, marker)
	}
	known := contexts[1].(map[string]interface{})
	require.Equal(t, true, known["user_set"])
	require.Equal(t, 3, known["user_instruction"])
	require.Equal(t, true, known["healthcheck_set"])
	for _, marker := range []string{"user_set_unknown", "user_instruction_unknown", "healthcheck_set_unknown"} {
		require.NotContains(t, known, marker)
	}
	deferred := contexts[2].(map[string]interface{})
	require.Equal(t, placeholder, deferred["user_instruction"])
	unknownFrames := contexts[3].(map[string]interface{})
	require.Equal(t, placeholder, unknownFrames["environment"])
	require.Equal(t, placeholder, unknownFrames["arguments"])
	require.Equal(t, -1, unknownFrames["user_instruction"], "known absence remains -1")
	require.Equal(t, placeholder, facts["global_arguments"])
	bindings := facts["bindings"].([]interface{})
	require.Equal(t, placeholder, bindings[0].(map[string]interface{})["parent"])
	require.Equal(t, -1, bindings[1].(map[string]interface{})["parent"], "known absence remains -1")
}

func TestNewDockerRuleInputProjectsContextSettersAsOpaqueValues(t *testing.T) {
	const placeholder = "opaque-test-context"
	facts := map[string]interface{}{
		"contexts": []interface{}{map[string]interface{}{
			"user_set": false, "user_set_unknown": true,
			"user_instruction": -1, "user_instruction_unknown": true,
			"healthcheck_set": false, "healthcheck_set_unknown": true,
		}},
	}
	projectDockerUnknownContextSetters(facts, placeholder)
	projectDockerUnknowns(facts, placeholder)
	removeDockerParserMetadata(facts, placeholder)
	context := facts["contexts"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, placeholder, context["user_set"])
	require.Equal(t, placeholder, context["user_instruction"])
	require.Equal(t, placeholder, context["healthcheck_set"])
	require.NotContains(t, context, "user_set_unknown")
	require.NotContains(t, context, "user_instruction_unknown")
	require.NotContains(t, context, "healthcheck_set_unknown")
}

func TestProjectDockerUnknownStageRunCommandsOpensInventory(t *testing.T) {
	const placeholder = "opaque-run-inventory"
	knownWget := map[string]interface{}{"value": "wget", "known": true}
	knownApk := map[string]interface{}{"value": "apk", "known": true}
	facts := map[string]interface{}{
		"stages": []interface{}{
			map[string]interface{}{"run_commands": []interface{}{knownWget, map[string]interface{}{"value": "", "known": false}, knownApk}},
			map[string]interface{}{"run_commands": []interface{}{knownWget}},
			map[string]interface{}{"run_commands": []interface{}{placeholder}},
		},
	}

	projectDockerUnknownStageRunCommands(facts, placeholder)

	stages := facts["stages"].([]interface{})
	require.Equal(t, []interface{}{knownWget, knownApk, placeholder}, stages[0].(map[string]interface{})["run_commands"])
	require.Equal(t, []interface{}{knownWget}, stages[1].(map[string]interface{})["run_commands"], "known singleton inventory stays closed")
	require.Equal(t, []interface{}{placeholder}, stages[2].(map[string]interface{})["run_commands"], "an existing opaque marker remains a singleton open inventory")
}

func TestDockerGateSuppressesCountFromOpenStageRunInventory(t *testing.T) {
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id": stage._dd_meta.id, "path": []} if {
 some document in input.document
 some stage in document._dockerfile.stages
 count(stage.run_commands) == 1
}`
	content := `FROM alpine AS base
ONBUILD RUN curl https://example.test
FROM base AS child
`
	d, query, loader, results := dockerGateRun(t, []string{content}, []string{"fixture"}, dockerGateTestLibrary, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the one unknown inherited command creates a count candidate")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		t.Context(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Empty(t, items, "the direct open-inventory marker prevents a false singleton count")

	known, knownQuery, knownLoader, knownResults := dockerGateRun(t, []string{"FROM alpine\nRUN [\"echo\", \"known\"]\n"}, []string{"known"}, dockerGateTestLibrary, rule)
	knownItems, err := resultItems(knownResults)
	require.NoError(t, err)
	require.Len(t, knownItems, 1)
	require.NoError(t, (&Inspector{QueryLoader: knownLoader}).gateDockerResults(
		t.Context(), dockerGateContext(knownQuery), known, known.payload, knownResults,
	))
	knownItems, err = resultItems(knownResults)
	require.NoError(t, err)
	require.Len(t, knownItems, 1, "a known singleton command inventory remains reportable")
}

func TestDockerRuleInputProjectsInheritedUserSourceAndFrameUnknowns(t *testing.T) {
	content := `FROM alpine AS base
USER 1000
ONBUILD USER nobody
ONBUILD COPY --from=build /out /out
FROM base AS child
FROM alpine AS independent
USER root
`
	input, err := newDockerRuleInput(dockerGateTestInput(t, content))
	require.NoError(t, err)
	raw, err := ast.ValueToInterface(input.payload, nil)
	require.NoError(t, err)
	facts := raw.(map[string]interface{})["document"].([]interface{})[0].(map[string]interface{})["_dockerfile"].(map[string]interface{})
	contexts := facts["contexts"].([]interface{})
	stages := facts["stages"].([]interface{})
	child := stages[1].(map[string]interface{})
	childContext := contexts[dockerFactIndexForTest(t, child["context"])].(map[string]interface{})
	require.True(t, childContext["user_set"].(bool))
	require.Equal(t, input.placeholder, childContext["user_instruction"])
	independent := stages[2].(map[string]interface{})
	independentContext := contexts[dockerFactIndexForTest(t, independent["context"])].(map[string]interface{})
	require.Equal(t, 6, dockerFactIndexForTest(t, independentContext["user_instruction"]))
	for _, context := range contexts {
		fields := context.(map[string]interface{})
		require.NotContains(t, fields, "user_set_unknown")
		require.NotContains(t, fields, "user_instruction_unknown")
		require.NotContains(t, fields, "healthcheck_set_unknown")
		if fields["deferred"] == true {
			require.Equal(t, input.placeholder, fields["user_instruction"])
		}
	}
	instructions := facts["instructions"].([]interface{})
	onbuildCopy := instructions[3].(map[string]interface{})["trigger"].(map[string]interface{})["copy"].(map[string]interface{})
	require.Equal(t, input.placeholder, onbuildCopy["source_stage"])
	require.Equal(t, "build", onbuildCopy["from"].(map[string]interface{})["value"])
	require.Equal(t, "name", onbuildCopy["from_kind"].(map[string]interface{})["value"])
}

func dockerFactIndexForTest(t *testing.T, raw interface{}) int {
	t.Helper()
	index, ok := dockerFactIndex(raw)
	require.True(t, ok)
	return index
}
