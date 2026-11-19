package engine

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestProjectDockerFailedInstructionFacts(t *testing.T) {
	const placeholder = "opaque-failed-fact"
	knownRunExecution := map[string]interface{}{"form": "shell", "calls": []interface{}{map[string]interface{}{"name": "pip"}}}
	knownRunSyntax := map[string]interface{}{"form": "shell", "script": "pip install flask"}
	knownFromImage := map[string]interface{}{"kind": "unknown", "reference": map[string]interface{}{"known": false}}
	knownCopyFrom := map[string]interface{}{"value": "builder", "known": true}
	facts := map[string]interface{}{
		"instructions": []interface{}{
			map[string]interface{}{"kind": "from", "parse_ok": false, "image": knownFromImage},
			map[string]interface{}{"kind": "run", "parse_ok": false, "execution": knownRunExecution, "syntax": knownRunSyntax},
			map[string]interface{}{"kind": "run", "parse_ok": false},
			map[string]interface{}{"kind": "cmd", "parse_ok": false},
			map[string]interface{}{"kind": "entrypoint", "parse_ok": false},
			map[string]interface{}{"kind": "user", "parse_ok": false},
			map[string]interface{}{"kind": "workdir", "parse_ok": false},
			map[string]interface{}{"kind": "copy", "parse_ok": false},
			map[string]interface{}{"kind": "add", "parse_ok": false},
			map[string]interface{}{"kind": "healthcheck", "parse_ok": false},
			map[string]interface{}{"kind": "arg", "parse_ok": false, "bindings": []interface{}{map[string]interface{}{"name": "A"}}},
			map[string]interface{}{"kind": "env", "parse_ok": false},
			map[string]interface{}{"kind": "label", "parse_ok": false},
			map[string]interface{}{"kind": "expose", "parse_ok": false},
			map[string]interface{}{"kind": "volume", "parse_ok": false},
			map[string]interface{}{"kind": "shell", "parse_ok": false},
			map[string]interface{}{
				"kind": "onbuild", "parse_ok": true,
				"trigger": map[string]interface{}{
					"kind": "copy", "parse_ok": true,
					"copy": map[string]interface{}{"from": knownCopyFrom, "from_kind": map[string]interface{}{"value": "name"}, "source_stage": -1},
				},
			},
		},
	}

	projectDockerFailedInstructionFacts(facts, placeholder)

	instructions := facts["instructions"].([]interface{})
	from := instructions[0].(map[string]interface{})
	require.Equal(t, knownFromImage, from["image"], "FROM relation tainting needs the parser's unknown image structure")
	knownRun := instructions[1].(map[string]interface{})
	require.Equal(t, knownRunExecution, knownRun["execution"], "mount expansion failure must retain independently parsed RUN execution")
	require.Equal(t, knownRunSyntax, knownRun["syntax"])
	failedRun := instructions[2].(map[string]interface{})
	require.Equal(t, placeholder, failedRun["execution"])
	require.Equal(t, placeholder, failedRun["syntax"])
	for _, index := range []int{3, 4} {
		command := instructions[index].(map[string]interface{})
		require.Equal(t, placeholder, command["execution"])
		require.Equal(t, placeholder, command["syntax"])
	}
	for _, index := range []int{5, 6} {
		require.Equal(t, placeholder, instructions[index].(map[string]interface{})["value"])
	}
	for _, index := range []int{7, 8} {
		require.Equal(t, placeholder, instructions[index].(map[string]interface{})["copy"])
	}
	require.Equal(t, placeholder, instructions[9].(map[string]interface{})["healthcheck"])
	arg := instructions[10].(map[string]interface{})["bindings"].([]interface{})
	require.Equal(t, 2, len(arg), "existing partial bindings remain alongside the open marker")
	require.Equal(t, placeholder, arg[1])
	for _, index := range []int{11, 12} {
		require.Equal(t, []interface{}{placeholder}, instructions[index].(map[string]interface{})["bindings"])
	}
	expose := instructions[13].(map[string]interface{})
	require.Equal(t, []interface{}{placeholder}, expose["values"])
	require.Equal(t, []interface{}{placeholder}, expose["ports"])
	for _, index := range []int{14, 15} {
		require.Equal(t, []interface{}{placeholder}, instructions[index].(map[string]interface{})["values"])
	}
	onbuild := instructions[16].(map[string]interface{})
	trigger := onbuild["trigger"].(map[string]interface{})
	copyFacts := trigger["copy"].(map[string]interface{})
	require.Equal(t, placeholder, copyFacts["source_stage"])
	require.Equal(t, knownCopyFrom, copyFacts["from"], "authored FROM syntax remains available")
	require.Equal(t, "name", copyFacts["from_kind"].(map[string]interface{})["value"])
}

func TestDockerRuleInputKeepsExecutionUnknownOnlyForFailedShellForm(t *testing.T) {
	content := `FROM alpine
SHELL ["/bin/bash", "-c"]
SHELL []
RUN echo shell-dependent
RUN ["echo", "exec-form"]
`
	input, err := newDockerRuleInput(dockerGateTestInput(t, content))
	require.NoError(t, err)
	raw, err := ast.ValueToInterface(input.payload, nil)
	require.NoError(t, err)
	facts := raw.(map[string]interface{})["document"].([]interface{})[0].(map[string]interface{})["_dockerfile"].(map[string]interface{})
	instructions := facts["instructions"].([]interface{})
	failedShell := instructions[2].(map[string]interface{})
	require.NotContains(t, failedShell, "parse_ok")
	require.Equal(t, input.placeholder, failedShell["values"].([]interface{})[0])
	shellRun := instructions[3].(map[string]interface{})
	require.Equal(t, input.placeholder, shellRun["execution"])
	require.Equal(t, "shell", shellRun["syntax"].(map[string]interface{})["form"])
	execRun := instructions[4].(map[string]interface{})
	execution := execRun["execution"].(map[string]interface{})
	require.Equal(t, "exec", execution["form"])
	require.Equal(t, []interface{}{"echo", "exec-form"}, execution["argv"])
}
