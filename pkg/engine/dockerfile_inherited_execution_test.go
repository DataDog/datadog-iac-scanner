package engine

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestDockerDynamicBaseDoesNotCertifyInheritedShellCalls(t *testing.T) {
	const content = "ARG BASE=builder\nFROM alpine AS builder\nSHELL [\"python\",\"-c\"]\nFROM $BASE AS final\nRUN sudo true\n"
	document := dockerRootTestDocument(t, "fixture", content)
	facts := document["_dockerfile"].(map[string]interface{})
	_, run := dockerRunInstructionForTest(t, facts)
	execution := run["execution"].(map[string]interface{})
	require.Equal(t, "shell", execution["form"])
	require.Equal(t, false, execution["shell_known"])
	require.True(t, dockerHasCallWrapper(execution["calls"], "sudo"), "the parser currently applies its default sh grammar despite the unresolved local base")
	require.Contains(t, dockerRunCommandNames(facts["stages"].([]interface{})[1]), "true")

	projectedFacts := cloneDockerInheritanceValue(facts).(map[string]interface{})
	taintUnknownDockerStageRelationships(projectedFacts, "unknown-stage")
	taintUnknownDockerInheritedExecution(projectedFacts, "unknown-stage")
	_, projectedRun := dockerRunInstructionForTest(t, projectedFacts)
	require.Equal(t, "unknown-stage", projectedRun["execution"])
	require.Equal(t, "shell", projectedRun["syntax"].(map[string]interface{})["form"])
	require.Equal(t, "sudo true", projectedRun["syntax"].(map[string]interface{})["script"])
	require.Equal(t, []interface{}{"unknown-stage"}, dockerRunCommandValues(projectedFacts["stages"].([]interface{})[1]))
}

func TestDockerExternalBaseShellStartsUnknown(t *testing.T) {
	const content = "FROM custom-image\nRUN sudo true\n"
	document := dockerRootTestDocument(t, "fixture", content)
	facts := document["_dockerfile"].(map[string]interface{})
	_, run := dockerRunInstructionForTest(t, facts)
	execution := run["execution"].(map[string]interface{})
	require.Equal(t, false, execution["shell_known"], "external image SHELL metadata is not available to the parser")
	require.True(t, dockerHasCallWrapper(execution["calls"], "sudo"), "the parser currently guesses sh while its shell-known flag is false")

	input := dockerGateInputWithIDs(t, []string{content}, []string{"fixture"})
	projected, err := newDockerRuleInput(input)
	require.NoError(t, err)
	projectedInput, err := ast.ValueToInterface(projected.payload, nil)
	require.NoError(t, err)
	projectedDoc := projectedInput.(map[string]interface{})["document"].([]interface{})[0].(map[string]interface{})
	projectedFacts := projectedDoc["_dockerfile"].(map[string]interface{})
	_, projectedRun := dockerRunInstructionForTest(t, projectedFacts)
	require.Equal(t, projected.placeholder, projectedRun["execution"])
	require.Equal(t, "sudo true", projectedRun["syntax"].(map[string]interface{})["script"])
}

func TestDockerUnknownShellExecutionAbsenceIsGated(t *testing.T) {
	rule := withDockerContractVersion("1", `package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/1", "path":[]} if {
 run := input.document[0]._dockerfile.instructions[1]
 run.kind == "run"
 not run.execution.calls
}`)
	d, query, loader, results := dockerGateRun(t, []string{"FROM custom-image\nRUN echo runtime\n"}, []string{"fixture"}, dockerGateTestLibrary, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the opaque execution emits a pre-gate absence candidate")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Empty(t, items, "absence from an opaque execution cannot certify a finding")
}

func TestDockerInheritedExecutionKeepsExplicitShellAndExecFacts(t *testing.T) {
	for _, tc := range []struct {
		name, content, form string
	}{
		{
			name:    "explicit shell",
			content: "ARG BASE\nFROM alpine AS builder\nFROM $BASE AS final\nSHELL [\"sh\",\"-c\"]\nRUN sudo true\n",
			form:    "shell",
		},
		{
			name:    "exec form",
			content: "ARG BASE=builder\nFROM alpine AS builder\nSHELL [\"python\",\"-c\"]\nFROM $BASE AS final\nRUN [\"sudo\",\"true\"]\n",
			form:    "exec",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := dockerRootTestDocument(t, "fixture", tc.content)
			facts := cloneDockerInheritanceValue(document["_dockerfile"]).(map[string]interface{})
			taintUnknownDockerStageRelationships(facts, "unknown-stage")
			taintUnknownDockerInheritedExecution(facts, "unknown-stage")
			_, run := dockerRunInstructionForTest(t, facts)
			execution := run["execution"].(map[string]interface{})
			require.Equal(t, tc.form, execution["form"])
			require.True(t, dockerHasCallWrapper(execution["calls"], "sudo"))
			require.NotEqual(t, "unknown-stage", execution["shell_known"])
			require.NotContains(t, execution["calls"], "unknown-stage")
		})
	}
}

func TestDockerInheritedShellWrapperPolicy(t *testing.T) {
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":run._dd_meta.id, "path":[]} if {
	some doc in input.document
	some run in doc._dockerfile.instructions
	run.kind == "run"
	some call in run.execution.calls
	some wrapper in call.wrappers
	wrapper == "sudo"
}`
	for _, tc := range []struct {
		name, content string
		want          int
	}{
		{
			name:    "unknown inherited interpreter",
			content: "ARG BASE=builder\nFROM alpine AS builder\nSHELL [\"python\",\"-c\"]\nFROM $BASE AS final\nRUN sudo true\n",
			want:    0,
		},
		{
			name:    "unknown external shell",
			content: "FROM custom-image\nRUN sudo true\n",
			want:    0,
		},
		{
			name:    "explicit shell in uncertain stage",
			content: "ARG BASE\nFROM alpine AS builder\nFROM $BASE AS final\nSHELL [\"sh\",\"-c\"]\nRUN sudo true\n",
			want:    1,
		},
		{
			name:    "exec form independent of shell",
			content: "ARG BASE=builder\nFROM alpine AS builder\nSHELL [\"python\",\"-c\"]\nFROM $BASE AS final\nRUN [\"sudo\",\"true\"]\n",
			want:    1,
		},
		{
			name:    "explicit heredoc interpreter",
			content: "FROM custom-image\nRUN <<EOF bash\nsudo true\nEOF\n",
			want:    1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, query, loader, results := dockerGateRun(t, []string{tc.content}, []string{"fixture"}, dockerGateTestLibrary, rule)
			items, err := resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, tc.want, "shell-wrapper rules must see only facts supported by the selected interpreter")
			require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(context.Background(), dockerGateContext(query), d, d.payload, results))
			items, err = resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, tc.want, "known explicit-shell and exec-form results remain reportable")
		})
	}
}

func TestDockerUnknownExternalShellTaintsHealthcheckAndOnbuild(t *testing.T) {
	document := dockerRootTestDocument(t, "fixture", "FROM custom-image\nHEALTHCHECK CMD curl http://example.invalid\nONBUILD RUN sudo true\n")
	facts := cloneDockerInheritanceValue(document["_dockerfile"]).(map[string]interface{})
	instructions := facts["instructions"].([]interface{})
	healthcheck := instructions[1].(map[string]interface{})
	healthcheckFacts := healthcheck["healthcheck"].(map[string]interface{})
	healthcheckExecution := healthcheckFacts["execution"]
	require.Equal(t, false, healthcheckExecution.(map[string]interface{})["shell_known"])
	require.Equal(t, "shell", healthcheckFacts["syntax"].(map[string]interface{})["form"])
	contextIndex, ok := dockerFactIndex(healthcheck["context"])
	require.True(t, ok)
	contexts := facts["contexts"].([]interface{})
	contextHealthcheck := contexts[contextIndex].(map[string]interface{})["healthcheck"].(map[string]interface{})
	contextExecution := contextHealthcheck["execution"]
	require.Equal(t, false, contextExecution.(map[string]interface{})["shell_known"])
	onbuild := instructions[2].(map[string]interface{})
	trigger := onbuild["trigger"].(map[string]interface{})
	triggerExecution := trigger["execution"]
	require.Equal(t, false, triggerExecution.(map[string]interface{})["shell_known"])

	taintUnknownDockerInheritedExecution(facts, "unknown-shell")
	require.Equal(t, "unknown-shell", healthcheckFacts["execution"])
	require.Equal(t, "shell", healthcheckFacts["syntax"].(map[string]interface{})["form"])
	require.Equal(t, "curl http://example.invalid", healthcheckFacts["syntax"].(map[string]interface{})["script"])
	require.Equal(t, "unknown-shell", contextHealthcheck["execution"])
	require.Equal(t, "unknown-shell", trigger["execution"])
	require.Equal(t, "shell", trigger["syntax"].(map[string]interface{})["form"], "Dockerfile command syntax remains known")

	knownExecDoc := dockerRootTestDocument(t, "fixture", "FROM custom-image\nHEALTHCHECK CMD curl http://example.invalid\nRUN [\"wget\",\"https://example.invalid/file\"]\n")
	knownExecFacts := cloneDockerInheritanceValue(knownExecDoc["_dockerfile"]).(map[string]interface{})
	taintUnknownDockerInheritedExecution(knownExecFacts, "unknown-shell")
	_, execRun := dockerRunInstructionForTest(t, knownExecFacts)
	exec := execRun["execution"].(map[string]interface{})
	require.Equal(t, "exec", exec["form"])
	require.NotContains(t, exec["calls"], "unknown-shell", "unknown healthcheck shell facts must not taint independent exec-form RUN facts")
	require.Contains(t, dockerRunCommandNames(knownExecFacts["stages"].([]interface{})[0]), "wget")
	require.NotContains(t, dockerRunCommandValues(knownExecFacts["stages"].([]interface{})[0]), "unknown-shell")
}

func TestDockerUnknownShellRunPreservesKnownStageInventory(t *testing.T) {
	content := "ARG BASE=builder\nFROM alpine AS builder\nSHELL [\"python\",\"-c\"]\nFROM $BASE AS final\nRUN [\"wget\",\"https://example.invalid/file\"]\nRUN sudo true\n"
	document := dockerRootTestDocument(t, "fixture", content)
	facts := cloneDockerInheritanceValue(document["_dockerfile"]).(map[string]interface{})
	uncertain := taintUnknownDockerStageRelationships(facts, "unknown-stage")
	taintUnknownDockerInheritance(facts, "unknown-stage", uncertain)
	taintUnknownDockerInheritedExecution(facts, "unknown-stage")
	commands := dockerRunCommandValues(facts["stages"].([]interface{})[1])
	require.Contains(t, dockerRunCommandNames(facts["stages"].([]interface{})[1]), "wget")
	require.NotContains(t, dockerRunCommandNames(facts["stages"].([]interface{})[1]), "true", "the guessed-shell call must be removed from the known inventory")
	require.Contains(t, commands, "unknown-stage", "the unresolved RUN keeps the aggregate inventory incomplete")
}

func TestNewDockerRuleInputDoesNotMutateUnknownInheritedExecutionSource(t *testing.T) {
	const content = "ARG BASE=builder\nFROM alpine AS builder\nSHELL [\"python\",\"-c\"]\nFROM $BASE AS final\nRUN sudo true\n"
	document := dockerRootTestDocument(t, "fixture", content)
	input, err := ast.InterfaceToValue(map[string]interface{}{"document": []interface{}{document}})
	require.NoError(t, err)
	before, err := ast.ValueToInterface(input, nil)
	require.NoError(t, err)
	projected, err := newDockerRuleInput(input)
	require.NoError(t, err)
	after, err := ast.ValueToInterface(input, nil)
	require.NoError(t, err)
	require.Equal(t, before, after, "the scanner certainty projection operates on its private input copy")

	projectedInput, err := ast.ValueToInterface(projected.payload, nil)
	require.NoError(t, err)
	projectedDocument := projectedInput.(map[string]interface{})["document"].([]interface{})[0].(map[string]interface{})
	facts := projectedDocument["_dockerfile"].(map[string]interface{})
	_, run := dockerRunInstructionForTest(t, facts)
	require.Equal(t, projected.placeholder, run["execution"])
	require.Equal(t, "sudo true", run["syntax"].(map[string]interface{})["script"])
}

func dockerRunInstructionForTest(t *testing.T, facts map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()
	instructions := facts["instructions"].([]interface{})
	for index, raw := range instructions {
		instruction, ok := raw.(map[string]interface{})
		if ok && instruction["kind"] == "run" {
			return index, instruction
		}
	}
	require.FailNow(t, "Dockerfile has no RUN instruction")
	return 0, nil
}

func dockerHasCallWrapper(value interface{}, wrapper string) bool {
	calls, _ := value.([]interface{})
	for _, raw := range calls {
		call, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		wrappers, _ := call["wrappers"].([]interface{})
		for _, rawWrapper := range wrappers {
			if rawWrapper == wrapper {
				return true
			}
		}
	}
	return false
}

func dockerRunCommandNames(value interface{}) []string {
	values := dockerRunCommandValues(value)
	names := make([]string, 0, len(values))
	for _, raw := range values {
		if item, ok := raw.(map[string]interface{}); ok {
			if name, ok := item["value"].(string); ok {
				names = append(names, name)
			}
		}
	}
	return names
}

func dockerRunCommandValues(value interface{}) []interface{} {
	stage, _ := value.(map[string]interface{})
	commands, _ := stage["run_commands"].([]interface{})
	return commands
}
