package docker

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
	"github.com/stretchr/testify/require"
)

func TestStageRunCommandsAreStageLocalAndSetLike(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine AS base
RUN /usr/bin/wget https://example.test/one
RUN curl https://example.test/two
RUN /usr/bin/wget https://example.test/three
FROM base AS child
RUN curl https://example.test/child
FROM scratch
RUN make all
`)
	require.Len(t, result.Stages, 3)
	require.Equal(t, []string{"base", "child", ""}, result.StageNames)

	runInstructions := make([]Instruction, 0)
	for _, instruction := range result.Instructions {
		if instruction.Kind == "run" {
			runInstructions = append(runInstructions, instruction)
		}
	}
	require.Len(t, runInstructions, 5)
	for _, instruction := range runInstructions[:3] {
		require.Equal(t, []string{"wget", "curl"}, knownStageCommands(result.Stages[instruction.Stage].RunCommands))
	}
	require.Equal(t, []string{"curl"}, knownStageCommands(result.Stages[runInstructions[3].Stage].RunCommands),
		"a child stage does not inherit its base stage's command inventory")
	require.Equal(t, []string{"make"}, knownStageCommands(result.Stages[runInstructions[4].Stage].RunCommands))
}

func TestStageRunCommandsIncludeExecAndShellCalls(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
RUN ["/usr/bin/wget", "https://example.test/exec"]
RUN curl https://example.test/shell
`)
	require.Len(t, result.Instructions, 3)
	jsonRun, shellRun := result.Instructions[1], result.Instructions[2]
	require.NotNil(t, jsonRun.Execution)
	require.NotNil(t, shellRun.Execution)
	require.Equal(t, "exec", jsonRun.Execution.Form)
	require.Equal(t, "shell", shellRun.Execution.Form)
	require.Equal(t, []string{"wget", "curl"}, knownStageCommands(result.Stages[jsonRun.Stage].RunCommands))
	require.Equal(t, []string{"wget", "curl"}, knownStageCommands(result.Stages[shellRun.Stage].RunCommands))
}

func TestStageRunCommandsExcludeFunctionsAndDeferredCalls(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
RUN helper() { curl https://example.test/deferred; }; helper
RUN wget https://example.test/active
`)
	require.Len(t, result.Instructions, 3)
	commands := result.Stages[result.Instructions[1].Stage].RunCommands
	require.NotContains(t, knownStageCommands(commands), "curl")
	require.NotContains(t, knownStageCommands(commands), "helper")
	require.Contains(t, knownStageCommands(commands), "wget")
}

func TestStageRunCommandsPreserveUnknownExecutableAndIncompleteInventory(t *testing.T) {
	result := parseAnalysis(t, `FROM alpine
RUN echo known
RUN $TOOL
`)
	require.Len(t, result.Instructions, 3)
	commands := result.Stages[result.Instructions[1].Stage].RunCommands
	require.Contains(t, knownStageCommands(commands), "echo")
	require.Len(t, unknownStageCommands(commands), 1)
	require.False(t, unknownStageCommands(commands)[0].Known)

	analysis := &Analysis{Stages: []Stage{{Index: 0}}, Instructions: []Instruction{
		{Kind: "run", Stage: 0, Execution: &Execution{Facts: &shell.Facts{
			Calls:    []shell.Invocation{{Name: "printf", Executable: shell.Value{Text: "printf", Known: true}}},
			Complete: false,
		}}},
		{Kind: "run", Stage: 0, Execution: &Execution{Facts: &shell.Facts{
			Calls:    []shell.Invocation{{Name: "echo", Executable: shell.Value{Text: "echo", Known: true}}},
			Complete: true,
		}}},
	}}
	assignStageRunCommands(analysis)
	require.Equal(t, []string{"printf", "echo"}, knownStageCommands(analysis.Stages[0].RunCommands))
	require.Len(t, unknownStageCommands(analysis.Stages[0].RunCommands), 1)
}

func TestStageRunCommandsSerializeOncePerStageWithLinearGrowth(t *testing.T) {
	modelJSON := func(count int) ([]byte, *Analysis) {
		var content strings.Builder
		content.WriteString("FROM alpine\n")
		for i := 0; i < count; i++ {
			fmt.Fprintf(&content, "RUN command-%03d\n", i)
		}
		analysis := parseAnalysis(t, content.String())
		serialized, err := json.Marshal(analysis)
		require.NoError(t, err)
		return serialized, analysis
	}

	size100, model100 := modelJSON(100)
	size200, model200 := modelJSON(200)
	require.Len(t, model100.Stages[0].RunCommands, 100)
	require.Len(t, model200.Stages[0].RunCommands, 200)
	require.Greater(t, len(size200), len(size100))
	require.Less(t, float64(len(size200))/float64(len(size100)), 2.5,
		"doubling RUN instructions should not square the serialized inventory size")

	instructionJSON, err := json.Marshal(model200.Instructions[1])
	require.NoError(t, err)
	var instruction map[string]interface{}
	require.NoError(t, json.Unmarshal(instructionJSON, &instruction))
	_, exists := instruction["stage_run_commands"]
	require.False(t, exists, "the stage-level inventory must not be repeated on each instruction")
}

func TestStageWithoutRunsSerializesAnEmptyInventory(t *testing.T) {
	analysis := parseAnalysis(t, "FROM alpine\n")
	require.Len(t, analysis.Stages, 1)
	require.NotNil(t, analysis.Stages[0].RunCommands)
	require.Empty(t, analysis.Stages[0].RunCommands)

	serialized, err := json.Marshal(analysis)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(serialized, &decoded))
	stages := decoded["stages"].([]interface{})
	stage := stages[0].(map[string]interface{})
	require.Equal(t, []interface{}{}, stage["run_commands"])
}

func knownStageCommands(values []shell.Value) []string {
	var names []string
	for _, value := range values {
		if value.Known {
			names = append(names, value.Text)
		}
	}
	return names
}

func unknownStageCommands(values []shell.Value) []shell.Value {
	var unknown []shell.Value
	for _, value := range values {
		if !value.Known {
			unknown = append(unknown, value)
		}
	}
	return unknown
}

func TestStageNamesAlignWithParsedStages(t *testing.T) {
	result := parseAnalysis(t, `ARG BASE=alpine
FROM ${BASE} AS Builder
RUN echo build
FROM Builder
RUN echo unnamed
FROM scratch AS Final
RUN echo final
`)
	require.Len(t, result.Stages, 3)
	require.Equal(t, []string{"builder", "", "final"}, result.StageNames)
	for index, stage := range result.Stages {
		require.Equal(t, stage.Name, result.StageNames[index])
	}
}
