package engine

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestDockerInstructionRootsWithoutAnnotationKeepWholeRoots(t *testing.T) {
	roots, _ := dockerUnitTestRoots(t, "FROM alpine\nRUN echo ok\nENV A=b\n")
	got, err := dockerUnitRoots(&model.QueryMetadata{Query: "unannotated", Content: "package datadog"}, roots)
	require.NoError(t, err)
	require.Len(t, got, len(roots))
	for i := range roots {
		require.Same(t, roots[i].doc, got[i].doc)
		require.Same(t, roots[i].term, got[i].term)
	}
}

func TestDockerInstructionRootsProjectOnlyMatchingInstructions(t *testing.T) {
	roots, input := dockerUnitTestRoots(t, "FROM alpine\nRUN echo ok\nADD source /target\nENV A=b\nUSER app\n")
	originalDoc := roots[0].doc
	query := dockerUnitTestQuery(`
# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
#       kinds:
#         - run
#         - env
package datadog
`)
	got, err := dockerUnitRoots(&query, roots)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for i, wantKind := range []string{"run", "env"} {
		unitModel := got[i].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
		instructions := unitModel.Get(ast.StringTerm("instructions")).Value.(*ast.Array)
		require.Equal(t, 1, instructions.Len())
		instruction := instructions.Elem(0).Value.(ast.Object)
		require.Equal(t, wantKind, string(instruction.Get(ast.StringTerm("kind")).Value.(ast.String)))
		metadata := instruction.Get(ast.StringTerm("_dd_meta")).Value.(ast.Object)
		id := metadata.Get(ast.StringTerm("id")).Value.(ast.String)
		if wantKind == "run" {
			require.Equal(t, "fixture#/_dockerfile/instructions/1", string(id))
		} else {
			require.Equal(t, "fixture#/_dockerfile/instructions/3", string(id))
		}
		for _, excluded := range []string{"stages", "contexts", "bindings", "global_arguments"} {
			require.Nil(t, unitModel.Get(ast.StringTerm(excluded)))
		}
		require.Equal(t, got[0].id, got[i].id)
	}
	for _, field := range []string{"resource_type", "resource_name"} {
		require.Equal(t,
			originalDoc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object).Get(ast.StringTerm(field)),
			got[0].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object).Get(ast.StringTerm(field)),
		)
	}
	require.NotNil(t, input)
}

func TestDockerInstructionRootsWithoutKindsSelectUnknownInstruction(t *testing.T) {
	roots, _ := dockerUnitTestRoots(t, "RUN echo ok\n")
	model := roots[0].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	stages := model.Get(ast.StringTerm("stages")).Value.(*ast.Array)
	stageNames := model.Get(ast.StringTerm("stage_names")).Value.(*ast.Array)
	require.Zero(t, stages.Len(), "fixture has no FROM stage")
	require.Zero(t, stageNames.Len(), "stage_names is aligned with stages, including unnamed stages")

	metadata := ast.NewObject()
	metadata.Insert(ast.StringTerm("id"), ast.StringTerm("fixture#/_dockerfile/instructions/0"))
	instruction := ast.NewObject()
	instruction.Insert(ast.StringTerm("kind"), ast.StringTerm("future_keyword"))
	instruction.Insert(ast.StringTerm("index"), ast.NewTerm(ast.Number("0")))
	instruction.Insert(ast.StringTerm("_dd_meta"), ast.NewTerm(metadata))
	model.Insert(ast.StringTerm("instructions"), ast.NewTerm(ast.NewArray(ast.NewTerm(instruction))))

	query := dockerUnitTestQuery(`# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
package datadog
`)
	units, err := dockerUnitRoots(&query, roots)
	require.NoError(t, err)
	require.Len(t, units, 1, "omitting kinds selects every instruction kind, including future ones")
	unitModel := units[0].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	selected := unitModel.Get(ast.StringTerm("instructions")).Value.(*ast.Array)
	require.Equal(t, 1, selected.Len())
	require.Equal(t, "future_keyword", string(selected.Elem(0).Value.(ast.Object).Get(ast.StringTerm("kind")).Value.(ast.String)))
	require.Equal(t, 0, unitModel.Get(ast.StringTerm("stage_names")).Value.(*ast.Array).Len())
	for _, field := range []string{"stages", "contexts", "bindings", "global_arguments"} {
		require.Nil(t, unitModel.Get(ast.StringTerm(field)), "instruction units remain complete and fixed: %s", field)
	}

	query.Content = strings.Replace(query.Content, "scope: instruction", "scope: instruction\n#       kinds: [run]", 1)
	filtered, err := dockerUnitRoots(&query, roots)
	require.NoError(t, err)
	require.Empty(t, filtered, "explicit kind lists continue to filter instructions")
}

func TestDockerInstructionScopeWithoutKindsStillRequiresContractVersion(t *testing.T) {
	query := dockerUnitTestQuery(`# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
package datadog

DatadogPolicy contains result if { true }
`)
	err := parseDockerContractVersion(&query)
	require.ErrorContains(t, err, "missing custom.datadog.dockerfile.version")
}

func TestDockerInstructionRootsRejectMalformedMetadata(t *testing.T) {
	roots, _ := dockerUnitTestRoots(t, "FROM alpine\nRUN echo ok\n")
	for _, test := range []struct {
		name string
		meta string
	}{
		{
			name: "unsupported scope",
			meta: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: file
#       kinds: [run]
package datadog`,
		},
		{
			name: "empty kinds",
			meta: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
#       kinds: []
package datadog`,
		},
		{
			name: "null kinds",
			meta: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
#       kinds: null
package datadog`,
		},
		{
			name: "kinds is not a list",
			meta: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
#       kinds: run
package datadog`,
		},
		{
			name: "unknown kind",
			meta: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
#       kinds: [runn]
package datadog`,
		},
		{
			name: "wrong annotation scope",
			meta: `# METADATA
# scope: rule
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
#       kinds: [run]
package datadog
allow if { true }`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := dockerUnitRoots(&model.QueryMetadata{Query: "bad-unit", Content: test.meta}, roots)
			require.Error(t, err)
		})
	}
}

func TestDockerInstructionRootsKeepUnknownOnOriginalNode(t *testing.T) {
	input := dockerGateTestInput(t, "FROM alpine\nARG U\nUSER $U\n")
	dockerInput, err := newDockerRuleInput(input)
	require.NoError(t, err)
	roots, err := dockerRoots(dockerInput)
	require.NoError(t, err)
	query := dockerUnitTestQuery(`
# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       scope: instruction
#       kinds: [user]
package datadog
`)
	units, err := dockerUnitRoots(&query, roots)
	require.NoError(t, err)
	require.Len(t, units, 1)
	require.True(t, dockerInput.hasUnknown(units[0].doc))
	unitModel := units[0].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	instruction := unitModel.Get(ast.StringTerm("instructions")).Value.(*ast.Array).Elem(0).Value.(ast.Object)
	require.Equal(t, "fixture#/_dockerfile/instructions/2", string(instruction.Get(ast.StringTerm("_dd_meta")).Value.(ast.Object).Get(ast.StringTerm("id")).Value.(ast.String)))
}

func dockerUnitTestRoots(t *testing.T, content string) ([]dockerBuildRoot, *dockerRuleInput) {
	t.Helper()
	dockerInput, err := newDockerRuleInput(dockerGateTestInput(t, content))
	require.NoError(t, err)
	roots, err := dockerRoots(dockerInput)
	require.NoError(t, err)
	return roots, dockerInput
}

func dockerUnitTestQuery(content string) model.QueryMetadata {
	return model.QueryMetadata{Query: "docker-unit-test", Platform: "Dockerfile", Content: content}
}

func TestDockerRunUnitsShareStageInventory(t *testing.T) {
	roots, _ := dockerUnitTestRoots(t, "FROM alpine AS build\nSHELL [\"/bin/sh\",\"-c\"]\nRUN alpha\nRUN beta\nFROM alpine\nSHELL [\"/bin/sh\",\"-c\"]\nRUN gamma\n")
	query := dockerUnitTestQuery("package datadog")
	query.Content = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: instruction
#       kinds: [run]
package datadog
`
	units, err := dockerUnitRoots(&query, roots)
	require.NoError(t, err)
	require.Len(t, units, 3)
	inventories := make([]*ast.Term, len(units))
	for i, unit := range units {
		model := unit.doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
		inventories[i] = model.Get(ast.StringTerm("stage_run_commands"))
		require.NotNil(t, inventories[i])
		instruction := model.Get(ast.StringTerm("instructions")).Value.(*ast.Array).Elem(0).Value.(ast.Object)
		require.Nil(t, instruction.Get(ast.StringTerm("stage_run_commands")), "the parser serializes each inventory once per stage")
	}
	require.Same(t, inventories[0], inventories[1], "units share the immutable stage AST term")
	require.NotSame(t, inventories[0], inventories[2], "separate stages keep separate inventories")
	first := inventories[0].Value.(*ast.Array)
	require.Equal(t, 2, first.Len())
	require.Equal(t, ast.String("alpha"), first.Elem(0).Value.(ast.Object).Get(ast.StringTerm("value")).Value)
	require.Equal(t, ast.String("beta"), first.Elem(1).Value.(ast.Object).Get(ast.StringTerm("value")).Value)
}
