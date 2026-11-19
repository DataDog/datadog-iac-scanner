package engine

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestDockerProjectionPreservesDerivedUncertainty(t *testing.T) {
	input, err := ast.InterfaceToValue(map[string]interface{}{"document": []interface{}{map[string]interface{}{
		"id": "fixture",
		"_dockerfile": map[string]interface{}{"instructions": []interface{}{map[string]interface{}{
			"kind": "copy", "copy": map[string]interface{}{
				"from":         map[string]interface{}{"known": false, "value": ""},
				"source_stage": -1,
				"from_kind":    map[string]interface{}{"known": false, "value": ""},
				"sources":      []interface{}{map[string]interface{}{"kind": "unknown", "name": "$FILE", "scheme": "", "value": map[string]interface{}{"known": false, "value": ""}}},
			},
			"image": map[string]interface{}{"kind": "unknown", "namespace": ""},
			"ports": []interface{}{map[string]interface{}{"start": map[string]interface{}{"known": false, "value": 0}, "end": map[string]interface{}{"known": false, "value": 0}}},
			"execution": map[string]interface{}{
				"calls":                []interface{}{map[string]interface{}{"name": "", "executable": map[string]interface{}{"known": false, "value": ""}, "cd_path": map[string]interface{}{"known": false, "value": ""}}},
				"package_cache_mounts": []interface{}{map[string]interface{}{"known": false, "value": false}},
				"package_commands": []interface{}{map[string]interface{}{
					"manager": "pip", "known": false,
					"options":  []interface{}{map[string]interface{}{"name": "--cache-dir", "value": ""}},
					"packages": []interface{}{map[string]interface{}{"name": "example", "pinned": false}},
				}},
			},
		}}},
	}}})
	require.NoError(t, err)
	projected, err := newDockerRuleInput(input)
	require.NoError(t, err)
	raw, err := ast.ValueToInterface(projected.payload, nil)
	require.NoError(t, err)
	root := raw.(map[string]interface{})
	doc := root["document"].([]interface{})[0].(map[string]interface{})
	instruction := doc["_dockerfile"].(map[string]interface{})["instructions"].([]interface{})[0].(map[string]interface{})
	copyFact := instruction["copy"].(map[string]interface{})
	require.Equal(t, projected.placeholder, copyFact["source_stage"])
	require.Equal(t, projected.placeholder, copyFact["from_kind"].(map[string]interface{})["value"])
	require.Equal(t, projected.placeholder, instruction["image"].(map[string]interface{})["namespace"])
	port := instruction["ports"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, projected.placeholder, port["start"].(map[string]interface{})["value"])
	require.Equal(t, projected.placeholder, port["end"].(map[string]interface{})["value"])
	call := instruction["execution"].(map[string]interface{})["calls"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, projected.placeholder, call["name"])
	require.Equal(t, projected.placeholder, call["cd_path"].(map[string]interface{})["value"])
	source := copyFact["sources"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, projected.placeholder, source["name"])
	require.Equal(t, projected.placeholder, source["scheme"])
	coverage := instruction["execution"].(map[string]interface{})["package_cache_mounts"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, projected.placeholder, coverage["value"])
	command := instruction["execution"].(map[string]interface{})["package_commands"].([]interface{})[0].(map[string]interface{})
	option := command["options"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, projected.placeholder, option["name"])
	require.Equal(t, projected.placeholder, option["value"])
	pkg := command["packages"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, projected.placeholder, pkg["name"])
}

func TestDockerPolicyInputDoesNotExposeParserKnownness(t *testing.T) {
	d, err := newDockerRuleInput(dockerGateTestInput(t, "FROM alpine\nENV known=retained complete=also-retained\nARG COMMAND\nSHELL [\"/bin/sh\",\"-c\"]\nRUN $COMMAND\n"))
	require.NoError(t, err)
	raw, err := ast.ValueToInterface(d.payload, nil)
	require.NoError(t, err)
	doc := raw.(map[string]interface{})["document"].([]interface{})[0].(map[string]interface{})
	facts := doc["_dockerfile"].(map[string]interface{})
	instructions := facts["instructions"].([]interface{})
	env := instructions[1].(map[string]interface{})
	for _, binding := range env["bindings"].([]interface{}) {
		value := binding.(map[string]interface{})["value"].(map[string]interface{})
		require.NotContains(t, value, "known")
	}
	run := instructions[4].(map[string]interface{})
	execution := run["execution"].(map[string]interface{})
	require.NotContains(t, execution, "complete")
	require.NotContains(t, execution, "shell_known")
	require.Contains(t, execution["calls"], d.placeholder, "unknown inventories remain opaque and open")
	contexts := facts["contexts"].([]interface{})
	context := contexts[len(contexts)-1].(map[string]interface{})
	require.Equal(t, d.placeholder, context["environment_values"], "unfetched external ENV keys remain unknown")
}

func TestDockerMetadataRemovalPreservesEnvironmentKeyNames(t *testing.T) {
	values := map[string]interface{}{
		"known":    map[string]interface{}{"value": "retained", "known": true},
		"complete": map[string]interface{}{"value": "also-retained", "known": true},
	}
	removeDockerParserMetadata(values, "unknown")
	require.Equal(t, "retained", values["known"].(map[string]interface{})["value"], "user-named ENV keys are not parser metadata")
	require.Equal(t, "also-retained", values["complete"].(map[string]interface{})["value"])
	require.NotContains(t, values["known"], "known")
}

func TestDockerPolicyInputKeepsInstructionParseDiagnosticsPrivate(t *testing.T) {
	input := dockerGateTestInput(t, "FROM alpine\nSHELL /bin/sh -c\n")
	rawDocument := input.(ast.Object).Get(ast.StringTerm("document")).Value.(*ast.Array).Elem(0).Value.(ast.Object)
	rawModel := rawDocument.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	invalid := rawModel.Get(ast.StringTerm("instructions")).Value.(*ast.Array).Elem(1).Value.(ast.Object)
	require.Equal(t, ast.Boolean(false), invalid.Get(ast.StringTerm("parse_ok")).Value)
	require.NotNil(t, invalid.Get(ast.StringTerm("error")), "the parser retains its diagnostics")
	projected, err := newDockerRuleInput(input)
	require.NoError(t, err)
	model := projected.documents["fixture"].(ast.Object).Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	instructions := model.Get(ast.StringTerm("instructions")).Value.(*ast.Array)
	for i := 0; i < instructions.Len(); i++ {
		instruction := instructions.Elem(i).Value.(ast.Object)
		require.Nil(t, instruction.Get(ast.StringTerm("parse_ok")))
		require.Nil(t, instruction.Get(ast.StringTerm("error")))
	}
}
