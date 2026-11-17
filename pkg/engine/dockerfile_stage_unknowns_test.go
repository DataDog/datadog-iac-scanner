package engine

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

const dockerStageRelationshipRule = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog

DatadogPolicy contains data.generic.common.finding(stage, [], {}) if {
	some document in input.document
	some stage in document._dockerfile.stages
	stage.index == 1
	stage.base_stage != 0
}`

func TestDockerUnknownFromCannotCertifyNoLocalBaseStage(t *testing.T) {
	const content = "ARG BASE=builder\nFROM alpine AS builder\nUSER app\nFROM $BASE AS final\n"
	document := dockerRootTestDocument(t, "fixture", content)
	analysis := document["_dockerfile"].(map[string]interface{})
	stages := analysis["stages"].([]interface{})
	second := stages[1].(map[string]interface{})
	require.Equal(t, float64(-1), second["base_stage"])
	require.Equal(t, float64(1), second["origin_stage"])

	input := dockerGateInputWithIDs(t, []string{content}, []string{"fixture"})
	dockerInput, err := newDockerRuleInput(input)
	require.NoError(t, err)
	common := `package generic.common
import rego.v1
finding(subject, path, details) := {"_dd_id": subject._dd_meta.id, "path": path}
`
	prepared, err := rego.New(
		rego.Query("result = data.datadog.DatadogPolicy"),
		rego.Module("Rule", dockerStageRelationshipRule),
		rego.Module("Common", common),
		rego.Module("Generic", dockerGateTestLibrary),
		rego.Module(dockerContractModuleName, dockerContractModule),
	).PrepareForEval(context.Background())
	require.NoError(t, err)
	results, err := prepared.Eval(context.Background(), rego.EvalParsedInput(dockerInput.payload))
	require.NoError(t, err)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the synthetic policy sees the unresolved base as an external-stage fact")

	loader := &QueryLoader{
		commonLibrary:     source.RegoLibraries{LibraryCode: common},
		platformLibraries: map[string]source.RegoLibraries{"Dockerfile": {LibraryCode: dockerGateTestLibrary}},
	}
	query := model.QueryMetadata{Query: "unknown-from-stage-relation", Platform: "Dockerfile", Content: dockerStageRelationshipRule}
	qCtx := dockerGateContext(query)
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), qCtx, dockerInput, dockerInput.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Empty(t, items, "a finding that depends on unresolved FROM-to-stage identity must be suppressed")
}

func TestTaintUnknownDockerStageRelationships(t *testing.T) {
	const placeholder = "unknown-stage-relation"
	facts := map[string]interface{}{
		"instructions": []interface{}{
			map[string]interface{}{"image": map[string]interface{}{"kind": "image", "reference": map[string]interface{}{"known": true}}},
			map[string]interface{}{"image": map[string]interface{}{"kind": "unknown", "reference": map[string]interface{}{"known": false, "default": "builder"}}},
			map[string]interface{}{"image": map[string]interface{}{"kind": "stage", "reference": map[string]interface{}{"known": true}, "stage": 1}},
			map[string]interface{}{"image": map[string]interface{}{"kind": "unknown", "reference": map[string]interface{}{"known": true}}},
		},
		"stages": []interface{}{
			map[string]interface{}{"from": float64(0), "base_stage": float64(-1), "origin_stage": float64(0)},
			map[string]interface{}{"from": float64(1), "base_stage": float64(-1), "origin_stage": float64(1)},
			map[string]interface{}{"from": float64(2), "base_stage": float64(1), "origin_stage": float64(1)},
			map[string]interface{}{"from": float64(3), "base_stage": float64(-1), "origin_stage": float64(3)},
		},
	}

	uncertain := taintUnknownDockerStageRelationships(facts, placeholder)
	stages := facts["stages"].([]interface{})
	first := stages[0].(map[string]interface{})
	second := stages[1].(map[string]interface{})
	third := stages[2].(map[string]interface{})
	fourth := stages[3].(map[string]interface{})
	require.Equal(t, float64(-1), first["base_stage"], "a known external image remains a known non-local base")
	require.Equal(t, float64(0), first["origin_stage"])
	require.Equal(t, placeholder, second["base_stage"], "the unknown reference must not claim no local base")
	require.Equal(t, placeholder, second["origin_stage"])
	require.Equal(t, float64(1), third["base_stage"], "a literal local stage alias has a known immediate base")
	require.Equal(t, placeholder, third["origin_stage"], "the aliased stage's original base is still unresolved")
	require.Equal(t, float64(-1), fourth["base_stage"], "a known, invalid literal does not create a dynamic stage relationship")
	require.Equal(t, float64(3), fourth["origin_stage"])
	require.Equal(t, map[int]bool{1: true, 2: true}, uncertain)
}
