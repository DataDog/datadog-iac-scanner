package engine

import (
	"context"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestDockerStageUnitsKeepLinkedSourceFactsAndStageIsolation(t *testing.T) {
	roots, input := dockerUnitTestRoots(t, "FROM alpine AS base\nUSER app\nFROM base AS inherited\nFROM alpine AS independent\nUSER root\n")
	originalModel := roots[0].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	query := dockerStageUnitQuery("docker-stage-source-relations")
	units, err := dockerUnitRoots(&query, roots)
	require.NoError(t, err)
	require.Len(t, units, 3)

	originalStages := originalModel.Get(ast.StringTerm("stages")).Value.(*ast.Array)
	originalInstructions := originalModel.Get(ast.StringTerm("instructions")).Value.(*ast.Array)
	originalContexts := originalModel.Get(ast.StringTerm("contexts")).Value.(*ast.Array)
	for i, unit := range units {
		require.True(t, unit.stageUnit)
		require.False(t, unit.instructionUnit)
		require.Equal(t, "fixture", unit.id)
		require.Equal(t, "fixture", string(unit.doc.Get(ast.StringTerm("id")).Value.(ast.String)))
		facts := unit.doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
		for _, field := range []string{"contract_version", "resource_type", "resource_name", "stage", "context", "from", "origin_from", "user_instruction"} {
			require.NotNil(t, facts.Get(ast.StringTerm(field)), field)
		}
		for _, field := range []string{"instructions", "stages", "stage_names", "contexts", "bindings", "global_arguments"} {
			require.Nil(t, facts.Get(ast.StringTerm(field)), field)
		}
		require.Same(t, originalStages.Elem(i), facts.Get(ast.StringTerm("stage")))
		contextIndex, ok := facts.Get(ast.StringTerm("stage")).Value.(ast.Object).Get(ast.StringTerm("context")).Value.(ast.Number).Int()
		require.True(t, ok)
		require.Same(t, originalContexts.Elem(contextIndex), facts.Get(ast.StringTerm("context")))
	}

	first := units[0].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	inherited := units[1].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	independent := units[2].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	require.Same(t, originalInstructions.Elem(0), first.Get(ast.StringTerm("from")))
	require.Same(t, originalInstructions.Elem(0), first.Get(ast.StringTerm("origin_from")))
	require.Same(t, originalInstructions.Elem(2), inherited.Get(ast.StringTerm("from")))
	require.Same(t, originalInstructions.Elem(0), inherited.Get(ast.StringTerm("origin_from")))
	require.Same(t, originalInstructions.Elem(3), independent.Get(ast.StringTerm("from")))
	require.Same(t, originalInstructions.Elem(3), independent.Get(ast.StringTerm("origin_from")))
	require.Same(t, originalInstructions.Elem(1), inherited.Get(ast.StringTerm("user_instruction")), "inherited USER points to its original source instruction")
	require.Same(t, originalInstructions.Elem(4), independent.Get(ast.StringTerm("user_instruction")), "local USER retains its source instruction")
	require.True(t, bool(independent.Get(ast.StringTerm("from")).Value.(ast.Object).Get(ast.StringTerm("final_stage")).Value.(ast.Boolean)))
	require.NotNil(t, input)
}

func TestDockerStageUnitPreservesUnknownOriginAndUserRelations(t *testing.T) {
	content := "ARG BASE=builder\nFROM alpine AS builder\nUSER app\nFROM $BASE AS uncertain\n"
	roots, input := dockerUnitTestRoots(t, content)
	query := dockerStageUnitQuery("docker-stage-unknown-relations")
	units, err := dockerUnitRoots(&query, roots)
	require.NoError(t, err)
	require.Len(t, units, 2)
	require.NotEmpty(t, input.placeholder)

	facts := units[1].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	stage := facts.Get(ast.StringTerm("stage")).Value.(ast.Object)
	require.Equal(t, ast.String(input.placeholder), stage.Get(ast.StringTerm("origin_stage")).Value)
	require.Equal(t, ast.String(input.placeholder), facts.Get(ast.StringTerm("origin_from")).Value)
	require.Equal(t, ast.String(input.placeholder), facts.Get(ast.StringTerm("user_instruction")).Value)
	context := facts.Get(ast.StringTerm("context")).Value.(ast.Object)
	require.Equal(t, ast.String(input.placeholder), context.Get(ast.StringTerm("user_instruction")).Value)
}

func TestEvalQueryDockerStageUnitsGateUnknownRelationsAndPreserveSource(t *testing.T) {
	query := dockerStageIntegrationQuery()
	var ids []string
	builder := func(ctx context.Context, qCtx *QueryContext, tracker Tracker, result interface{}, lineDetector *detector.DetectLine, oldSeverities bool, duration time.Duration) (*model.Vulnerability, error) {
		ids = append(ids, result.(map[string]interface{})["_dd_id"].(string))
		return DefaultVulnerabilityBuilder(ctx, qCtx, tracker, result, lineDetector, oldSeverities, duration)
	}
	ins := newDockerInstructionUnitInspector(t, query, builder)
	content := "ARG BASE=builder\nFROM alpine AS builder\nUSER app\nFROM $BASE AS uncertain\nFROM scratch AS clean\n"
	dockerInput, rawInput, file := dockerInstructionUnitInput(t, content)
	results := ins.evalQuery(context.Background(), "scan", map[string]*model.FileMetadata{file.ID: file}, platformPayloads{
		dockerInput: dockerInput,
		byPlatform:  map[string]ast.Value{"dockerfile": rawInput},
		full:        rawInput,
	}, []model.QueryMetadata{query}, 0, nil, nil, nil, nil, nil)
	require.NoError(t, results.err)
	require.Equal(t, []string{"fixture#/_dockerfile/stages/2"}, ids,
		"unknown origin and USER relations suppress stage 1 while the explicit known control remains")
	require.Len(t, results.vulnerabilities, 1)
	require.Equal(t, 5, results.vulnerabilities[0].Line, "the stage unit resolves location against the original source")
	require.Equal(t, "dockerfile_container", results.vulnerabilities[0].ResourceType)
}

func TestDockerStageScopeRejectsInstructionKinds(t *testing.T) {
	roots, _ := dockerUnitTestRoots(t, "FROM alpine\n")
	query := dockerUnitTestQuery(`
# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: stage
#       kinds: [from]
package datadog
`)
	_, err := dockerUnitRoots(&query, roots)
	require.ErrorContains(t, err, "stage scope does not accept instruction kinds")
}

func TestDockerStageUnitRejectsInvalidKnownFromRelation(t *testing.T) {
	roots, _ := dockerUnitTestRoots(t, "FROM alpine\nUSER app\n")
	model := roots[0].doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	stage := model.Get(ast.StringTerm("stages")).Value.(*ast.Array).Elem(0).Value.(ast.Object)
	badStage := ast.NewObject()
	_ = stage.Iter(func(key, value *ast.Term) error {
		if key.Value.Compare(ast.String("from")) == 0 {
			badStage.Insert(key, ast.IntNumberTerm(1))
		} else {
			badStage.Insert(key, value)
		}
		return nil
	})
	_, err := newDockerStageRoot(roots[0], model, ast.NewTerm(badStage), 0)
	require.ErrorContains(t, err, "does not reference a from instruction")
}

func dockerStageUnitQuery(id string) model.QueryMetadata {
	query := dockerUnitTestQuery(`
# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: stage
package datadog
`)
	query.Query = id
	return query
}

func dockerStageIntegrationQuery() model.QueryMetadata {
	query := dockerStageUnitQuery("docker-stage-unit-gate")
	query.Content = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: stage
package datadog

import data.generic.common as common

DatadogPolicy contains common.finding(stage) if {
	some document in input.document
	stage := document._dockerfile.stage
	stage.index > 0
	not document._dockerfile.origin_from.image.registry == "public.ecr.aws"
	not document._dockerfile.user_instruction.value
}
`
	query.Metadata = map[string]interface{}{
		"id": query.Query, "platform": "Dockerfile", "queryName": "Docker stage unit test",
		"severity": model.SeverityHigh,
	}
	return query
}
