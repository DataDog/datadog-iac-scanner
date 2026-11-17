package engine

import (
	"context"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	dockerparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

const dockerInstructionUnitRule = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: instruction
#       kinds: [user]
package datadog
import data.generic.common as common

DatadogPolicy contains common.finding(instruction) if {
	input.arguments.enabled
	some document in input.document
	count(document._dockerfile.instructions) == 1
	some instruction in document._dockerfile.instructions
	instruction.kind == "user"
	instruction.value.value != "root"
}
`

const dockerInstructionUnitCommon = `package generic.common
finding(item) := {"_dd_id": item._dd_meta.id, "path": []}
hasNamedCommand(calls, name) if { some call in calls; call.name == name }
`

func TestEvalQueryDockerInstructionUnitsGateUnknownsAndResolveOriginalSource(t *testing.T) {
	content := "FROM alpine\nARG USER_NAME\nUSER $USER_NAME\nUSER app\n"
	query := dockerInstructionUnitMetadata("docker-instruction-unit-source")
	var ids []string
	builder := func(ctx context.Context, qCtx *QueryContext, tracker Tracker, result interface{}, lineDetector *detector.DetectLine, useOldSeverities bool, duration time.Duration) (*model.Vulnerability, error) {
		finding := result.(map[string]interface{})
		ids = append(ids, finding["_dd_id"].(string))
		return DefaultVulnerabilityBuilder(ctx, qCtx, tracker, result, lineDetector, useOldSeverities, duration)
	}
	ins := newDockerInstructionUnitInspector(t, query, builder)
	dockerInput, rawInput, file := dockerInstructionUnitInput(t, content)
	require.Nil(t, rawInput.(ast.Object).Get(ast.StringTerm("arguments")), "the rule argument must come from rule configuration")
	results := ins.evalQuery(context.Background(), "scan", map[string]*model.FileMetadata{file.ID: file}, platformPayloads{
		dockerInput: dockerInput,
		byPlatform:  map[string]ast.Value{"dockerfile": rawInput},
		full:        rawInput,
	}, []model.QueryMetadata{query}, 0, nil, nil, nil, nil, nil)
	require.NoError(t, results.err)
	require.Equal(t, []string{"fixture#/_dockerfile/instructions/3"}, ids,
		"the unknown USER unit is suppressed and the known sibling is reported at its original instruction index")
	require.Len(t, results.vulnerabilities, 1)
	vulnerability := results.vulnerabilities[0]
	require.Equal(t, "Dockerfile", vulnerability.FileName)
	require.Equal(t, 4, vulnerability.Line)
	require.Equal(t, "dockerfile_container", vulnerability.ResourceType)
}

func TestEvalQueryDockerFileUnitKeepsUnknownInventoryMarkerAndKnownSibling(t *testing.T) {
	query := dockerInstructionUnitMetadata("docker-file-complete-input")
	query.Content = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: dockerfile
package datadog
import data.generic.common as common

DatadogPolicy contains common.finding(instruction) if {
	input.arguments.enabled
	some document in input.document
	some instruction in document._dockerfile.instructions
	instruction.kind == "run"
	not common.hasNamedCommand(instruction.execution.calls, "danger")
}
DatadogPolicy contains common.finding(instruction) if {
	input.arguments.enabled
	some document in input.document
	some instruction in document._dockerfile.instructions
	instruction.kind == "user"
	instruction.value.value != "root"
}
`
	var ids []string
	builder := func(ctx context.Context, qCtx *QueryContext, tracker Tracker, result interface{}, lineDetector *detector.DetectLine, useOldSeverities bool, duration time.Duration) (*model.Vulnerability, error) {
		ids = append(ids, result.(map[string]interface{})["_dd_id"].(string))
		return DefaultVulnerabilityBuilder(ctx, qCtx, tracker, result, lineDetector, useOldSeverities, duration)
	}
	ins := newDockerInstructionUnitInspector(t, query, builder)
	dockerInput, rawInput, file := dockerInstructionUnitInput(t, "FROM alpine\nARG CMD\nRUN $CMD\nUSER app\n")
	results := ins.evalQuery(context.Background(), "scan", map[string]*model.FileMetadata{file.ID: file}, platformPayloads{
		dockerInput: dockerInput,
		byPlatform:  map[string]ast.Value{"dockerfile": rawInput},
		full:        rawInput,
	}, []model.QueryMetadata{query}, 0, nil, nil, nil, nil, nil)
	require.NoError(t, results.err)
	require.Equal(t, []string{"fixture#/_dockerfile/instructions/3"}, ids,
		"the unknown RUN inventory absence is suppressed while the selected known USER fact survives")
	require.Len(t, results.vulnerabilities, 1)
	require.Equal(t, 4, results.vulnerabilities[0].Line, "location resolves from the original full Dockerfile")
}

func TestEvalQueryDockerInstructionUnitsReuseAndReleaseLineInfo(t *testing.T) {
	query := dockerInstructionUnitMetadata("docker-instruction-unit-line-info")
	content := "FROM alpine\nUSER app\nUSER guest\n"
	var calls int
	builder := func(ctx context.Context, qCtx *QueryContext, _ Tracker, _ interface{}, _ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
		file := qCtx.Files["fixture"]
		require.NoError(t, file.EnsureLineInfoDocument(ctx))
		require.Equal(t, "fixture", file.LineInfoDocument["id"])
		return &model.Vulnerability{FileID: file.ID, FileName: file.FilePath}, nil
	}
	ins := newDockerInstructionUnitInspector(t, query, builder)
	ins.SetReleasePostEvalData(true)
	dockerInput, rawInput, file := dockerInstructionUnitInput(t, content)
	file.SetLineInfoLoader(func(context.Context, *model.FileMetadata) (map[string]interface{}, error) {
		calls++
		return map[string]interface{}{"id": file.ID}, nil
	})
	results := ins.evalQuery(context.Background(), "scan", map[string]*model.FileMetadata{file.ID: file}, platformPayloads{
		dockerInput: dockerInput,
		byPlatform:  map[string]ast.Value{"dockerfile": rawInput},
		full:        rawInput,
	}, []model.QueryMetadata{query}, 0, nil, nil, nil, nil, nil)
	require.NoError(t, results.err)
	require.Len(t, results.vulnerabilities, 2)
	require.Equal(t, 1, calls, "instruction units from the same file reuse one loaded line-info tree")
	require.Nil(t, file.LineInfoDocument, "the tree is released after the last unit for the file")
}

func TestEvalQueryDockerInstructionUnitsReleaseLineInfoOnCancellation(t *testing.T) {
	query := dockerInstructionUnitMetadata("docker-instruction-unit-cancel")
	content := "FROM alpine\nUSER app\nUSER guest\n"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	var builds int
	builder := func(ctx context.Context, qCtx *QueryContext, _ Tracker, _ interface{}, _ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
		file := qCtx.Files["fixture"]
		require.NoError(t, file.EnsureLineInfoDocument(ctx))
		builds++
		cancel()
		return &model.Vulnerability{FileID: file.ID}, nil
	}
	ins := newDockerInstructionUnitInspector(t, query, builder)
	ins.SetReleasePostEvalData(true)
	dockerInput, rawInput, file := dockerInstructionUnitInput(t, content)
	file.SetLineInfoLoader(func(context.Context, *model.FileMetadata) (map[string]interface{}, error) {
		calls++
		return map[string]interface{}{"id": file.ID}, nil
	})
	results := ins.evalQuery(ctx, "scan", map[string]*model.FileMetadata{file.ID: file}, platformPayloads{
		dockerInput: dockerInput,
		byPlatform:  map[string]ast.Value{"dockerfile": rawInput},
		full:        rawInput,
	}, []model.QueryMetadata{query}, 0, nil, nil, nil, nil, nil)
	require.ErrorIs(t, results.err, context.Canceled)
	require.Empty(t, results.vulnerabilities, "cancellation must not return partial root results")
	require.Equal(t, 1, builds)
	require.Equal(t, 1, calls, "the second unit is not evaluated after cancellation")
	require.Nil(t, file.LineInfoDocument, "the shared tree is released on cancellation")
}

func dockerInstructionUnitMetadata(id string) model.QueryMetadata {
	return model.QueryMetadata{
		Query:    "docker-instruction-unit",
		Platform: "Dockerfile",
		Content:  dockerInstructionUnitRule,
		Metadata: map[string]interface{}{
			"id": id, "platform": "Dockerfile", "queryName": "Docker instruction unit",
			"severity": model.SeverityHigh,
		},
	}
}

func newDockerInstructionUnitInspector(t *testing.T, query model.QueryMetadata, builder VulnerabilityBuilder) *Inspector {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{queries: []model.QueryMetadata{query}, vb: builder})
	ins.QueryLoader.commonLibrary = source.RegoLibraries{LibraryCode: dockerInstructionUnitCommon, LibraryInputData: "{}"}
	ins.QueryLoader.parsedCommon = nil
	ins.QueryLoader.platformLibraries["Dockerfile"] = source.RegoLibraries{LibraryCode: dockerGateTestLibrary, LibraryInputData: "{}"}
	delete(ins.QueryLoader.parsedGeneric, "Dockerfile")
	queryID := query.Metadata["id"].(string)
	ins.ruleConfigs = map[string]config.IacRuleConfig{
		queryID: {Arguments: map[string]any{"enabled": true}},
	}
	return ins
}

func dockerInstructionUnitInput(t *testing.T, content string) (*dockerRuleInput, ast.Value, *model.FileMetadata) {
	t.Helper()
	_, documents, _, _, err := (&dockerparser.Parser{}).Parse(context.Background(), []byte(content), "Dockerfile", false, 0)
	require.NoError(t, err)
	require.Len(t, documents, 1)
	documents[0]["id"] = "fixture"
	rawInput, err := ast.InterfaceToValue(map[string]interface{}{"document": documents})
	require.NoError(t, err)
	dockerInput, err := newDockerRuleInput(rawInput)
	require.NoError(t, err)
	file := &model.FileMetadata{ID: "fixture", FilePath: "Dockerfile", Kind: model.KindDOCKER, OriginalData: content}
	file.SetLazyLines()
	return dockerInput, rawInput, file
}
