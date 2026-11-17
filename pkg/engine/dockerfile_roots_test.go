package engine

import (
	"context"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	dockerparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

func TestDockerContractRule(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		content  string
		metadata map[string]interface{}
		want     bool
	}{
		{
			name:     "package alias",
			platform: "Dockerfile",
			content: `package datadog
import data.generic.common as c
DatadogPolicy contains c.finding(input.document[0]) if { true }`,
			want: true,
		},
		{
			name:     "direct function alias",
			platform: "Dockerfile",
			content: `package datadog
import data.generic.common.finding as emit
DatadogPolicy contains emit(input.document[0]) if { true }`,
			want: true,
		},
		{
			name:     "fully qualified function",
			platform: "Dockerfile",
			content: `package datadog
DatadogPolicy contains data.generic.common.finding(input.document[0]) if { true }`,
			want: true,
		},
		{
			name:     "nested package alias",
			platform: "Dockerfile",
			content: `package datadog
import data.generic as g
DatadogPolicy contains g.common.finding(input.document[0]) if { true }`,
			want: true,
		},
		{
			name:     "unused import does not opt in",
			platform: "Dockerfile",
			content: `package datadog
import data.generic.common as c
DatadogPolicy contains {"searchKey":"x"} if { true }`,
			want: false,
		},
		{
			name:     "legacy metadata cannot hide native API",
			platform: "Dockerfile",
			content: `package datadog
import data.generic.common.finding as emit
DatadogPolicy contains emit(input.document[0]) if { true }`,
			metadata: map[string]interface{}{"contract": "legacy"},
			want:     true,
		},
		{
			name:     "other platform",
			platform: "Terraform",
			content: `package datadog
import data.generic.common.finding as emit
DatadogPolicy contains emit(input.document[0]) if { true }`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := model.QueryMetadata{
				Platform: tt.platform,
				Content:  tt.content,
				Metadata: tt.metadata,
			}
			require.Equal(t, tt.want, dockerContractRule(&query))
		})
	}
}

func TestDoRunDockerRootsIsolatesIndependentBuildRoots(t *testing.T) {
	const common = `package generic.common
finding(item) := {"_dd_id": item._dd_meta.id, "path": []}
`
	const content = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
import data.generic.common as c
DatadogPolicy contains c.finding(instruction) if {
	count(input.document) == 1
	doc := input.document[0]
	count(doc._dockerfile.stages) == 2
	some instruction in doc._dockerfile.instructions
	instruction.kind == "user"
	instruction.value.value != "root"
	input.arguments.enabled
}`
	query := model.QueryMetadata{Query: "docker-root-isolation", Platform: "Dockerfile", Content: content}
	var decoded []string
	ins := newTestInspector(t, inspectorOpts{queries: []model.QueryMetadata{query}, vb: func(_ context.Context, _ *QueryContext, _ Tracker, result interface{}, _ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
		finding := result.(map[string]interface{})
		decoded = append(decoded, finding["_dd_id"].(string))
		return &model.Vulnerability{FileID: "fixture", SearchKey: finding["_dd_id"].(string)}, nil
	}})
	ins.enableCoverageReport = true
	ins.QueryLoader.commonLibrary = source.RegoLibraries{LibraryCode: common, LibraryInputData: "{}"}
	ins.QueryLoader.parsedCommon = nil
	ins.QueryLoader.platformLibraries["Dockerfile"] = source.RegoLibraries{LibraryCode: dockerGateTestLibrary, LibraryInputData: "{}"}
	delete(ins.QueryLoader.parsedGeneric, "Dockerfile")
	prepared, err := ins.QueryLoader.LoadQuery(context.Background(), &query, nil, nil, nil, false)
	require.NoError(t, err)

	unknownDoc := dockerRootTestDocument(t, "unknown", "FROM alpine AS build\nARG U\nUSER $U\nFROM build\n")
	knownDoc := dockerRootTestDocument(t, "known", "FROM alpine AS build\nRUN echo ok\nFROM build\nUSER app\n")
	input, err := ast.InterfaceToValue(map[string]interface{}{
		"document":  []interface{}{unknownDoc, knownDoc},
		"arguments": map[string]interface{}{"enabled": true},
	})
	require.NoError(t, err)
	dockerInput, err := newDockerRuleInput(input)
	require.NoError(t, err)
	ctx := &QueryContext{
		Ctx:         context.Background(),
		Query:       &PreparedQuery{OpaQuery: *prepared, Metadata: query},
		payload:     &input,
		dockerInput: dockerInput,
		Files:       map[string]*model.FileMetadata{"fixture": {FilePath: "Dockerfile"}},
	}

	vulns, _, _, err := ins.doRunDockerRoots(context.Background(), ctx)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, []string{"known#/_dockerfile/instructions/3"}, decoded)
	require.Contains(t, decoded[0], "known#")
	require.NotNil(t, ctx.coverage)
	require.Contains(t, ins.coverageReport.Files, query.Query)
}

func TestDoRunLegacyDockerRuleKeepsCombinedInput(t *testing.T) {
	query := model.QueryMetadata{
		Query:    "docker-legacy-combined",
		Platform: "Dockerfile",
		Metadata: map[string]interface{}{"contract": "legacy"},
		Content: `package datadog
DatadogPolicy contains {"documentId":"known", "searchKey":"command[1]"} if {
	count(input.document) == 2
	input.arguments.enabled
	input.document[1].id == "known"
}`,
	}
	require.False(t, dockerContractRule(&query))
	var decoded []string
	ins := newTestInspector(t, inspectorOpts{queries: []model.QueryMetadata{query}, vb: func(_ context.Context, _ *QueryContext, _ Tracker, result interface{}, _ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
		decoded = append(decoded, result.(map[string]interface{})["documentId"].(string))
		return &model.Vulnerability{FileID: "fixture"}, nil
	}})
	prepared, err := ins.QueryLoader.LoadQuery(context.Background(), &query, nil, nil, nil, false)
	require.NoError(t, err)
	unknownDoc := dockerRootTestDocument(t, "unknown", "FROM alpine\nARG U\nUSER $U\n")
	knownDoc := dockerRootTestDocument(t, "known", "FROM alpine\nUSER app\n")
	input, err := ast.InterfaceToValue(map[string]interface{}{
		"document":  []interface{}{unknownDoc, knownDoc},
		"arguments": map[string]interface{}{"enabled": true},
	})
	require.NoError(t, err)
	dockerInput, err := newDockerRuleInput(input)
	require.NoError(t, err)
	ctx := &QueryContext{
		Ctx:         context.Background(),
		Query:       &PreparedQuery{OpaQuery: *prepared, Metadata: query},
		payload:     &input,
		dockerInput: dockerInput,
		Files:       map[string]*model.FileMetadata{"fixture": {FilePath: "Dockerfile"}},
	}

	vulns, _, _, err := ins.doRun(context.Background(), ctx)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, []string{"known"}, decoded)
}

func TestDoRunDockerRootsFailureReturnsNoPartialResults(t *testing.T) {
	query := model.QueryMetadata{Query: "docker-root-failure", Platform: "Dockerfile", Content: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id": sprintf("%s#/_dockerfile/instructions/0", [input.document[0].id]), "path":[]} if { true }`}
	ins := newTestInspector(t, inspectorOpts{queries: []model.QueryMetadata{query}, vb: func(_ context.Context, _ *QueryContext, _ Tracker, _ interface{}, _ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
		return &model.Vulnerability{FileID: "fixture"}, nil
	}})
	prepared, err := rego.New(
		rego.Query("result = data.datadog.DatadogPolicy"),
		rego.Module("rule", query.Content),
		rego.Module("Generic", dockerGateTestLibrary),
	).PrepareForEval(context.Background())
	require.NoError(t, err)
	ins.QueryLoader.parsedCommon = nil
	ins.QueryLoader.commonLibrary.LibraryCode = "invalid rego"
	firstDoc := dockerRootTestDocument(t, "first", "FROM alpine\nUSER app\n")
	secondDoc := dockerRootTestDocument(t, "second", "FROM alpine\nARG U\nUSER $U\n")
	input, err := ast.InterfaceToValue(map[string]interface{}{"document": []interface{}{firstDoc, secondDoc}})
	require.NoError(t, err)
	dockerInput, err := newDockerRuleInput(input)
	require.NoError(t, err)
	qCtx := &QueryContext{
		Ctx:         context.Background(),
		Query:       &PreparedQuery{OpaQuery: prepared, Metadata: query},
		payload:     &input,
		dockerInput: dockerInput,
		Files:       map[string]*model.FileMetadata{"fixture": {FilePath: "Dockerfile"}},
	}

	vulns, _, _, err := ins.doRunDockerRoots(context.Background(), qCtx)
	require.Error(t, err)
	require.Empty(t, vulns)
}

func TestDoRunDockerRootsCancellationReturnsNoPartialResults(t *testing.T) {
	ins := newTestInspector(t, inspectorOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	vulns, raised, severity, err := ins.doRunDockerRoots(ctx, &QueryContext{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, vulns)
	require.Zero(t, raised)
	require.Empty(t, severity)
}

func dockerRootTestDocument(t *testing.T, id, content string) map[string]interface{} {
	t.Helper()
	_, documents, _, _, err := (&dockerparser.Parser{}).Parse(context.Background(), []byte(content), "Dockerfile", false, 0)
	require.NoError(t, err)
	require.Len(t, documents, 1)
	documents[0]["id"] = id
	return documents[0]
}
