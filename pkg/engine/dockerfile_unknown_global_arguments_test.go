package engine

import (
	"context"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

const dockerUnknownGlobalArgumentsCommon = `package generic.common
finding(item) := {"_dd_id": item._dd_meta.id, "path": []}
`

func TestFailedGlobalArgProjectionKeepsIndependentFindingAndSuppressesDependentFinding(t *testing.T) {
	const rule = `package datadog
import data.generic.common as common

DatadogPolicy contains common.finding(instruction) if {
some document in input.document
some instruction in document._dockerfile.instructions
instruction.kind == "run"
}

DatadogPolicy contains common.finding(instruction) if {
some document in input.document
some instruction in document._dockerfile.instructions
instruction.kind == "user"
document._dockerfile.global_arguments != 0
}`
	query := model.QueryMetadata{
		Query:    "dockerfile-failed-global-arg",
		Platform: "Dockerfile",
		Content:  withDockerContractVersion("1", rule),
	}
	var decodedIDs []string
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{query},
		vb: func(_ context.Context, _ *QueryContext, _ Tracker, result interface{}, _ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
			decodedIDs = append(decodedIDs, result.(map[string]interface{})["_dd_id"].(string))
			return &model.Vulnerability{FileID: "fixture"}, nil
		},
	})
	ins.QueryLoader.commonLibrary = source.RegoLibraries{LibraryCode: dockerUnknownGlobalArgumentsCommon, LibraryInputData: "{}"}
	ins.QueryLoader.parsedCommon = nil
	ins.QueryLoader.platformLibraries["Dockerfile"] = source.RegoLibraries{LibraryCode: dockerGateTestLibrary, LibraryInputData: "{}"}
	delete(ins.QueryLoader.parsedGeneric, "Dockerfile")
	prepared, err := ins.QueryLoader.LoadQuery(context.Background(), &query, nil, nil, nil, false)
	require.NoError(t, err)

	doc := dockerRootTestDocument(t, "fixture", "ARG =invalid\nFROM alpine\nRUN echo safe\nUSER app\n")
	input, err := ast.InterfaceToValue(map[string]interface{}{"document": []interface{}{doc}})
	require.NoError(t, err)
	dockerInput, err := newDockerRuleInput(input)
	require.NoError(t, err)
	rawResults, err := prepared.Eval(context.Background(), rego.EvalParsedInput(dockerInput.payload))
	require.NoError(t, err)
	rawItems, err := resultItems(rawResults)
	require.NoError(t, err)
	require.Len(t, rawItems, 2, "the rule must produce both independent and global-argument-dependent candidates before the unknown gate")
	qCtx := &QueryContext{
		Ctx:         context.Background(),
		Query:       &PreparedQuery{OpaQuery: *prepared, Metadata: query},
		payload:     &input,
		dockerInput: dockerInput,
		Files:       map[string]*model.FileMetadata{"fixture": {FilePath: "Dockerfile"}},
	}

	vulns, _, _, err := ins.doRunDockerRoots(context.Background(), qCtx)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, []string{"fixture#/_dockerfile/instructions/2"}, decodedIDs)
}
