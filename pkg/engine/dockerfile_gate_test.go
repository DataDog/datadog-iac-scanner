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

const dockerGateTestLibrary = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package generic.dockerfile
`

func dockerGateTestInput(t *testing.T, content string) ast.Value {
	t.Helper()
	_, docs, _, _, err := (&dockerparser.Parser{}).Parse(context.Background(), []byte(content), "Dockerfile", false, 0)
	require.NoError(t, err)
	docs[0]["id"] = "fixture"
	input, err := ast.InterfaceToValue(map[string]interface{}{"document": docs})
	require.NoError(t, err)
	return input
}

func TestDockerUnknownGate(t *testing.T) {
	tests := []struct {
		name, content, body string
		raw, kept           int
	}{
		{"unknown comparison", "FROM alpine\nARG U\nUSER $U\n", `i := input.document[0]._dockerfile.instructions[2]; i.value.value != "root"`, 1, 0},
		{"known comparison", "FROM alpine\nUSER app\n", `i := input.document[0]._dockerfile.instructions[1]; i.value.value != "root"`, 1, 1},
		{"independent fact", "FROM alpine\nARG U\nUSER $U\n", `i := input.document[0]._dockerfile.instructions[2]; i.kind == "user"`, 1, 1},
		{"negated unknown equality", "FROM alpine\nARG U\nUSER $U\n", `i := input.document[0]._dockerfile.instructions[2]; not i.value.value == "root"`, 1, 0},
		{"known missing field", "FROM alpine\n", `not input.document[0]._dockerfile.nonexistent`, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := newDockerRuleInput(dockerGateTestInput(t, tt.content))
			require.NoError(t, err)
			rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/0","path":[]} if { ` + tt.body + ` }`
			query := model.QueryMetadata{Query: "docker-unknown-test", Platform: "Dockerfile", Content: rule}
			loader := &QueryLoader{
				commonLibrary:     source.RegoLibraries{LibraryCode: "package generic.common", LibraryInputData: "{}"},
				platformLibraries: map[string]source.RegoLibraries{"Dockerfile": {LibraryCode: dockerGateTestLibrary, LibraryInputData: "{}"}},
			}
			prepared, err := rego.New(rego.Query("result = data.datadog.DatadogPolicy"), rego.Module("rule", rule), rego.Module("docker", dockerGateTestLibrary)).PrepareForEval(context.Background())
			require.NoError(t, err)
			results, err := prepared.Eval(context.Background(), rego.EvalParsedInput(d.payload))
			require.NoError(t, err)
			items, err := resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, tt.raw)
			qCtx := &QueryContext{Query: &PreparedQuery{Metadata: query}}
			require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(context.Background(), qCtx, d, d.payload, results))
			items, err = resultItems(results)
			require.NoError(t, err)
			require.Len(t, items, tt.kept)
		})
	}
}

func TestDockerGatePreservesLegacyPayload(t *testing.T) {
	input := dockerGateTestInput(t, "FROM alpine\nARG U\nUSER $U\n")
	before, err := ast.ValueToInterface(input, nil)
	require.NoError(t, err)
	d, err := newDockerRuleInput(input)
	require.NoError(t, err)
	after, err := ast.ValueToInterface(input, nil)
	require.NoError(t, err)
	require.Equal(t, before, after, "projection must not mutate a shared legacy payload")
	projected, err := ast.ValueToInterface(d.payload, nil)
	require.NoError(t, err)
	originalDoc := before.(map[string]interface{})["document"].([]interface{})[0].(map[string]interface{})
	projectedDoc := projected.(map[string]interface{})["document"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, originalDoc["command"], projectedDoc["command"])
	require.Equal(t, originalDoc["args"], projectedDoc["args"])
}

func TestDockerGateRunsBeforeDecode(t *testing.T) {
	query := model.QueryMetadata{Query: "docker-gate-before-decode", Platform: "Dockerfile", Content: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/2","path":[]} if {
 input.document[0]._dockerfile.instructions[2].value.value != "root"
}`}
	decoded := 0
	ins := newTestInspector(t, inspectorOpts{queries: []model.QueryMetadata{query},
		vb: func(context.Context, *QueryContext, Tracker, interface{}, *detector.DetectLine, bool, time.Duration) (*model.Vulnerability, error) {
			decoded++
			return &model.Vulnerability{}, nil
		},
	})
	prepared, err := rego.New(rego.Query("result = data.datadog.DatadogPolicy"), rego.Module("rule", query.Content)).PrepareForEval(context.Background())
	require.NoError(t, err)
	payload := dockerGateTestInput(t, "FROM alpine\nARG U\nUSER $U\n")
	qCtx := &QueryContext{Ctx: context.Background(), Query: &PreparedQuery{Metadata: query, OpaQuery: prepared}, payload: &payload}
	_, _, _, err = ins.doRun(context.Background(), qCtx)
	require.NoError(t, err)
	require.Zero(t, decoded)
}

func TestDockerGateFailureDoesNotReport(t *testing.T) {
	d, err := newDockerRuleInput(dockerGateTestInput(t, "FROM alpine\nARG U\nUSER $U\n"))
	require.NoError(t, err)
	results := rego.ResultSet{{Bindings: map[string]interface{}{"result": []interface{}{map[string]interface{}{"_dd_id": "fixture#/_dockerfile", "path": []interface{}{}}}}}}
	ins := &Inspector{QueryLoader: &QueryLoader{}}
	qCtx := &QueryContext{Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "broken", Platform: "Dockerfile", Content: "invalid rego"}}}
	require.Error(t, ins.gateDockerResults(context.Background(), qCtx, d, d.payload, results))
}

// Accessors must not make a known instruction uncertain merely by returning
// its enclosing file/model, which can contain unrelated unknown values.
func TestDockerGateAccessors(t *testing.T) {
	library := dockerGateTestLibrary + `
files := [doc | some doc in input.document; object.get(doc, "_dockerfile", null) != null]
model(doc) := object.get(doc, "_dockerfile", {})
instructions(doc) := [item | some item in model(doc).instructions]
finding(item) := {"_dd_id":item._dd_meta.id,"path":[]}
`
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
import data.generic.dockerfile as docker
DatadogPolicy contains result if {
 some doc in docker.files
 some instruction in docker.instructions(doc)
 instruction.kind == "maintainer"
 result := docker.finding(instruction)
}`
	d, err := newDockerRuleInput(dockerGateTestInput(t, "FROM alpine\nMAINTAINER example\n"))
	require.NoError(t, err)
	ins := &Inspector{QueryLoader: &QueryLoader{
		commonLibrary:     source.RegoLibraries{LibraryInputData: "{}"},
		platformLibraries: map[string]source.RegoLibraries{"Dockerfile": {LibraryCode: library, LibraryInputData: "{}"}},
	}}
	prepared, err := rego.New(rego.Query("result = data.datadog.DatadogPolicy"), rego.Module("rule", rule), rego.Module("docker", library)).PrepareForEval(context.Background())
	require.NoError(t, err)
	results, err := prepared.Eval(context.Background(), rego.EvalParsedInput(d.payload))
	require.NoError(t, err)
	raw, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, raw, 1)
	q := &QueryContext{Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "accessors", Platform: "Dockerfile", Content: rule}}}
	cands, _, err := d.candidates(raw)
	require.NoError(t, err)
	gate, err := ins.newDockerUnknownGate(&q.Query.Metadata, d.placeholder)
	require.NoError(t, err)
	report, err := gate.Check(context.Background(), d.payload, cands)
	require.NoError(t, err)
	t.Logf("gate verdict: %+v", report.Verdicts)
	require.NoError(t, ins.gateDockerResults(context.Background(), q, d, d.payload, results))
	kept, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, kept, 1)
}

func TestDockerGateKnownPackageFactsDoNotInventUnknowns(t *testing.T) {
	input := dockerGateTestInput(t, "FROM python:3\nSHELL [\"/bin/sh\",\"-c\"]\nRUN pip install --upgrade pip && pip install requests\nCMD [\"cat\", \"/etc/os-release\"]\n")
	projected, err := newDockerRuleInput(input)
	require.NoError(t, err)
	require.Len(t, projected.unknownDocuments, 1, "external image configuration remains unknown")
	document := projected.documents["fixture"].(ast.Object)
	facts := document.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
	run := facts.Get(ast.StringTerm("instructions")).Value.(*ast.Array).Elem(2).Value.(ast.Object)
	packages := run.Get(ast.StringTerm("execution")).Value.(ast.Object).Get(ast.StringTerm("package_commands"))
	require.False(t, projected.hasUnknown(packages.Value), "literal package arguments do not inherit unrelated configuration uncertainty")
}
