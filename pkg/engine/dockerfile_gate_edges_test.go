package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	dockerparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

func TestDockerGateSuppressesAbsenceFromIncompleteInventory(t *testing.T) {
	content := "FROM alpine\nSHELL [\"/bin/sh\",\"-c\"]\nARG CMD\nRUN $CMD\n"
	library := dockerGateTestLibrary + `
hasNamedCommand(calls, name) if { some call in calls; call.name == name }
`
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/3", "path":[]} if {
	i := input.document[0]._dockerfile.instructions[3]
i.kind == "run"
not data.generic.dockerfile.hasNamedCommand(i.execution.calls, "danger")
}`

	d, query, loader, results := dockerGateRun(t, []string{content}, []string{"fixture"}, library, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the Rego helper emits an absence candidate despite the unknown inventory marker")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Empty(t, items, "an absence finding cannot be certified from an incomplete command inventory")
}

func TestDockerGateKeepsKnownFactFromIncompleteScript(t *testing.T) {
	content := "FROM alpine\nSHELL [\"/bin/sh\",\"-c\"]\nRUN apt-get install curl; \"$BIN\"\n"
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/2", "path":[]} if {
i := input.document[0]._dockerfile.instructions[2]
some command in i.execution.package_commands
command.manager == "apt-get"
command.action == "install"
some pkg in command.packages
pkg.name == "curl"
}`
	d, query, loader, results := dockerGateRun(t, []string{content}, []string{"fixture"}, dockerGateTestLibrary, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "a known package fact remains observable beside an incomplete command inventory")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the known package finding has a clean derivation")
}

func TestDockerGateSuppressesAbsenceWhenOrderingBudgetExceeded(t *testing.T) {
	content := "FROM alpine\nSHELL [\"/bin/sh\",\"-c\"]\nRUN " + strings.Repeat("echo x; ", 1000) + "\n"
	library := dockerGateTestLibrary + `
hasNamedCommand(calls, name) if { some call in calls; call.name == name }
`
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/2", "path":[]} if {
i := input.document[0]._dockerfile.instructions[2]
not data.generic.dockerfile.hasNamedCommand(i.execution.calls, "danger")
}`
	d, query, loader, results := dockerGateRun(t, []string{content}, []string{"fixture"}, library, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the incomplete inventory marker leaves an absence candidate for the gate")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Empty(t, items, "an ordering-analysis budget cannot certify absence")
}

func TestDockerGateKeepsKnownFindingBesideUnknownDocument(t *testing.T) {
	contents := []string{
		"FROM alpine\nARG U\nUSER $U\n",
		"FROM alpine\nUSER app\n",
	}
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id": sprintf("%s#/_dockerfile/instructions/%d", [doc.id, n]), "path":[]} if {
some doc in input.document
some n, instruction in doc._dockerfile.instructions
instruction.kind == "user"
instruction.value.value != "root"
}`
	d, query, loader, results := dockerGateRun(t, contents, []string{"unknown", "known"}, dockerGateTestLibrary, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 2)
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the unknown document's finding is suppressed without hiding the independent known document")
	kept := items[0].(map[string]interface{})["_dd_id"].(string)
	require.Contains(t, kept, "known#")
}

func TestDockerGateSuppressesCrossDocumentFindingFromUnknownDocument(t *testing.T) {
	contents := []string{
		"FROM alpine\nARG U\nUSER $U\n",
		"FROM alpine\nUSER app\n",
	}
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id": sprintf("%s#/_dockerfile/instructions/%d", [target.id, targetIndex]), "path":[]} if {
some source in input.document
source.id == "unknown"
some sourceIndex, sourceInstruction in source._dockerfile.instructions
sourceInstruction.kind == "user"
sourceInstruction.value.value != "root"
some target in input.document
target.id == "known"
some targetIndex, targetInstruction in target._dockerfile.instructions
targetInstruction.kind == "user"
targetInstruction.value.value == "app"
}`
	d, query, loader, results := dockerGateRun(t, contents, []string{"unknown", "known"}, dockerGateTestLibrary, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the finding belongs to known doc B but is selected using unknown doc A")
	require.Contains(t, items[0].(map[string]interface{})["_dd_id"], "known#")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Empty(t, items, "unknown input in doc A makes the finding for doc B uncertain")
}

func TestDockerGateDoesNotTrustAlternateDerivationWithMissingDocument(t *testing.T) {
	contents := []string{
		"FROM alpine\nARG U\nUSER $U\n",
		"FROM alpine\nUSER app\n",
	}
	library := dockerGateTestLibrary + `
hasDocument(docs, id) if { some doc in docs; doc.id == id }
`
	result := `{"_dd_id":"known#/_dockerfile/instructions/1", "path":[]}`
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains ` + result + ` if {
some source in input.document
source.id == "unknown"
some n, instruction in source._dockerfile.instructions
instruction.kind == "user"
instruction.value.value != "root"
}
DatadogPolicy contains ` + result + ` if {
not data.generic.dockerfile.hasDocument(input.document, "unknown")
some target in input.document
target.id == "known"
some n, instruction in target._dockerfile.instructions
instruction.kind == "user"
instruction.value.value == "app"
}`
	d, query, loader, results := dockerGateRun(t, contents, []string{"unknown", "known"}, library, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "the full input emits the finding through doc A's unresolved value")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Empty(t, items, "a clean derivation created only by dropping doc A cannot certify the full-input finding")
}

func TestDockerGateTracksInheritedAndWrittenUnknownValues(t *testing.T) {
	knownInput := dockerGateInputWithIDs(t, []string{"FROM alpine\nUSER app\n"}, []string{"known"})
	known, err := newDockerRuleInput(knownInput)
	require.NoError(t, err)
	require.Len(t, known.unknownDocuments, 1, "unfetched inherited configuration remains unknown")
	knownValue := known.documents["known"].(ast.Object).Get(ast.StringTerm("_dockerfile")).Value.(ast.Object).Get(ast.StringTerm("instructions")).Value.(*ast.Array).Elem(1).Value.(ast.Object).Get(ast.StringTerm("value"))
	require.False(t, known.hasUnknown(knownValue.Value), "the explicit USER value stays known independently of external defaults")

	unknownInput := dockerGateInputWithIDs(t, []string{"FROM alpine\nARG U\nUSER $U\n"}, []string{"unknown"})
	unknown, err := newDockerRuleInput(unknownInput)
	require.NoError(t, err)
	require.Len(t, unknown.unknownDocuments, 1, "a written ARG-backed value remains unknown")
	unknownValue := unknown.documents["unknown"].(ast.Object).Get(ast.StringTerm("_dockerfile")).Value.(ast.Object).Get(ast.StringTerm("instructions")).Value.(*ast.Array).Elem(2).Value.(ast.Object).Get(ast.StringTerm("value"))
	require.True(t, unknown.hasUnknown(unknownValue.Value))
}

func TestDockerGateUsesConfiguredArgumentsInEffectiveInput(t *testing.T) {
	content := "FROM alpine\nARG U\nUSER $U\n"
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/2", "path":[]} if {
input.arguments.required == "enabled"
i := input.document[0]._dockerfile.instructions[2]
i.value.value != "root"
}`
	d, query, loader, _ := dockerGateRun(t, []string{content}, []string{"fixture"}, dockerGateTestLibrary, rule)
	args, err := ast.InterfaceToValue(map[string]interface{}{"required": "enabled"})
	require.NoError(t, err)
	effective, err := withRuleArguments(d.payload, args)
	require.NoError(t, err)
	prepared, err := prepareDockerGateRule(t, effective, query, dockerGateTestLibrary, rule)
	require.NoError(t, err)
	items, err := resultItems(prepared)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(query), d, effective, prepared,
	))
	items, err = resultItems(prepared)
	require.NoError(t, err)
	require.Empty(t, items, "the rule argument enables the candidate, while the Dockerfile fact remains uncertain")
}

func TestDockerGateReturnsCompileAndCancellationErrors(t *testing.T) {
	d, _, loader, _ := dockerGateRun(t,
		[]string{"FROM alpine\nARG U\nUSER $U\n"}, []string{"fixture"}, dockerGateTestLibrary,
		`# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/2", "path":[]} if {
input.document[0]._dockerfile.instructions[2].value.value != "root"
}`,
	)
	results := rego.ResultSet{{Bindings: map[string]interface{}{"result": []interface{}{
		map[string]interface{}{"_dd_id": "fixture#/_dockerfile/instructions/2", "path": []interface{}{}},
	}}}}

	badQuery := model.QueryMetadata{Query: "docker-gate-compile-error", Platform: "Dockerfile", Content: "this is invalid rego"}
	err := (&Inspector{QueryLoader: loader}).gateDockerResults(
		context.Background(), dockerGateContext(badQuery), d, d.payload, cloneDockerResults(results),
	)
	require.Error(t, err)

	query := model.QueryMetadata{Query: "docker-gate-cancelled", Platform: "Dockerfile", Content: `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id":"fixture#/_dockerfile/instructions/2", "path":[]} if {
input.document[0]._dockerfile.instructions[2].value.value != "root"
}`}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = (&Inspector{QueryLoader: loader}).gateDockerResults(
		ctx, dockerGateContext(query), d, d.payload, cloneDockerResults(results),
	)
	require.Error(t, err)
}

func dockerGateRun(t *testing.T, contents, ids []string, library, rule string) (
	*dockerRuleInput, model.QueryMetadata, *QueryLoader, rego.ResultSet,
) {
	t.Helper()
	input := dockerGateInputWithIDs(t, contents, ids)
	d, err := newDockerRuleInput(input)
	require.NoError(t, err)
	query := model.QueryMetadata{Query: "docker-gate-edge-test", Platform: "Dockerfile", Content: rule}
	prepared, err := prepareDockerGateRule(t, d.payload, query, library, rule)
	require.NoError(t, err)
	return d, query, &QueryLoader{
		commonLibrary:     source.RegoLibraries{LibraryCode: "package generic.common", LibraryInputData: "{}"},
		platformLibraries: map[string]source.RegoLibraries{"Dockerfile": {LibraryCode: library, LibraryInputData: "{}"}},
	}, prepared
}

func dockerGateInputWithIDs(t *testing.T, contents, ids []string) ast.Value {
	t.Helper()
	require.Len(t, contents, len(ids))
	docs := make([]interface{}, 0, len(contents))
	for i, content := range contents {
		_, parsed, _, _, err := (&dockerparser.Parser{}).Parse(context.Background(), []byte(content), fmt.Sprintf("Dockerfile-%d", i), false, 0)
		require.NoError(t, err)
		parsed[0]["id"] = ids[i]
		docs = append(docs, parsed[0])
	}
	input, err := ast.InterfaceToValue(map[string]interface{}{"document": docs})
	require.NoError(t, err)
	return input
}

func prepareDockerGateRule(t *testing.T, input ast.Value, query model.QueryMetadata, library, rule string) (rego.ResultSet, error) {
	t.Helper()
	prepared, err := rego.New(
		rego.Query("result = data.datadog.DatadogPolicy"),
		rego.Module("rule", rule), rego.Module("generic", library),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}
	return prepared.Eval(context.Background(), rego.EvalParsedInput(input))
}

func dockerGateContext(query model.QueryMetadata) *QueryContext {
	return &QueryContext{Query: &PreparedQuery{Metadata: query}}
}

func cloneDockerResults(results rego.ResultSet) rego.ResultSet {
	cloned := make(rego.ResultSet, len(results))
	for i, result := range results {
		bindings := make(map[string]interface{}, len(result.Bindings))
		for key, value := range result.Bindings {
			bindings[key] = value
		}
		cloned[i].Bindings = bindings
	}
	return cloned
}
