package engine

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestProjectDockerFailedRunMountInventories(t *testing.T) {
	const placeholder = "opaque-unknown-mounts"
	knownCacheMount := map[string]interface{}{"kind": "cache", "target": "/cache"}
	knownEmptyMounts := []interface{}{}
	partialMounts := []interface{}{knownCacheMount}
	facts := map[string]interface{}{
		"instructions": []interface{}{
			map[string]interface{}{"kind": "run", "parse_ok": false, "mounts": partialMounts},
			map[string]interface{}{"kind": "run", "parse_ok": true, "mounts": knownEmptyMounts},
			map[string]interface{}{"kind": "shell", "parse_ok": false, "mounts": []interface{}{}},
			map[string]interface{}{
				"kind":     "onbuild",
				"parse_ok": true,
				"trigger":  map[string]interface{}{"kind": "run", "parse_ok": false, "mounts": []interface{}{}},
			},
		},
	}

	projectDockerFailedRunMountInventories(facts, placeholder)

	instructions := facts["instructions"].([]interface{})
	failedRun := instructions[0].(map[string]interface{})
	require.Equal(t, []interface{}{knownCacheMount, placeholder}, failedRun["mounts"], "known partial facts remain available alongside the open inventory marker")
	validRun := instructions[1].(map[string]interface{})
	require.Equal(t, knownEmptyMounts, validRun["mounts"], "a valid empty mount inventory stays known-empty")
	invalidShell := instructions[2].(map[string]interface{})
	require.Empty(t, invalidShell["mounts"], "non-RUN parse failures do not taint mount inventories")
	onbuild := instructions[3].(map[string]interface{})
	trigger := onbuild["trigger"].(map[string]interface{})
	require.Equal(t, []interface{}{placeholder}, trigger["mounts"], "failed deferred RUN mount inventory is also open")
}

func TestProjectDockerFailedRunMountInventoriesHandlesMissingMountList(t *testing.T) {
	const placeholder = "opaque-unknown-mounts"
	facts := map[string]interface{}{
		"instructions": []interface{}{map[string]interface{}{"kind": "run", "parse_ok": false}},
	}

	projectDockerFailedRunMountInventories(facts, placeholder)

	instruction := facts["instructions"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, []interface{}{placeholder}, instruction["mounts"])
}

func TestNewDockerRuleInputPreservesFailedRunMountUnknowns(t *testing.T) {
	doc := dockerRootTestDocument(t, "fixture", `FROM alpine
SHELL ["/bin/sh", "-c"]
ARG CACHE_UID=1000
RUN --mount=type=cache,target=/cache/pip,uid=$CACHE_UID pip install --cache-dir=/cache/pip flask
`)
	input, err := ast.InterfaceToValue(map[string]interface{}{"document": []interface{}{doc}})
	require.NoError(t, err)
	dockerInput, err := newDockerRuleInput(input)
	require.NoError(t, err)
	raw, err := ast.ValueToInterface(dockerInput.payload, nil)
	require.NoError(t, err)
	root := raw.(map[string]interface{})
	document := root["document"].([]interface{})[0].(map[string]interface{})
	facts := document["_dockerfile"].(map[string]interface{})
	instructions := facts["instructions"].([]interface{})
	run := instructions[3].(map[string]interface{})
	require.NotContains(t, run, "parse_ok", "parser diagnostics are stripped after uncertainty projection")
	mounts := run["mounts"].([]interface{})
	require.Contains(t, mounts, dockerInput.placeholder, "the missing mount fact remains an open inventory")
	execution := run["execution"].(map[string]interface{})
	cacheFacts := execution["package_cache_mounts"].([]interface{})
	require.Len(t, cacheFacts, 1)
	cacheFact := cacheFacts[0].(map[string]interface{})
	require.NotContains(t, cacheFact, "known", "knownness metadata is stripped from policy input")
	require.Equal(t, dockerInput.placeholder, cacheFact["value"], "the unknown value remains opaque")
}

func TestDockerGateSuppressesCacheDependentFindingButKeepsKnownPackageFinding(t *testing.T) {
	content := `FROM alpine
SHELL ["/bin/sh", "-c"]
ARG CACHE_UID=1000
RUN --mount=type=cache,target=/cache/pip,uid=$CACHE_UID pip install --cache-dir=/cache/pip flask
`
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog
DatadogPolicy contains {"_dd_id": instruction._dd_meta.id, "path": ["cache"]} if {
 some document in input.document
 some instruction in document._dockerfile.instructions
 instruction.kind == "run"
 some cache in instruction.execution.package_cache_mounts
 cache.value != true
}
DatadogPolicy contains {"_dd_id": instruction._dd_meta.id, "path": ["unpinned"]} if {
 some document in input.document
 some instruction in document._dockerfile.instructions
 instruction.kind == "run"
 some command in instruction.execution.package_commands
 command.manager == "pip"
 some pkg in command.packages
 pkg.name == "flask"
 pkg.pinned == false
}`
	d, query, loader, results := dockerGateRun(t, []string{content}, []string{"fixture"}, dockerGateTestLibrary, rule)
	items, err := resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 2, "the test policy sees both an uncertain cache result and an independent package result")
	require.NoError(t, (&Inspector{QueryLoader: loader}).gateDockerResults(
		t.Context(), dockerGateContext(query), d, d.payload, results,
	))
	items, err = resultItems(results)
	require.NoError(t, err)
	require.Len(t, items, 1, "only the candidate that depends on missing mount expansion should be suppressed")
	kept := items[0].(map[string]interface{})
	require.Equal(t, []interface{}{"unpinned"}, kept["path"])
}
