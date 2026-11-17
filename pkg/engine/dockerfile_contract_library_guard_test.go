package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const unversionedDockerLibraryRule = `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if { true }`

const versionedDockerLibrary = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package generic.dockerfile

import rego.v1

files := [document | some document in input.document]
`

func dockerContractLibraryLoader(ruleContent, libraryContent string) (*QueryLoader, *model.QueryMetadata) {
	return &QueryLoader{
		platformLibraries: map[string]source.RegoLibraries{
			"Dockerfile": {LibraryCode: libraryContent},
		},
	}, &model.QueryMetadata{
		Query:    "dockerfile-contract-library-guard",
		Platform: "Dockerfile",
		Content:  ruleContent,
	}
}

func TestVersionedDockerfileLibraryRequiresRuleVersionEvenForLegacyOutput(t *testing.T) {
	loader, query := dockerContractLibraryLoader(unversionedDockerLibraryRule, versionedDockerLibrary)
	require.False(t, dockerContractRule(query), "legacy result and no direct API/ref should exercise the library guard")
	err := loader.validateDockerContractMetadata(query)
	require.ErrorContains(t, err, "versioned platform library")
	require.ErrorContains(t, err, "must declare custom.datadog.dockerfile.version")
}

func TestVersionedDockerfileLibraryGuardsObjectGetFactAccess(t *testing.T) {
	queryContent := `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if {
	document := input.document[0]
	facts := object.get(document, "_dockerfile", {})
	facts.instructions[_].kind == "run"
}`
	loader, query := dockerContractLibraryLoader(queryContent, versionedDockerLibrary)
	require.False(t, dockerContractRule(query), "object.get's string key is not an AST ref")
	err := loader.validateDockerContractMetadata(query)
	require.ErrorContains(t, err, "versioned platform library")
}

func TestUnversionedDockerfileLibraryPreservesLegacyRule(t *testing.T) {
	loader, query := dockerContractLibraryLoader(unversionedDockerLibraryRule, "package generic.dockerfile\n")
	require.False(t, dockerContractRule(query))
	require.NoError(t, loader.validateDockerContractMetadata(query))
}

func TestVersionedDockerfileRuleRequiresVersionedLibrary(t *testing.T) {
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog

DatadogPolicy contains {"searchKey": "legacy"} if { true }`
	loader, query := dockerContractLibraryLoader(rule, "package generic.dockerfile\n")
	require.ErrorContains(t, loader.validateDockerContractMetadata(query), "library is missing its contract version declaration")
}

func TestVersionedDockerfileRuleAndLibraryMatch(t *testing.T) {
	rule := `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
package datadog

DatadogPolicy contains {"searchKey": "legacy"} if { true }`
	loader, query := dockerContractLibraryLoader(rule, versionedDockerLibrary)
	require.NoError(t, loader.validateDockerContractMetadata(query))
}

func TestUnversionedDockerfileLibraryPreservesLegacyHelperImports(t *testing.T) {
	query := `package datadog
import data.generic.dockerfile as docker
DatadogPolicy contains {"documentId":"fixture", "searchKey":"USER"} if {
 docker.legacy_check(input.document)
}`
	loader, metadata := dockerContractLibraryLoader(query, `package generic.dockerfile
legacy_check(documents) if { count(documents) > 0 }
`)
	require.False(t, dockerContractRule(metadata), "the legacy and native libraries share their package name")
	require.NoError(t, loader.validateDockerContractMetadata(metadata))
	loader.platformLibraries["Dockerfile"] = source.RegoLibraries{LibraryCode: versionedDockerLibrary}
	require.ErrorContains(t, loader.validateDockerContractMetadata(metadata), "versioned platform library")
}
