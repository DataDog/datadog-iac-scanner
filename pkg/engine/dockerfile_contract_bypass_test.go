package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestDockerContractRuleRecognizesVersionedFactAPIs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "direct API reference",
			content: `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if {
	data.datadog_scanner.dockerfile_v1(1)
	count(input.document) > 0
}`,
			want: true,
		},
		{
			name: "API package alias",
			content: `package datadog
import data.datadog_scanner as scanner
DatadogPolicy contains {"searchKey": "legacy"} if {
	scanner.dockerfile_v1(1)
	count(input.document) > 0
}`,
			want: true,
		},
		{
			name: "API function alias",
			content: `package datadog
import data.datadog_scanner.dockerfile_v1 as dockerfile_v1
DatadogPolicy contains {"searchKey": "legacy"} if {
	dockerfile_v1(1)
	count(input.document) > 0
}`,
			want: true,
		},
		{
			name: "Generic Dockerfile package alias",
			content: `package datadog
import data.generic.dockerfile as docker
DatadogPolicy contains {"searchKey": "legacy"} if {
	count(docker.files) > 0
}`,
			want: false,
		},
		{
			name: "Generic parent package alias",
			content: `package datadog
import data.generic as generic
DatadogPolicy contains {"searchKey": "legacy"} if {
	count(generic.dockerfile.files) > 0
}`,
			want: false,
		},
		{
			name: "specific Generic Dockerfile helper alias",
			content: `package datadog
import data.generic.dockerfile.files as docker_files
DatadogPolicy contains {"searchKey": "legacy"} if {
	count(docker_files) > 0
}`,
			want: false,
		},
		{
			name: "API reference inside helper rule",
			content: `package datadog
capable if { data.datadog_scanner.dockerfile_v1(1) }
DatadogPolicy contains {"searchKey": "legacy"} if {
	capable
	count(input.document) > 0
}`,
			want: true,
		},
		{
			name: "direct raw model access",
			content: `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if {
	input.document[0]._dockerfile.instructions[_].kind == "run"
}`,
			want: true,
		},
		{
			name: "raw model access through local document alias",
			content: `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if {
	document := input.document[0]
	document._dockerfile.instructions[_].kind == "run"
}`,
			want: true,
		},
		{
			name: "unused Generic Dockerfile import stays legacy",
			content: `package datadog
import data.generic.dockerfile as docker
DatadogPolicy contains {"searchKey": "legacy"} if { true }`,
			want: false,
		},
		{
			name: "unrelated reference stays legacy",
			content: `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if {
	input.document[0].dockerfile.files == []
}`,
			want: false,
		},
		{
			name: "string containing model field name stays legacy",
			content: `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if {
"_dockerfile" == "_dockerfile"
}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := model.QueryMetadata{Platform: "Dockerfile", Query: "dockerfile-contract-bypass", Content: tt.content}
			require.Equal(t, tt.want, dockerContractRule(&query))
		})
	}
}

func TestDockerContractRuleRejectsUnversionedFactConsumerWithLegacyOutput(t *testing.T) {
	query := model.QueryMetadata{
		Platform: "Dockerfile",
		Query:    "unversioned-dockerfile-facts",
		Content: `package datadog
import data.generic.dockerfile as docker
DatadogPolicy contains {"searchKey": "legacy"} if {
	some document in docker.files
	document._dockerfile.instructions[_].kind == "run"
}`,
	}

	require.True(t, dockerContractRule(&query))
	err := (&QueryLoader{}).validateDockerContractMetadata(&query)
	require.ErrorContains(t, err, "missing custom.datadog.dockerfile.version")
}

func TestDockerContractRuleRejectsUnversionedRawFactConsumer(t *testing.T) {
	query := model.QueryMetadata{
		Platform: "Dockerfile",
		Query:    "unversioned-raw-dockerfile-facts",
		Content: `package datadog
DatadogPolicy contains {"searchKey": "legacy"} if {
	input.document[_]._dockerfile.instructions[_].kind == "run"
}`,
	}

	require.True(t, dockerContractRule(&query))
	err := (&QueryLoader{}).validateDockerContractMetadata(&query)
	require.ErrorContains(t, err, "missing custom.datadog.dockerfile.version")
}

func TestDockerContractRuleLeavesFactIndependentLegacyRuleUnversioned(t *testing.T) {
	query := model.QueryMetadata{
		Platform: "Dockerfile",
		Query:    "legacy-dockerfile-search-key",
		Content: `package datadog
DatadogPolicy contains {"searchKey": "FROM={{alpine}}"} if { true }`,
	}

	require.False(t, dockerContractRule(&query))
	require.NoError(t, (&QueryLoader{}).validateDockerContractMetadata(&query))
}
