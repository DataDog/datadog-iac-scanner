package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

func contractQuery(content string) *model.QueryMetadata {
	return &model.QueryMetadata{
		Query:    "query.rego",
		Content:  content,
		Platform: "Dockerfile",
		Metadata: map[string]interface{}{"id": "dockerfile-example"},
	}
}

const dockerContractFindingRule = `package datadog

import rego.v1

DatadogPolicy contains data.generic.common.finding("doc#/_dockerfile", "", {}) if {
	true
}`

func withDockerContractVersion(version string, rule string) string {
	return `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: ` + version + `
` + rule
}

func TestParseDockerContractVersion(t *testing.T) {
	t.Run("versioned native rule", func(t *testing.T) {
		require.NoError(t, parseDockerContractVersion(contractQuery(withDockerContractVersion("1", dockerContractFindingRule))))
	})

	t.Run("version-only annotation opts into full-root contract", func(t *testing.T) {
		require.NoError(t, parseDockerContractVersion(contractQuery(withDockerContractVersion("1", "package datadog\n"))))
	})

	t.Run("native rule missing version is an error", func(t *testing.T) {
		err := parseDockerContractVersion(contractQuery(dockerContractFindingRule))
		require.ErrorContains(t, err, "missing custom.datadog.dockerfile.version")
	})

	t.Run("unsupported version is an explicit error", func(t *testing.T) {
		err := parseDockerContractVersion(contractQuery(withDockerContractVersion("2", dockerContractFindingRule)))
		require.ErrorContains(t, err, "requires contract version 2")
	})

	t.Run("legacy metadata cannot bypass native contract", func(t *testing.T) {
		query := contractQuery(dockerContractFindingRule)
		query.Metadata["contract"] = "legacy"
		err := parseDockerContractVersion(query)
		require.ErrorContains(t, err, "cannot use legacy mode")
	})

	t.Run("non-Dockerfile rule is ignored", func(t *testing.T) {
		query := contractQuery(dockerContractFindingRule)
		query.Platform = "Terraform"
		err := parseDockerContractVersion(query)
		require.NoError(t, err)
	})

	t.Run("non-integer version is rejected", func(t *testing.T) {
		err := parseDockerContractVersion(contractQuery(withDockerContractVersion("1.5", dockerContractFindingRule)))
		require.ErrorContains(t, err, "positive integer")
	})
}

func TestValidateDockerContractInput(t *testing.T) {
	newInput := func(docs ...map[string]interface{}) ast.Value {
		values := make([]interface{}, len(docs))
		for i, doc := range docs {
			values[i] = doc
		}
		value, err := ast.InterfaceToValue(map[string]interface{}{"document": values})
		require.NoError(t, err)
		return value
	}
	validFacts := func() map[string]interface{} {
		return map[string]interface{}{
			"contract_version": docker.ContractVersion,
			"stage_names":      []interface{}{},
			"resource_type":    "dockerfile_container",
			"resource_name":    "dockerfile_container",
			"instructions":     []interface{}{},
			"stages":           []interface{}{},
			"contexts":         []interface{}{},
			"bindings":         []interface{}{},
			"global_arguments": 0,
		}
	}
	docWithFacts := func(facts map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"id": "fixture", "_dockerfile": facts}
	}

	tests := []struct {
		name    string
		input   ast.Value
		wantErr string
	}{
		{name: "matching complete v1 schema", input: newInput(docWithFacts(validFacts()))},
		{name: "missing version", input: newInput(docWithFacts(map[string]interface{}{})), wantErr: "missing contract_version"},
		{name: "missing model", input: newInput(map[string]interface{}{"id": "fixture"}), wantErr: "missing its model"},
		{name: "mismatched version", input: newInput(docWithFacts(map[string]interface{}{"contract_version": docker.ContractVersion + 1})), wantErr: "has contract version"},
		{name: "invalid version type", input: newInput(docWithFacts(map[string]interface{}{"contract_version": "1"})), wantErr: "invalid contract_version"},
		{name: "missing required array", input: newInput(docWithFacts(withoutField(validFacts(), "instructions"))), wantErr: `missing model field "instructions"`},
		{name: "wrong required array type", input: newInput(docWithFacts(withField(validFacts(), "stages", "bad"))), wantErr: `model field "stages" must be an array`},
		{name: "missing resource name", input: newInput(docWithFacts(withoutField(validFacts(), "resource_name"))), wantErr: `missing model field "resource_name"`},
		{name: "empty resource type", input: newInput(docWithFacts(withField(validFacts(), "resource_type", "  "))), wantErr: `model field "resource_type" must be a non-empty string`},
		{name: "wrong global arguments type", input: newInput(docWithFacts(withField(validFacts(), "global_arguments", "zero"))), wantErr: `model field "global_arguments" must be an integer`},
		{name: "negative global arguments", input: newInput(docWithFacts(withField(validFacts(), "global_arguments", -1))), wantErr: `model field "global_arguments" must be a non-negative integer`},
		{name: "opaque global arguments require the exact private placeholder", input: newInput(docWithFacts(withField(validFacts(), "global_arguments", "other-placeholder"))), wantErr: `model field "global_arguments" must be an integer`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDockerContractInput(tt.input, "")
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.True(t, strings.Contains(err.Error(), tt.wantErr), err.Error())
		})
	}

	t.Run("missing document array is empty input", func(t *testing.T) {
		input, err := ast.InterfaceToValue(map[string]interface{}{})
		require.NoError(t, err)
		require.NoError(t, validateDockerContractInput(input, ""))
	})
	t.Run("empty document array is empty input", func(t *testing.T) {
		require.NoError(t, validateDockerContractInput(newInput(), ""))
	})
	t.Run("exact private placeholder is accepted for unknown global arguments", func(t *testing.T) {
		const placeholder = "\x00dd-unknown-test"
		input := newInput(docWithFacts(withField(validFacts(), "global_arguments", placeholder)))
		require.NoError(t, validateDockerContractInput(input, placeholder))
		require.ErrorContains(t, validateDockerContractInput(input, "different-placeholder"), `model field "global_arguments" must be an integer`)
	})
	t.Run("real parser payload has a valid v1 schema", func(t *testing.T) {
		_, docs, _, _, err := (&docker.Parser{}).Parse(context.Background(), []byte("FROM alpine\nRUN echo ready\n"), "Dockerfile", false, 0)
		require.NoError(t, err)
		require.Len(t, docs, 1)
		docs[0]["id"] = "fixture"
		input := newInput(map[string]interface{}(docs[0]))
		require.NoError(t, validateDockerContractInput(input, ""))
	})
}

func withoutField(values map[string]interface{}, field string) map[string]interface{} {
	copy := make(map[string]interface{}, len(values)-1)
	for key, value := range values {
		if key != field {
			copy[key] = value
		}
	}
	return copy
}

func withField(values map[string]interface{}, field string, value interface{}) map[string]interface{} {
	copy := make(map[string]interface{}, len(values))
	for key, existing := range values {
		copy[key] = existing
	}
	copy[field] = value
	return copy
}

func TestDockerContractCapabilityModule(t *testing.T) {
	library := `package generic.dockerfile

import rego.v1

supported if {
	data.datadog_scanner.dockerfile_v1(1)
}`

	prepare := func(includeCapability bool) error {
		opts := []func(*rego.Rego){
			rego.Query("data.generic.dockerfile.supported"),
			rego.Module("dockerfile.rego", library),
		}
		if includeCapability {
			opts = append(opts, rego.Module(dockerContractModuleName, dockerContractModule))
		}
		_, err := rego.New(opts...).PrepareForEval(context.Background())
		return err
	}
	require.ErrorContains(t, prepare(false), "undefined function")
	require.NoError(t, prepare(true))
}
