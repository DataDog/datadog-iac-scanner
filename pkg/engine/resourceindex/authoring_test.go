/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthoringNormalizationSharesUnchangedSubtrees(t *testing.T) {
	nested := map[string]interface{}{"tags": map[string]interface{}{"owner": "iac"}}
	values := []interface{}{"one", "two"}
	source := map[string]interface{}{
		"nested": nested,
		"values": values,
	}

	entry := makeEntry(source, "doc", "resource", "name", nil)

	entryNested := entry["nested"].(map[string]interface{})
	entryNested["shared"] = true
	require.Equal(t, true, nested["shared"])

	entryValues := entry["values"].([]interface{})
	require.True(t, &values[0] == &entryValues[0])
	require.NotContains(t, source, EntryResourceType)
	require.NotContains(t, source, EntryDD)
}

func TestAuthoringNormalizationDoesNotMutateSource(t *testing.T) {
	source := map[string]interface{}{
		"_parsed_run": map[string]interface{}{
			"_parsed_command": map[string]interface{}{"ok": true},
			"_dd_lines":       map[string]interface{}{"run": 1},
		},
		"_dd_filter_expr": map[string]interface{}{
			"_op":    "==",
			"_value": "main",
		},
		"nested": map[string]interface{}{
			"_kics_lines": map[string]interface{}{"field": 1},
			"value":       "kept",
		},
	}
	expected := map[string]interface{}{
		"_parsed_run": map[string]interface{}{
			"_parsed_command": map[string]interface{}{"ok": true},
			"_dd_lines":       map[string]interface{}{"run": 1},
		},
		"_dd_filter_expr": map[string]interface{}{
			"_op":    "==",
			"_value": "main",
		},
		"nested": map[string]interface{}{
			"_kics_lines": map[string]interface{}{"field": 1},
			"value":       "kept",
		},
	}

	makeCICDEntry(source, "doc", "github_step", "step", nil)

	require.Equal(t, expected, source)
}

func TestAuthoringNormalizationTransformsCICDParsedFieldsRecursively(t *testing.T) {
	source := map[string]interface{}{
		"_parsed_run": map[string]interface{}{
			"_parsed_command": map[string]interface{}{
				"ok":        true,
				"_dd_lines": map[string]interface{}{"command": 1},
			},
			"_parsed_expressions_shell": []interface{}{
				map[string]interface{}{"_parsed_token": "echo"},
			},
		},
	}

	entry := makeCICDEntry(source, "doc", "github_step", "step", nil)

	run := entry["analysis"].(map[string]interface{})["run"].(map[string]interface{})
	runAnalysis := run["analysis"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"ok": true}, runAnalysis["command"])
	expressions := runAnalysis["expressions"].(map[string]interface{})
	token := expressions["shell"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, "echo", token["analysis"].(map[string]interface{})["token"])
	require.NotContains(t, runAnalysis["command"], "_dd_lines")

	fieldMap := entry[EntryDD].(map[string]interface{})[EntryDDFieldMap].(ProvenanceMap)
	require.Equal(t, "_parsed_run", fieldMap["analysis.run"])
}

func TestAuthoringNormalizationScopesFilterFields(t *testing.T) {
	source := map[string]interface{}{
		"_op":           "user-operator",
		"_value":        "user-value",
		"_parsed_value": "user-parsed-value",
		"nested": map[string]interface{}{
			"_op":    "nested-user-operator",
			"_value": "nested-user-value",
		},
		"_dd_filter_expr": map[string]interface{}{
			"_op": "&&",
			"_left": map[string]interface{}{
				"_selector": "branch",
				"_value":    "main",
			},
			"_right": map[string]interface{}{
				"_op":    "==",
				"_value": "release",
			},
		},
	}

	entry := makeEntry(source, "doc", "resource", "name", nil)

	require.Equal(t, "user-operator", entry["_op"])
	require.Equal(t, "user-value", entry["_value"])
	require.Equal(t, "user-parsed-value", entry["_parsed_value"])
	require.Equal(t, source["nested"], entry["nested"])

	filter := entry["filterExpression"].(map[string]interface{})
	require.Equal(t, "&&", filter["operator"])
	require.Equal(t, "branch", filter["left"].(map[string]interface{})["selector"])
	require.Equal(t, "main", filter["left"].(map[string]interface{})["value"])
	require.Equal(t, "==", filter["right"].(map[string]interface{})["operator"])
	require.Equal(t, "release", filter["right"].(map[string]interface{})["value"])

	fieldMap := entry[EntryDD].(map[string]interface{})[EntryDDFieldMap].(ProvenanceMap)
	require.Equal(t, "_dd_filter_expr", fieldMap["filterExpression"])
	require.Equal(t, "_op", fieldMap["filterExpression.operator"])
}

func TestAuthoringNormalizationHidesNestedParserInternals(t *testing.T) {
	shared := map[string]interface{}{"owner": "iac"}
	source := map[string]interface{}{
		"configuration": map[string]interface{}{
			"shared": shared,
			"nested": map[string]interface{}{
				"value":       "kept",
				"_dd_lines":   map[string]interface{}{"value": 1},
				"_kics_lines": map[string]interface{}{"value": 1},
				"EndLine":     4,
			},
		},
	}

	entry := makeEntry(source, "doc", "resource", "name", nil)

	configuration := entry["configuration"].(map[string]interface{})
	nested := configuration["nested"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"value": "kept"}, nested)
	configuration["shared"].(map[string]interface{})["shared"] = true
	require.Equal(t, true, shared["shared"])

	sourceNested := source["configuration"].(map[string]interface{})["nested"].(map[string]interface{})
	require.Contains(t, sourceNested, "_dd_lines")
	require.Contains(t, sourceNested, "_kics_lines")
	require.Contains(t, sourceNested, "EndLine")
}
