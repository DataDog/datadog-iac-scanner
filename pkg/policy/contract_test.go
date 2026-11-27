/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package policy

import (
	"encoding/json"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestPathKeyEscapingAndSourceMapping(t *testing.T) {
	// Dots, backslashes, leading digits, and integer indexes stay distinct.
	require.Equal(t, `tags.a\.b`, PathKey(Path{Key("tags"), Key("a.b")}))
	require.Equal(t, `tags.\0`, PathKey(Path{Key("tags"), Key("0")}))
	require.Equal(t, `ingress.0.cidr_blocks`, PathKey(Path{Key("ingress"), Index(0), Key("cidr_blocks")}))

	sm := &SourceMapping{
		BlockSpan: SourceSpan{File: "main.tf", StartLine: 1, StartCol: 1, EndLine: 10, EndCol: 1},
		Ranges: map[string]SourceSpan{
			"":              {File: "main.tf", StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 30},
			"ingress.0":     {File: "main.tf", StartLine: 4, StartCol: 3, EndLine: 7, EndCol: 4},
			"ingress.0.tag": {File: "main.tf", StartLine: 5, StartCol: 5, EndLine: 5, EndCol: 18},
		},
	}
	// Exact path hit.
	require.Equal(t, 5, sm.Range(Path{Key("ingress"), Index(0), Key("tag")}).StartLine)
	// Falls back to deepest ancestor.
	require.Equal(t, 4, sm.Range(Path{Key("ingress"), Index(0), Key("missing")}).StartLine)
	// Unindexed nested block resolves to first block.
	require.Equal(t, 4, sm.Range(Path{Key("ingress")}).StartLine)
	// Empty path resolves to header span.
	require.Equal(t, 1, sm.Range(nil).StartLine)
}

func TestProjectUnitsAndDecodeFinding(t *testing.T) {
	bucket := &Resource{
		ID:      "r:0",
		Kind:    "resource",
		Type:    "aws_s3_bucket",
		Name:    "logs",
		Address: "aws_s3_bucket.logs",
		File:    "main.tf",
		Attributes: map[string]any{
			"bucket": "my-logs",
		},
		State: ValueState{
			Unknown: map[string]bool{"acl": true},
			Written: map[string]bool{"bucket": true, "acl": true},
		},
		Relations: &ResourceRelations{
			Related: map[string]map[string]RelationList{
				"aws_s3_bucket_versioning": {
					"bucket": {IDs: []string{"r:1"}, Complete: true},
				},
			},
		},
	}
	unit := &Unit{
		ID:            ".",
		Platform:      "terraform",
		ScopeComplete: true,
		Resources:     []*Resource{bucket},
		ByID:          map[string]*Resource{"r:0": bucket},
	}

	val := ProjectUnits("terraform", []*Unit{unit}, ProjectOptions{IncludeRelations: true, IncludeByID: true})
	obj, ok := val.(ast.Object)
	require.True(t, ok)
	require.Equal(t, ast.String("v2"), obj.Get(ast.StringTerm("contract_version")).Value)
	require.NotNil(t, obj.Get(ast.StringTerm("by_id")))

	// Single-resource projection omits relations and by_id.
	single := ProjectUnits("terraform", []*Unit{unit}, ProjectOptions{AllowedTypes: map[string]bool{"aws_s3_bucket": true}})
	singleObj := single.(ast.Object)
	require.Nil(t, singleObj.Get(ast.StringTerm("by_id")))

	// Finding decoding handles typed paths and after-only remediation.
	f, err := DecodeFinding(map[string]any{
		"_dd_id":          "r:0",
		"path":            []any{"versioning", json.Number("0"), "enabled"},
		"after":           "true",
		"remediationType": "replacement",
	})
	require.NoError(t, err)
	require.Equal(t, "r:0", f.ResourceID)
	require.Equal(t, "versioning.0.enabled", PathKey(f.Path))
	require.Equal(t, "true", f.After)
}

func TestDecodeFindingRequiresPathAndRejectsLegacyDerivedFields(t *testing.T) {
	base := map[string]any{"_dd_id": "r:1", "path": []any{}}
	_, err := DecodeFinding(map[string]any{"_dd_id": "r:1"})
	require.ErrorContains(t, err, "missing path")
	_, err = DecodeFinding(map[string]any{"_dd_id": "r:1", "path": nil})
	require.ErrorIs(t, err, ErrInvalidPath)
	for _, field := range []string{"documentId", "searchKey", "resourceType", "resourceName"} {
		raw := map[string]any{}
		for key, value := range base {
			raw[key] = value
		}
		raw[field] = "legacy"
		_, err := DecodeFinding(raw)
		require.ErrorContains(t, err, "legacy derived field")
		require.ErrorContains(t, err, field)
	}
}

func TestDecodeFindingPathContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		path any
		want Path
	}{
		{name: "empty path", path: "", want: nil},
		{name: "string path", path: "acl", want: Path{Key("acl")}},
		{name: "indexed path", path: []any{"ingress", 0, "cidr_blocks"}, want: Path{Key("ingress"), Index(0), Key("cidr_blocks")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finding, err := DecodeFinding(map[string]any{"_dd_id": "r:1", "path": tc.path})
			require.NoError(t, err)
			require.Equal(t, tc.want, finding.Path)
		})
	}

	for _, invalid := range []any{nil, 42, map[string]any{}, true, []any{"valid", 0, false}} {
		_, err := DecodeFinding(map[string]any{"_dd_id": "r:1", "path": invalid})
		require.ErrorIs(t, err, ErrInvalidPath)
	}
}

func TestFindingOptionalTextFieldsRejectNonStrings(t *testing.T) {
	for _, field := range []string{"after", "remediation", "remediationType", "overrideKey"} {
		for _, invalid := range []any{true, json.Number("14"), nil, []any{}} {
			_, err := DecodeFinding(map[string]any{"_dd_id": "r:1", "path": []any{}, field: invalid})
			require.ErrorContains(t, err, "must be a string")
		}
	}
}
