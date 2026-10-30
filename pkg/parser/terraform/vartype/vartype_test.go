/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package vartype

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func parseNative(t *testing.T, src string) hcl.Expression {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	return expr
}

func TestConformAppliesOptionalAttributeDefaults(t *testing.T) {
	constraint, ok := Parse(parseNative(t, `object({ enabled = optional(bool, false), name = optional(string) })`))
	require.True(t, ok)
	got, err := constraint.Conform(cty.EmptyObjectVal)
	require.NoError(t, err)
	require.True(t, got.RawEquals(cty.ObjectVal(map[string]cty.Value{
		"enabled": cty.False,
		"name":    cty.NullVal(cty.String),
	})), "%#v", got)
}

func TestConformConvertsToTheType(t *testing.T) {
	constraint, ok := Parse(parseNative(t, `number`))
	require.True(t, ok)
	got, err := constraint.Conform(cty.StringVal("5"))
	require.NoError(t, err)
	require.True(t, got.RawEquals(cty.NumberIntVal(5)))

	_, err = constraint.Conform(cty.StringVal("five"))
	require.Error(t, err)
}

func TestParseReadsJSONStringConstraints(t *testing.T) {
	file, diags := hcljson.Parse([]byte(`{"type": "list(string)"}`), "main.tf.json")
	require.False(t, diags.HasErrors(), diags.Error())
	attrs, diags := file.Body.JustAttributes()
	require.False(t, diags.HasErrors(), diags.Error())
	constraint, ok := Parse(attrs["type"].Expr)
	require.True(t, ok)
	require.Equal(t, cty.List(cty.String), constraint.Type)
}

func TestParseRejectsInvalidConstraints(t *testing.T) {
	_, ok := Parse(parseNative(t, `nope`))
	require.False(t, ok)
	constraint, ok := Parse(parseNative(t, `"list(string)"`))
	require.False(t, ok, "a quoted native constraint is not a type")
	require.Equal(t, Any, constraint)

	file, diags := hcljson.Parse([]byte(`{"type": "list(("}`), "main.tf.json")
	require.False(t, diags.HasErrors(), diags.Error())
	attrs, _ := file.Body.JustAttributes()
	_, ok = Parse(attrs["type"].Expr)
	require.False(t, ok)
}
