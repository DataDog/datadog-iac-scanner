/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

const unknownPolicyModule = `
resource "aws_iam_role" "r" {
  name = "r"
}

data "aws_iam_policy_document" "p" {
  statement {
    sid       = "Logs"
    actions   = ["logs:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.r.arn]
    }
  }
  statement {
    sid       = "Mixed"
    actions   = ["s3:GetObject"]
    resources = [aws_iam_role.r.arn, "arn:aws:s3:::b/*"]
  }
  statement {
    sid       = "Template"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::b/${aws_iam_role.r.arn}/*"]
  }
}

resource "aws_iam_policy" "p" {
  name   = "p"
  policy = data.aws_iam_policy_document.p.json
}
`

// An unresolved value of a policy document is replaced in the rendered JSON;
// the statements and fields around it stay known.
func TestDataPolicyDocumentKeepsKnownPartsAroundUnknownValues(t *testing.T) {
	e := New()
	e.SetOpaquePartialData(true)
	dir := writeModule(t, t.TempDir(), "root", map[string]string{"main.tf": unknownPolicyModule})
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	text, ok := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "p")))["policy"].(string)
	require.True(t, ok, "policy is not a known string")
	var policy struct {
		Statement []struct {
			Sid        string
			Actions    []string
			Resources  []string
			Principals map[string][]string
		}
	}
	require.NoError(t, json.Unmarshal([]byte(text), &policy))
	require.Len(t, policy.Statement, 3)

	unknown := value.UnknownMarker
	logs := policy.Statement[0]
	require.Equal(t, []string{"logs:*"}, logs.Actions)
	require.Equal(t, []string{"*"}, logs.Resources)
	require.Equal(t, map[string][]string{"AWS": {unknown}}, logs.Principals)

	mixed := policy.Statement[1]
	require.Equal(t, []string{"s3:GetObject"}, mixed.Actions)
	require.Equal(t, []string{unknown, "arn:aws:s3:::b/*"}, mixed.Resources)

	require.Equal(t, []string{unknown}, policy.Statement[2].Resources)
}

// Outside opaque mode the unresolved reference keeps its text.
func TestDataPolicyDocumentKeepsReferenceTextWithoutOpaqueMode(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "root", map[string]string{"main.tf": unknownPolicyModule})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	text, _ := AttributesToDocument(ptr(findResource(t, resources, "aws_iam_policy", "p")))["policy"].(string)
	require.Contains(t, text, "${aws_iam_role.r.arn}")
	require.NotContains(t, text, value.UnknownMarker)
}

// A string the expression evaluates to, wholly known, is kept even when it
// reads like interpolation text; only the strings it does not resolve are
// replaced.
func TestMarkUnresolvedKeepsWhollyKnownStrings(t *testing.T) {
	rendered := cty.TupleVal([]cty.Value{cty.StringVal("${a.b}"), cty.StringVal("${aws:username}"), cty.StringVal("*")})
	known := cty.TupleVal([]cty.Value{cty.UnknownVal(cty.String), cty.StringVal("${aws:username}"), cty.StringVal("*")})

	got := markUnresolved(rendered, known, true)
	require.True(t, got.RawEquals(cty.TupleVal([]cty.Value{
		cty.StringVal(value.UnknownMarker), cty.StringVal("${aws:username}"), cty.StringVal("*"),
	})))

	got = markUnresolved(rendered, cty.NilVal, false)
	require.True(t, got.RawEquals(cty.TupleVal([]cty.Value{
		cty.StringVal(value.UnknownMarker), cty.StringVal(value.UnknownMarker), cty.StringVal("*"),
	})))
}
