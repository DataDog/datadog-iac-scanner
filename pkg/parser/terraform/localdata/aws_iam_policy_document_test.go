/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func decodeJSON(t *testing.T, src string, vars map[string]cty.Value) string {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	ctx := &hcl.EvalContext{Variables: vars}
	policy := decodePolicyDocument(file.Body, func(expr hcl.Expression) (cty.Value, bool) {
		v, d := expr.Value(ctx)
		return v, !d.HasErrors()
	})
	out, err := policy.render()
	require.NoError(t, err)
	return out
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		src  string
		vars map[string]cty.Value
		want string
	}{
		{
			name: "multiple principals and conditions",
			src: `
statement {
  actions = ["s3:GetObject"]
  principals {
    type        = "AWS"
    identifiers = ["*"]
  }
  principals {
    type        = "Service"
    identifiers = ["lambda.amazonaws.com"]
  }
  condition {
    test     = "StringEquals"
    variable = "aws:SourceAccount"
    values   = ["1"]
  }
  condition {
    test     = "Bool"
    variable = "aws:SecureTransport"
    values   = ["false"]
  }
}`,
			want: `{"Statement":[{"Actions":["s3:GetObject"],"Condition":{"Bool":{"aws:SecureTransport":["false"]},` +
				`"StringEquals":{"aws:SourceAccount":["1"]}},"Effect":"Allow","Principals":{"AWS":["*"],"Service":["lambda.amazonaws.com"]}}],"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "effect defaults to Allow",
			src: `
statement {
  actions   = ["s3:*"]
  resources = ["*"]
}`,
			want: `{"Statement":[{"Actions":["s3:*"],"Effect":"Allow","Resources":["*"]}],"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "dynamic blocks expand to statements, principals and conditions",
			src: `
dynamic "statement" {
  for_each = { a = "s3:Get*", b = "s3:Put*" }
  content {
    sid     = statement.key
    actions = [statement.value]
    dynamic "principals" {
      for_each = ["lambda.amazonaws.com"]
      iterator = p
      content {
        type        = "Service"
        identifiers = [p.value]
      }
    }
    dynamic "condition" {
      for_each = ["1"]
      content {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [condition.value]
      }
    }
  }
}
statement {
  actions = ["x:y"]
}`,
			want: `{"Statement":[` +
				`{"Actions":["s3:Get*"],"Condition":{"StringEquals":{"aws:SourceAccount":["1"]}},"Effect":"Allow",` +
				`"Principals":{"Service":["lambda.amazonaws.com"]},"Sid":"a"},` +
				`{"Actions":["s3:Put*"],"Condition":{"StringEquals":{"aws:SourceAccount":["1"]}},"Effect":"Allow",` +
				`"Principals":{"Service":["lambda.amazonaws.com"]},"Sid":"b"},` +
				`{"Actions":["x:y"],"Effect":"Allow"}],"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "dynamic block whose for_each does not resolve generates none",
			src: `
dynamic "statement" {
  for_each = var.missing
  content {
    actions = ["s3:*"]
  }
}
statement {
  actions = ["x:y"]
}`,
			want: `{"Statement":[{"Actions":["x:y"],"Effect":"Allow"}],"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "sensitive for_each still expands",
			src: `
dynamic "statement" {
  for_each = var.names
  content {
    actions = [statement.value]
  }
}`,
			vars: map[string]cty.Value{
				"var": cty.ObjectVal(map[string]cty.Value{
					"names": cty.TupleVal([]cty.Value{cty.StringVal("s3:*")}).Mark("sensitive"),
				}),
			},
			want: `{"Statement":[{"Actions":["s3:*"],"Effect":"Allow"}],"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "unresolvable field leaves the rest",
			src: `
policy_id = "p"
statement {
  effect    = "Allow"
  actions   = ["*"]
  resources = [var.missing]
}`,
			want: `{"Id":"p","Statement":[{"Actions":["*"],"Effect":"Allow"}],"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "source and override documents merge by sid",
			src: `
source_policy_documents   = [var.src]
override_policy_documents = [var.override]
statement {
  sid     = "Own"
  actions = ["s3:ListBucket"]
}`,
			vars: map[string]cty.Value{
				"var": cty.ObjectVal(map[string]cty.Value{
					"src": cty.StringVal(`{"Version":"2012-10-17","Statement":[` +
						`{"Sid":"Keep","Effect":"Allow","Action":"sqs:*","Principal":"*"},` +
						`{"Sid":"Own","Effect":"Allow","Action":["s3:*"]}]}`),
					"override": cty.StringVal(`{"Statement":[{"Sid":"Keep","Effect":"Deny","Actions":["sqs:*"]}],"Version":"2012-10-17"}`),
				}),
			},
			want: `{"Statement":[{"Actions":["sqs:*"],"Effect":"Deny","Sid":"Keep"},{"Actions":["s3:ListBucket"],"Effect":"Allow","Sid":"Own"}],` +
				`"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "source condition values that are not strings read as text",
			src:  `source_policy_documents = [var.src]`,
			vars: map[string]cty.Value{
				"var": cty.ObjectVal(map[string]cty.Value{
					"src": cty.StringVal(`{"Statement":[{"Sid":"DenyHTTP","Effect":"Deny","Action":"s3:*",` +
						`"Condition":{"Bool":{"aws:SecureTransport":false},"NumericLessThan":{"s3:TlsVersion":1.2}}}]}`),
				}),
			},
			want: `{"Statement":[{"Actions":["s3:*"],"Condition":{"Bool":{"aws:SecureTransport":["false"]},` +
				`"NumericLessThan":{"s3:TlsVersion":["1.2"]}},"Effect":"Deny","Sid":"DenyHTTP"}],"Version":"2012-10-17"}` + "\n",
		},
		{
			name: "deprecated source_json and override_json merge by sid",
			src: `
source_json   = var.src
override_json = var.override
statement {
  sid     = "Own"
  actions = ["s3:ListBucket"]
}`,
			vars: map[string]cty.Value{
				"var": cty.ObjectVal(map[string]cty.Value{
					"src":      cty.StringVal(`{"Statement":[{"Sid":"Keep","Effect":"Allow","Action":"sqs:*"}]}`),
					"override": cty.StringVal(`{"Statement":[{"Sid":"Own","Effect":"Allow","Action":"*","Resource":"*"}],"Version":"2012-10-17"}`),
				}),
			},
			want: `{"Statement":[{"Actions":["sqs:*"],"Effect":"Allow","Sid":"Keep"},{"Actions":["*"],"Effect":"Allow","Resources":["*"],"Sid":"Own"}],"Version":"2012-10-17"}` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, decodeJSON(t, tt.src, tt.vars))
		})
	}
}

func TestParseJSONPrincipalWildcard(t *testing.T) {
	policy, ok := parsePolicyJSON(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}}`)
	require.True(t, ok)
	require.Len(t, policy.Statements, 1)
	require.Equal(t, map[string][]string{"AWS": {"*"}}, policy.Statements[0].Principals)
	require.Equal(t, []string{"*"}, policy.Statements[0].Resources)
}

func renderedAttributes(t *testing.T, src string) map[string]string {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	rd := &partial.Renderer{Ctx: &hcl.EvalContext{Variables: map[string]cty.Value{}}, Source: partial.BytesSource([]byte(src))}
	return policyDocumentAttributes(file.Body, rd.Render)
}

func TestDynamicContentRendersUnresolvedPartsApartFromIterator(t *testing.T) {
	got := renderedAttributes(t, `
dynamic "statement" {
  for_each = ["a"]
  content {
    actions   = [statement.value, var.x]
    resources = ["arn:${statement.value}:${var.y}"]
  }
}`)
	require.Equal(t, `{"Statement":[{"Actions":["a","${var.x}"],"Effect":"Allow","Resources":["arn:a:${var.y}"]}],`+
		`"Version":"2012-10-17"}`+"\n", got["json"])
}

func TestDocumentOfUnresolvedDynamicBlocksStaysUnresolved(t *testing.T) {
	require.Nil(t, renderedAttributes(t, `
dynamic "statement" {
  for_each = var.rules
  content {
    actions = ["s3:*"]
  }
}`))
	got := renderedAttributes(t, `
dynamic "statement" {
  for_each = var.rules
  content {
    actions = ["s3:*"]
  }
}
statement {
  actions = ["x:y"]
}`)
	require.Contains(t, got["json"], `"x:y"`)
}

func TestLaterDocumentVersionWinsEvenWhenLexicallySmaller(t *testing.T) {
	attrs := renderedAttributes(t, `
source_json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"A\",\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
version     = "2008-10-17"
`)
	require.Contains(t, attrs["json"], `"Version":"2008-10-17"`)
}
