/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"testing"

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
				`"StringEquals":{"aws:SourceAccount":["1"]}},"Principals":{"AWS":["*"],"Service":["lambda.amazonaws.com"]}}]}` + "\n",
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
			want: `{"Id":"p","Statement":[{"Actions":["*"],"Effect":"Allow"}]}` + "\n",
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
					"override": cty.StringVal(`{"Statement":[{"Sid":"Keep","Effect":"Deny","Actions":["sqs:*"]}]}`),
				}),
			},
			want: `{"Statement":[{"Actions":["sqs:*"],"Effect":"Deny","Sid":"Keep"},{"Actions":["s3:ListBucket"],"Sid":"Own"}],` +
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
				`"NumericLessThan":{"s3:TlsVersion":["1.2"]}},"Effect":"Deny","Sid":"DenyHTTP"}]}` + "\n",
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
					"override": cty.StringVal(`{"Statement":[{"Sid":"Own","Effect":"Allow","Action":"*","Resource":"*"}]}`),
				}),
			},
			want: `{"Statement":[{"Actions":["sqs:*"],"Effect":"Allow","Sid":"Keep"},{"Actions":["*"],"Effect":"Allow","Resources":["*"],"Sid":"Own"}]}` + "\n",
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
