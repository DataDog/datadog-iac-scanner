/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
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
	policy, ok := decodePolicyDocument(file.Body, func(expr hcl.Expression) (cty.Value, bool) {
		v, d := expr.Value(ctx)
		return v, !d.HasErrors()
	})
	require.True(t, ok)
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
			name: "null effect defaults to Allow",
			src: `
statement {
  effect    = null
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
	require.Equal(t, map[string][]string{"*": {"*"}}, policy.Statements[0].Principals)
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
	require.Nil(t, renderedAttributes(t, `
dynamic "statement" {
  for_each = var.rules
  content {
    actions = ["s3:*"]
  }
}
statement {
  actions = ["x:y"]
}`))
	require.Nil(t, renderedAttributes(t, `
statement {
  actions = ["s3:*"]
  dynamic "principals" {
    for_each = var.principals
    content {
      type        = "AWS"
      identifiers = [principals.value]
    }
  }
}`))
}

func TestUnresolvedSourcePolicyDocumentsStayUnresolved(t *testing.T) {
	require.Nil(t, renderedAttributes(t, `
source_policy_documents = [var.missing]
statement {
  actions = ["s3:*"]
}
`))
	require.Nil(t, renderedAttributes(t, `
source_policy_documents = ["not-json"]
statement {
  actions = ["s3:*"]
}
`))
}

func TestNullOrEmptySourceDocumentsAreUnset(t *testing.T) {
	for _, src := range []string{
		`
source_policy_documents = null
statement {
  actions = ["s3:*"]
}
`,
		`
source_policy_documents = []
statement {
  actions = ["s3:*"]
}
`,
		`
source_json = ""
statement {
  actions = ["s3:*"]
}
`,
		`
source_json = null
statement {
  actions = ["s3:*"]
}
`,
	} {
		got := renderedAttributes(t, src)
		require.Contains(t, got["json"], `"s3:*"`)
	}
}

func policyWithVersions(source, own string) string {
	src := `source_json = "{\"Version\":\"` + source + `\",\"Statement\":[{\"Sid\":\"A\",\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"` + "\n"
	if own != "" {
		src += `version = "` + own + `"` + "\n"
	}
	return src
}

func TestVersionMergeLikeProvider(t *testing.T) {
	tests := []struct {
		name         string
		src, version string
		want         string
	}{
		{name: "own version without sources", src: `
version = "2008-10-17"
statement {
  actions = ["s3:*"]
}`, want: "2008-10-17"},
		{name: "unset version defaults", src: `
statement {
  actions = ["s3:*"]
}`, want: "2012-10-17"},
		{name: "newer source version wins over the default", src: policyWithVersions("2020-01-01", ""), want: "2020-01-01"},
		{name: "older source version upgrades to the default", src: policyWithVersions("2008-10-17", ""), want: "2012-10-17"},
		{name: "older own version keeps the newer source", src: policyWithVersions("2012-10-17", "2008-10-17"), want: "2012-10-17"},
		{name: "newer own version wins over the source", src: policyWithVersions("2008-10-17", "2020-01-01"), want: "2020-01-01"},
		{name: "own version keeps an older source out", src: policyWithVersions("2008-10-17", "2008-10-18"), want: "2008-10-18"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Contains(t, renderedAttributes(t, tt.src)["json"], `"Version":"`+tt.want+`"`)
		})
	}
}

func TestOverrideVersionUpgrades(t *testing.T) {
	got := renderedAttributes(t, `
version       = "2008-10-17"
override_json = "{\"Version\":\"2020-01-01\",\"Statement\":[{\"Sid\":\"A\",\"Effect\":\"Allow\",\"Action\":\"s3:*\"}]}"
`)
	require.Contains(t, got["json"], `"Version":"2020-01-01"`)
}

func TestSameTypePrincipalsAndConditionsMerge(t *testing.T) {
	got := renderedAttributes(t, `
statement {
  actions = ["s3:*"]
  principals {
    type        = "AWS"
    identifiers = ["a"]
  }
  principals {
    type        = "AWS"
    identifiers = ["b"]
  }
  not_principals {
    type        = "Service"
    identifiers = ["x"]
  }
  not_principals {
    type        = "Service"
    identifiers = ["y"]
  }
  condition {
    test     = "StringEquals"
    variable = "aws:SourceAccount"
    values   = ["1"]
  }
  condition {
    test     = "StringEquals"
    variable = "aws:SourceAccount"
    values   = ["2"]
  }
  condition {
    test     = "StringEquals"
    variable = "aws:PrincipalOrgID"
    values   = ["o"]
  }
}`)["json"]
	require.Contains(t, got, `"Principals":{"AWS":["a","b"]}`)
	require.Contains(t, got, `"Not_principals":{"Service":["x","y"]}`)
	require.Contains(t, got, `"StringEquals":{"aws:PrincipalOrgID":["o"],"aws:SourceAccount":["1","2"]}`)
}

func TestUnreadableSourceDocumentsStayUnresolved(t *testing.T) {
	for _, attr := range []string{
		"source_policy_documents", "override_policy_documents",
	} {
		for name, value := range map[string]string{
			"unresolved":   "[var.missing]",
			"not json":     `["not-json"]`,
			"empty string": `[""]`,
		} {
			t.Run(attr+" "+name, func(t *testing.T) {
				require.Nil(t, renderedAttributes(t, attr+" = "+value+`
statement {
  actions = ["s3:*"]
}`))
			})
		}
	}
	for _, attr := range []string{"source_json", "override_json"} {
		for name, value := range map[string]string{
			"unresolved": "var.missing",
			"not json":   `"not-json"`,
		} {
			t.Run(attr+" "+name, func(t *testing.T) {
				require.Nil(t, renderedAttributes(t, attr+" = "+value+`
statement {
  actions = ["s3:*"]
}`))
			})
		}
	}
}

// productionAttributes renders with the variables and functions the parser
// evaluates documents with, so an unresolved reference reaches the document
// the way it does in a scan.
func productionAttributes(t *testing.T, src string) map[string]string {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	rd := &partial.Renderer{
		Ctx: &hcl.EvalContext{
			Variables: map[string]cty.Value{"var": cty.EmptyObjectVal},
			Functions: functions.TerraformFuncs,
		},
		Source: partial.BytesSource([]byte(src)),
	}
	return policyDocumentAttributes(file.Body, rd.Render)
}

func TestSourceDocumentWithUnresolvedFieldStaysUnresolved(t *testing.T) {
	for name, field := range map[string]string{
		"condition":                 `Condition = var.cond`,
		"condition test":            `Condition = { Bool = { "aws:SecureTransport" = "true" }, StringEquals = var.eq }`,
		"condition values object":   `Condition = { StringEquals = { "aws:SourceAccount" = { a = var.x } } }`,
		"principal list":            `Principal = ["a"]`,
		"principal identifiers":     `Principal = { AWS = [{ a = var.x }] }`,
		"principal empty":           `Principal = ""`,
		"action nested":             `Action = [["s3:*"]]`,
		"sid not a string":          `Sid = { a = 1 }`,
		"effect not a string":       `Effect = ["Allow"]`,
		"statement list of strings": ``,
	} {
		t.Run(name, func(t *testing.T) {
			stmt := `{ Sid = "S", Effect = "Allow", Action = "s3:GetObject", Resource = "*", ` + field + ` }`
			if field == "" {
				stmt = `var.stmt`
			}
			require.Nil(t, productionAttributes(t, `
source_policy_documents = [jsonencode({
  Version   = "2012-10-17"
  Statement = [`+stmt+`]
})]
`))
		})
	}
}

func TestSourceDocumentFieldsThatAreSetOrNullStayResolved(t *testing.T) {
	got := productionAttributes(t, `
source_policy_documents = [jsonencode({
  Version   = "2012-10-17"
  Statement = [{
    Sid       = "S"
    Effect    = "Deny"
    Action    = ["s3:*", "s3:Get*"]
    Resource  = "*"
    Principal = { AWS = ["a"] }
    Condition = { Bool = { "aws:SecureTransport" = false }, NumericLessThan = { "s3:TlsVersion" = [1.2] } }
  }, {
    Sid          = "N"
    Effect       = "Allow"
    NotAction    = null
    Principal    = null
    Condition    = null
    NotResource  = "arn:aws:s3:::b"
  }]
})]
`)
	require.NotNil(t, got)
	require.Contains(t, got["json"], `"Bool":{"aws:SecureTransport":["false"]}`)
	require.Contains(t, got["json"], `"NumericLessThan":{"s3:TlsVersion":["1.2"]}`)
	require.Contains(t, got["json"], `"Not_resources":["arn:aws:s3:::b"]`)
}

func TestParsePolicyJSONFailsClosedOnUnreadableFields(t *testing.T) {
	for name, raw := range map[string]string{
		"condition string":         `{"Statement":[{"Effect":"Allow","Condition":"${var.c}"}]}`,
		"condition test string":    `{"Statement":[{"Effect":"Allow","Condition":{"Bool":"${var.c}"}}]}`,
		"principal array":          `{"Statement":[{"Effect":"Allow","Principal":["a"]}]}`,
		"not principal number":     `{"Statement":[{"Effect":"Allow","NotPrincipal":1}]}`,
		"action object":            `{"Statement":[{"Effect":"Allow","Action":{"a":1}}]}`,
		"resource nested list":     `{"Statement":[{"Effect":"Allow","Resource":[["a"]]}]}`,
		"effect object":            `{"Statement":[{"Effect":{}}]}`,
		"statement is a string":    `{"Statement":"${var.s}"}`,
		"statement has a string":   `{"Statement":["${var.s}"]}`,
		"version is a number":      `{"Version":2012,"Statement":[]}`,
		"principal identifier map": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":{"a":"b"}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := parsePolicyJSON(raw)
			require.False(t, ok)
		})
	}
}

func TestNestedDynamicBlocksShareOneBudget(t *testing.T) {
	list := func(n int) string { return "[" + strings.Repeat(`"a",`, n) + "]" }
	nested := func(outer, inner int) string {
		return `
dynamic "statement" {
  for_each = ` + list(outer) + `
  content {
    actions = ["s3:*"]
    dynamic "principals" {
      for_each = ` + list(inner) + `
      content {
        type        = "AWS"
        identifiers = [principals.value]
      }
    }
  }
}`
	}
	// 100 statements and 5 principals each generate 600 blocks.
	require.NotNil(t, renderedAttributes(t, nested(100, 5)))
	// Each cap alone holds, but their product does not.
	require.Nil(t, renderedAttributes(t, nested(256, 256)))
	// 2 statements with 256 principals each is 514 blocks, within the budget;
	// 4 statements is 1028, over it.
	require.NotNil(t, renderedAttributes(t, nested(2, 256)))
	require.Nil(t, renderedAttributes(t, nested(4, 256)))
}

func TestGoogleDynamicBlocksShareOneBudget(t *testing.T) {
	list := func(n int) string { return "[" + strings.Repeat(`"a",`, n) + "]" }
	src := `
dynamic "binding" {
  for_each = ` + list(256) + `
  content {
    role = "roles/viewer"
    dynamic "condition" {
      for_each = ` + list(256) + `
      content {
        title      = "t"
        expression = "true"
      }
    }
  }
}`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	rd := &partial.Renderer{Ctx: &hcl.EvalContext{Variables: map[string]cty.Value{}}, Source: partial.BytesSource([]byte(src))}
	require.Nil(t, googleIAMPolicyAttributes(file.Body, rd.Render))
}

func TestSourceDocumentWithPartiallyUnresolvedConditionStaysUnresolved(t *testing.T) {
	require.Nil(t, productionAttributes(t, `
source_policy_documents = [jsonencode({
  Statement = [{
    Effect = "Deny", Action = "s3:*", Resource = "*"
    Condition = {
      Bool         = { "aws:SecureTransport" = false }
      StringEquals = { "aws:SourceVpce" = var.vpce }
    }
  }]
})]
`))
}

func TestEmptyConditionValuesAreNotEmitted(t *testing.T) {
	got := renderedAttributes(t, `
statement {
  effect    = "Deny"
  actions   = ["s3:*"]
  resources = ["*"]
  condition {
    test     = "Bool"
    variable = "aws:SecureTransport"
    values   = []
  }
}`)
	require.NotContains(t, got["json"], `"Condition"`)
}

func TestEmptyPrincipalIdentifiersAreNotEmitted(t *testing.T) {
	got := renderedAttributes(t, `
statement {
  actions = ["s3:*"]
  principals {
    type        = "AWS"
    identifiers = []
  }
}`)
	require.NotContains(t, got["json"], `"Principals"`)
}

func TestParsePolicyJSONFailsClosedOnNullAndUnresolvedTemplates(t *testing.T) {
	for name, raw := range map[string]string{
		"statement null":           `{"Statement":[null,{"Effect":"Allow","Action":"s3:*"}]}`,
		"condition value null":     `{"Statement":[{"Effect":"Allow","Condition":{"StringEquals":{"a":null}}}]}`,
		"condition value empty":    `{"Statement":[{"Effect":"Allow","Condition":{"StringEquals":{"a":[]}}}]}`,
		"principal ids empty":      `{"Statement":[{"Effect":"Allow","Principal":{"AWS":[]}}]}`,
		"condition template":       `{"Statement":[{"Effect":"Deny","Condition":{"StringEquals":{"aws:SourceVpce":"${var.vpce}"}}}]}`,
		"mixed condition template": `{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":false},"StringEquals":{"aws:SourceVpce":"${var.vpce}"}}}]}`,
		"action template":          `{"Statement":[{"Effect":"Allow","Action":"${var.a}"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := parsePolicyJSON(raw)
			require.False(t, ok)
		})
	}
}

func TestOverrideJSONWinsOverOverridePolicyDocuments(t *testing.T) {
	got := renderedAttributes(t, `
override_policy_documents = ["{\"Statement\":[{\"Sid\":\"S\",\"Effect\":\"Allow\",\"Action\":\"s3:ListBucket\"}]}"]
override_json             = "{\"Statement\":[{\"Sid\":\"S\",\"Effect\":\"Deny\",\"Action\":\"s3:*\"}]}"
`)
	require.Contains(t, got["json"], `"Effect":"Deny"`)
	require.Contains(t, got["json"], `"Actions":["s3:*"]`)
	require.NotContains(t, got["json"], `"s3:ListBucket"`)
}

func TestParsePolicyJSONFailsClosedOnUnresolvedKeys(t *testing.T) {
	for name, raw := range map[string]string{
		"principal type": `{"Statement":[{"Effect":"Allow","Principal":{"${var.t}":["*"]}}]}`,
		"condition test": `{"Statement":[{"Effect":"Deny","Condition":{"${var.test}":{"aws:SecureTransport":false}}}]}`,
		"condition var":  `{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"${var.v}":["false"]}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := parsePolicyJSON(raw)
			require.False(t, ok)
		})
	}
}

func TestOmittedConditionTestIsNotEmitted(t *testing.T) {
	got := renderedAttributes(t, `
statement {
  effect  = "Deny"
  actions = ["s3:*"]
  condition {
    variable = "aws:SecureTransport"
    values   = ["false"]
  }
}`)
	require.NotContains(t, got["json"], `"Condition"`)
}

func TestSourceJSONThenSourcePolicyDocuments(t *testing.T) {
	got := renderedAttributes(t, `
source_json               = "{\"Statement\":[{\"Sid\":\"S\",\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\"}]}"
source_policy_documents   = ["{\"Statement\":[{\"Sid\":\"S\",\"Effect\":\"Deny\",\"Action\":\"s3:*\"}]}"]
`)
	require.Contains(t, got["json"], `"Effect":"Deny"`)
	require.Contains(t, got["json"], `"Actions":["s3:*"]`)
}
