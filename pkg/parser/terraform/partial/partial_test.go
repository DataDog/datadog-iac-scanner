/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package partial

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

func render(t *testing.T, src string, vars map[string]cty.Value) (string, bool) {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	r := &Renderer{
		Ctx:    &hcl.EvalContext{Variables: vars, Functions: functions.TerraformFuncs},
		Source: BytesSource([]byte(src)),
	}
	v, ok := r.Render(expr)
	if !ok {
		return "", false
	}
	out, err := ctyjson.Marshal(v, v.Type())
	require.NoError(t, err)
	return string(out), true
}

func TestRender(t *testing.T) {
	vars := map[string]cty.Value{
		"var": cty.ObjectVal(map[string]cty.Value{
			"names":   cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}),
			"enabled": cty.True,
			"arn_tpl": cty.StringVal("arn:${a}"),
			"env_tpl": cty.StringVal(`%{ if env == "prod" }P%{ else }D%{ endif }`),
		}),
	}
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "resolved value",
			src:  `upper("x")`,
			want: `"X"`,
		},
		{
			name: "reference keeps its spelling",
			src:  `aws_s3_bucket.b.list.0`,
			want: `"${aws_s3_bucket.b.list.0}"`,
		},
		{
			name: "placing function builds around unresolved parts",
			src:  `jsonencode({Resource = aws_sqs_queue.q.arn, Action = ["sqs:*"]})`,
			want: `"{\"Action\":[\"sqs:*\"],\"Resource\":\"${aws_sqs_queue.q.arn}\"}"`,
		},
		{
			name: "content dependent function is rendered whole inside a placing one",
			src:  `jsonencode({Resource = lower(aws_sqs_queue.q.arn)})`,
			want: `"{\"Resource\":\"${lower(aws_sqs_queue.q.arn)}\"}"`,
		},
		{
			name: "content dependent function alone is its text",
			src:  `lower(aws_sqs_queue.q.arn)`,
			want: `"${lower(aws_sqs_queue.q.arn)}"`,
		},
		{
			name: "unresolved condition is rendered whole",
			src:  `[aws_s3_bucket.b.id == "x" ? "a" : "b", "c"]`,
			want: `["${aws_s3_bucket.b.id == \"x\" ? \"a\" : \"b\"}","c"]`,
		},
		{
			name: "resolved condition places its branch",
			src:  `var.enabled ? aws_s3_bucket.b.arn : "none"`,
			want: `"${aws_s3_bucket.b.arn}"`,
		},
		{
			name: "for over a resolved collection",
			src:  `[for n in var.names : "${aws_s3_bucket.b.arn}/${n}"]`,
			want: `["${aws_s3_bucket.b.arn}/a","${aws_s3_bucket.b.arn}/b"]`,
		},
		{
			name: "for over an unresolved collection is its text",
			src:  `[for b in aws_s3_bucket.all : b.arn]`,
			want: `"${[for b in aws_s3_bucket.all : b.arn]}"`,
		},
		{
			name: "template",
			src:  `"arn:aws:s3:::${aws_s3_bucket.b.id}/${upper("x")}"`,
			want: `"arn:aws:s3:::${aws_s3_bucket.b.id}/X"`,
		},
		{
			name: "template for directive inside a placing function",
			src:  `jsonencode({x = "%{ for n in aws_x.y.list }${n}%{ endfor }"})`,
			want: `"{\"x\":\"%{ for n in aws_x.y.list }${n}%{ endfor }\"}"`,
		},
		{
			name: "format with plain verbs places",
			src:  `format("arn:aws:s3:::%s/*", aws_s3_bucket.b.id)`,
			want: `"arn:aws:s3:::${aws_s3_bucket.b.id}/*"`,
		},
		{
			name: "format with a precision is its text",
			src:  `format("%.8s", aws_x.y.name)`,
			want: `"${format(\"%.8s\", aws_x.y.name)}"`,
		},
		{
			name: "templatestring placing bare variables",
			src:  `templatestring(var.arn_tpl, {a = aws_x.y.id})`,
			want: `"arn:${aws_x.y.id}"`,
		},
		{
			name: "templatestring deciding on its variables is its text",
			src:  `templatestring(var.env_tpl, {env = aws_x.y.env})`,
			want: `"${templatestring(var.env_tpl, {env = aws_x.y.env})}"`,
		},
		{
			name: "type converting function is its text",
			src:  `tolist([aws_x.y.n, 30])`,
			want: `"${tolist([aws_x.y.n, 30])}"`,
		},
		{
			name: "for body reading a reference and its attribute",
			src:  `[for s in ["x"] : {whole = aws_x.y, arn = aws_x.y.arn}]`,
			want: `"${[for s in [\"x\"] : {whole = aws_x.y, arn = aws_x.y.arn}]}"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := render(t, tt.src, vars)
			require.True(t, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestRenderPartlyKnownReference(t *testing.T) {
	vars := map[string]cty.Value{
		"module": cty.ObjectVal(map[string]cty.Value{
			"m": cty.ObjectVal(map[string]cty.Value{
				"name": cty.StringVal("n"),
				"arn":  cty.UnknownVal(cty.String),
			}),
		}),
	}
	got, ok := render(t, `module.m`, vars)
	require.True(t, ok)
	require.Equal(t, `{"arn":"${module.m.arn}","name":"n"}`, got)
}

func TestRenderWithoutContext(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte(`[aws_s3_bucket.b.arn, "x"]`), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	v, ok := (&Renderer{}).Render(expr)
	require.True(t, ok)
	require.Equal(t, cty.TupleVal([]cty.Value{cty.StringVal("${aws_s3_bucket.b.arn}"), cty.StringVal("x")}), v)
}

func TestWithUnknownRefs(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte(`{a = aws_s3_bucket.b.arn, b = var.x}`), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
		"var": cty.ObjectVal(map[string]cty.Value{"x": cty.StringVal("y")}),
	}}
	v := WithUnknownRefs(expr, ctx)
	require.False(t, v.GetAttr("a").IsKnown())
	require.Equal(t, cty.StringVal("y"), v.GetAttr("b"))
}
