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

func TestEvaluate(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte(`{a = aws_s3_bucket.b.arn, b = var.x}`), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
		"var": cty.ObjectVal(map[string]cty.Value{"x": cty.StringVal("y")}),
	}}
	v, diags := Evaluate(expr, ctx)
	require.False(t, diags.HasErrors())
	require.False(t, v.GetAttr("a").IsKnown())
	require.Equal(t, cty.StringVal("y"), v.GetAttr("b"))
}

// References under one root are gathered into one object, keeping the known
// attributes of the root and the ones other references set.
func TestEvaluateManyAttributesOfOneRoot(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression(
		[]byte(`[module.a.id, module.b.id, module.b.arn, module.c["k"].id, local.x, local.y.z]`), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
		"module": cty.ObjectVal(map[string]cty.Value{
			"a": cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("a-id")}),
		}),
		"local": cty.ObjectVal(map[string]cty.Value{"x": cty.StringVal("x")}),
	}}
	v, diags := Evaluate(expr, ctx)
	require.False(t, diags.HasErrors())
	require.Equal(t, 6, v.LengthInt())
	require.Equal(t, cty.StringVal("a-id"), v.Index(cty.NumberIntVal(0)))
	for i := 1; i <= 3; i++ {
		require.False(t, v.Index(cty.NumberIntVal(int64(i))).IsKnown(), "element %d", i)
	}
	require.Equal(t, cty.StringVal("x"), v.Index(cty.NumberIntVal(4)))
	require.False(t, v.Index(cty.NumberIntVal(5)).IsKnown())
}

// Reference recovery only supplies placed values; it must not determine a
// collection's membership, object keys, or downstream content decisions.
func TestRenderForReferences(t *testing.T) {
	unknown := cty.UnknownVal(cty.String)
	ctx := &hcl.EvalContext{Functions: functions.TerraformFuncs, Variables: map[string]cty.Value{
		"var": cty.ObjectVal(map[string]cty.Value{"x": unknown, "y": unknown, "key": unknown, "flag": cty.UnknownVal(cty.Bool)}),
		"data": cty.ObjectVal(map[string]cty.Value{"policy": cty.ObjectVal(map[string]cty.Value{
			"p": cty.ObjectVal(map[string]cty.Value{"a": cty.ObjectVal(map[string]cty.Value{"json": unknown}), "b": cty.ObjectVal(map[string]cty.Value{"json": unknown})}),
		})}),
	}}
	for _, tc := range []struct{ name, src, want string }{
		{"direct elements", `[for p in data.policy.p : p.json]`, `["policy-a","policy-b"]`},
		{"shared key and value name", `[for p, p in {a = "b"} : data.policy.p[p].json]`, `["policy-b"]`},
		{"shadowed namespace", `[for data in data.policy.p : data.json]`, `["policy-a","policy-b"]`},
		{"list", `[for k in ["a", "b"] : data.policy.p[k].json]`, `["policy-a","policy-b"]`},
		{"filtered direct elements", `[for k, p in data.policy.p : p.json if k == "a"]`, `["policy-a"]`},
		{"filter", `[for k in ["a", "b"] : data.policy.p[k].json if k != "b"]`, `["policy-a"]`},
		{"object", `{for k in ["a", "b"] : k => data.policy.p[k].json}`, `{"a":"policy-a","b":"policy-b"}`},
		{"grouping", `{for k in ["a", "b"] : "all" => data.policy.p[k].json...}`, `{"all":["policy-a","policy-b"]}`},
		{"empty", `[for k in [] : data.policy.p[k].json]`, `[]`},
		{"unknown filter", `[for k in ["a"] : data.policy.p[k].json if var.flag]`, ""},
		{"unknown key", `{for k in ["a"] : var.key => data.policy.p[k].json}`, ""},
		{"unknown set membership", `[for k in toset([var.x, var.y]) : data.policy.p.a.json]`, ""},
		{"duplicate keys", `{for k in ["a", "b"] : "all" => data.policy.p[k].json}`, ""},
		{"content decision", `[for k in ["a"] : strcontains(data.policy.p[k].json, "policy")]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expr, diags := hclsyntax.ParseExpression([]byte(tc.src), "main.tf", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			rd := &Renderer{Ctx: ctx, Source: BytesSource([]byte(tc.src)), Reference: func(traversal hcl.Traversal, _ *hcl.EvalContext) (cty.Value, bool) {
				if len(traversal) == 5 && traversal.RootName() == "data" {
					typ, typeOK := traversal[1].(hcl.TraverseAttr)
					name, nameOK := traversal[2].(hcl.TraverseAttr)
					attr, attrOK := traversal[4].(hcl.TraverseAttr)
					if !typeOK || !nameOK || !attrOK || typ.Name != "policy" || name.Name != "p" || attr.Name != "json" {
						return cty.NilVal, false
					}
					if index, ok := traversal[3].(hcl.TraverseIndex); ok {
						return cty.StringVal("policy-" + index.Key.AsString()), true
					}
				}
				return cty.NilVal, false
			}}
			value, ok := rd.Render(expr)
			if tc.name == "content decision" {
				require.False(t, ok)
				return
			}
			require.True(t, ok)
			if tc.want == "" {
				require.Equal(t, "${"+tc.src+"}", value.AsString())
			} else {
				got, err := ctyjson.Marshal(value, value.Type())
				require.NoError(t, err)
				require.JSONEq(t, tc.want, string(got))
			}
		})
	}
}

// Lexical bindings govern both evaluation and presentation reference recovery.
func TestRendererBindings(t *testing.T) {
	unknown := cty.UnknownVal(cty.String)
	parent := &Renderer{Ctx: &hcl.EvalContext{Variables: map[string]cty.Value{
		"local": cty.ObjectVal(map[string]cty.Value{"value": unknown}),
		"data":  cty.ObjectVal(map[string]cty.Value{"value": unknown}),
	}}, Reference: func(hcl.Traversal, *hcl.EvalContext) (cty.Value, bool) {
		return cty.StringVal("module-value"), true
	}}
	for _, tc := range []struct {
		name  string
		src   string
		value cty.Value
		want  string
	}{
		{"known binding", "local.value", cty.StringVal("bound-value"), "bound-value"},
		{"unknown binding", "local.value", unknown, "${local.value}"},
		{"unbound root", "data.value", unknown, "module-value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expr, diags := hclsyntax.ParseExpression([]byte(tc.src), "main.tf", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			vars := map[string]cty.Value{"local": cty.ObjectVal(map[string]cty.Value{"value": tc.value})}
			for _, rd := range []*Renderer{parent, parent.WithBindings(map[string]cty.Value{"local": cty.StringVal("outer")})} {
				got, ok := rd.WithBindings(vars).Render(expr)
				require.True(t, ok)
				require.Equal(t, tc.want, got.AsString())
				got, ok = rd.Render(Bind(expr, vars))
				require.True(t, ok)
				require.Equal(t, tc.want, got.AsString())
			}
		})
	}
	require.Nil(t, (&Renderer{}).WithBindings(map[string]cty.Value{"local": unknown}).Reference)
}

func TestEvaluateExpressionOutcomes(t *testing.T) {
	for _, test := range []struct {
		name, source  string
		known, failed bool
	}{
		{"known scalar", `"public"`, true, false},
		{"unknown input", `var.value`, false, false},
		{"unresolved reference", `aws_s3_bucket.example.arn`, false, false},
		{"invalid function argument", `tonumber("invalid")`, false, true},
		{"invalid index", `[1][2]`, false, true},
		{"invalid length", `length(null)`, false, true},
		{"invalid function beside unresolved reference", `[aws_s3_bucket.example.arn,tonumber("invalid")]`, false, true},
		{"caught failure", `try(tonumber("invalid"),"public")`, true, false},
		{"tested failure", `can(tonumber("invalid"))`, true, false},
		{"inactive failing branch", `false ? tonumber("invalid") : 1`, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			expr, diagnostics := hclsyntax.ParseExpression([]byte(test.source), "expression.tf", hcl.InitialPos)
			require.False(t, diagnostics.HasErrors())
			ctx := &hcl.EvalContext{Functions: functions.TerraformFuncs, Variables: map[string]cty.Value{"var": cty.ObjectVal(map[string]cty.Value{"value": cty.UnknownVal(cty.String)})}}
			value, diagnostics := Evaluate(expr, ctx)
			require.Equal(t, test.known, value.IsKnown())
			require.Equal(t, test.failed, diagnostics.HasErrors())
			for _, diagnostic := range diagnostics {
				require.NotNil(t, diagnostic.Subject)
				require.Equal(t, "expression.tf", diagnostic.Subject.Filename)
			}
		})
	}
}
