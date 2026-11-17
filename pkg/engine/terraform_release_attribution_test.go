/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/zclconf/go-cty/cty"
)

// Same resource and call, attribution computed on a live scope and on the
// same scope after ReleaseEvalState (what model.loadRoot does).
func TestAttributionSurvivesReleaseEvalState(t *testing.T) {
	cases := []struct {
		name, expr, argument, locals string
		vars                         map[string]cty.Value
	}{
		{"coalesce null -> module local", `coalesce(var.acl, local.default_acl)`, `acl = null`,
			"locals {\n  default_acl = \"public-read\"\n}", map[string]cty.Value{"acl": cty.NullVal(cty.String)}},
		{"conditional picks module default", `var.policy == "" ? data.aws_iam_policy_document.default.json : var.policy`, `policy = ""`,
			"", map[string]cty.Value{"policy": cty.StringVal("")}},
		{"toggle picks module literal", `var.public ? "public-read" : "private"`, `public = true`,
			"", map[string]cty.Value{"public": cty.True}},
		{"lookup default", `lookup(var.acls, "logs", "public-read")`, `acls = {}`,
			"", map[string]cty.Value{"acls": cty.MapValEmpty(cty.String)}},
		{"coalesce keeps caller", `coalesce(var.acl, local.default_acl)`, `acl = "public-read"`,
			"locals {\n  default_acl = \"private\"\n}", map[string]cty.Value{"acl": cty.StringVal("public-read")}},
		{"conditional picks caller", `var.policy == "" ? data.aws_iam_policy_document.default.json : var.policy`, `policy = file("policy.json")`,
			"", map[string]cty.Value{"policy": cty.StringVal(`{"Statement":[]}`)}},
		{"try keeps caller", `try(var.settings.acl, "private")`, `settings = { acl = "public-read" }`,
			"", map[string]cty.Value{"settings": cty.ObjectVal(map[string]cty.Value{"acl": cty.StringVal("public-read")})}},
		{"lookup reads caller", `lookup(var.acls, "logs", "private")`, `acls = { logs = "public-read" }`,
			"", map[string]cty.Value{"acls": cty.MapVal(map[string]cty.Value{"logs": cty.StringVal("public-read")})}},
		{"local.acls[var.env]", `local.acls[var.env]`, `env = "prod"`,
			"locals {\n  acls = { prod = \"public-read\" }\n}", map[string]cty.Value{"env": cty.StringVal("prod")}},
		{"direct var", `var.acl`, `acl = "public-read"`, "", map[string]cty.Value{"acl": cty.StringVal("public-read")}},
	}
	for _, tt := range cases {
		run := func(release bool) model.ArgumentControl {
			scope := evaluatedScope(t, tt.vars, tt.locals)
			if release {
				scope.ReleaseEvalState()
			}
			r := &tfeval.ResolvedResource{
				Body:  parseBlockBody(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = "+tt.expr+"\n}"),
				Scope: scope,
				CallChain: []tfeval.CallSite{{
					Body: parseBlockBody(t, "module \"bucket\" {\n  source = \"../bucket\"\n  "+tt.argument+"\n}"),
				}},
			}
			args := newModuleAttributionCache().resourceArguments(r, "stack/main.tf")
			c, _ := controlAt(args, 2)
			return c
		}
		live, released := run(false), run(true)
		if live != released {
			t.Errorf("%s: attribution changed after ReleaseEvalState: %v -> %v", tt.name, live, released)
		}
	}
}
