/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestVariableOverrideDefaultParity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  cty.Value
	}{
		{
			name: "HCL base and JSON override omit default",
			files: map[string]string{
				"variables.tf":     `variable "value" { default = "base" }`,
				"override.tf.json": `{"variable":{"value":{"description":"updated"}}}`,
			},
			want: cty.StringVal("base"),
		},
		{
			name: "JSON base and multiple mixed overrides",
			files: map[string]string{
				"variables.tf.json": `{"variable":{"value":{"default":"base"}}}`,
				"a_override.tf":     `variable "value" { default = "first" }`,
				"override.tf.json":  `{"variable":{"value":{"default":"last"}}}`,
				"z_override.tf":     `variable "value" { description = "updated" }`,
			},
			want: cty.StringVal("last"),
		},
		{
			name: "explicit null replaces base default",
			files: map[string]string{
				"variables.tf.json": `{"variable":{"value":{"default":"base"}}}`,
				"override.tf":       `variable "value" { default = null }`,
			},
			want: cty.NullVal(cty.DynamicPseudoType),
		},
		{
			name: "ambiguous base keeps override standalone",
			files: map[string]string{
				"a.tf":        `variable "value" { default = "first" }`,
				"b.tf.json":   `{"variable":{"value":{"default":"second"}}}`,
				"override.tf": `variable "value" { description = "updated" }`,
			},
			want: cty.DynamicVal,
		},
		{
			name: "orphan override provides a default",
			files: map[string]string{
				"override.tf.json": `{"variable":{"value":{"default":"standalone"}}}`,
			},
			want: cty.StringVal("standalone"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const resource = `resource "example" "this" { value = var.value }`
			tc.files["main.tf"] = resource
			dir := writeModule(t, t.TempDir(), "module", tc.files)

			parser := terraform.NewDefault()
			_, vars, err := parser.Resolve(t.Context(), []byte(resource), filepath.Join(dir, "main.tf"), false, 0)
			require.NoError(t, err)
			require.True(t, tc.want.RawEquals(vars["var"].GetAttr("value")), "parser default: %#v", vars["var"])

			resources, _, _, err := New().EvaluateModule(t.Context(), dir, nil)
			require.NoError(t, err)
			require.Len(t, resources, 1)
			got := resources[0].Attributes["value"]
			require.True(t, tc.want.RawEquals(got), "evaluator default: %#v", got)
		})
	}
}

func TestExplicitRootVarsOnlyAffectEffectiveOverrides(t *testing.T) {
	root := t.TempDir()
	e := New()
	e.SetExplicitRootVars(map[string]cty.Value{"value": cty.StringVal("selected")})
	worker := e.Fork()
	for _, tc := range []struct {
		name, override, want string
	}{
		{"plain", "", "automatic"},
		{"orphan", `resource "example" "orphan" { other = true }`, "automatic"},
		{"matched", `resource "example" "this" { other = true }`, "selected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"main.tf":          `resource "example" "this" { value = var.value }`,
				"terraform.tfvars": `value = "automatic"`,
			}
			if tc.override != "" {
				files["override.tf"] = tc.override
			}
			dir := writeModule(t, root, tc.name, files)
			require.Equal(t, cty.StringVal(tc.want), worker.LoadRootVarsWithContext(t.Context(), dir)["value"])
		})
	}
}

func TestResourceOverrides(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `
resource "example" "this" {
  value      = "base"
  depends_on = [example.sibling]
  setting {
    name = "one"
    extra = true
  }
  setting { name = "two" }
  preserved { name = "stays" }
  lifecycle {
    prevent_destroy       = true
    create_before_destroy = false
  }
  connection { host = "original" }
  provisioner "local-exec" { command = "base-one" }
  provisioner "remote-exec" { inline = ["base-two"] }
}

resource "example" "sibling" {}
`,
		"a_override.tf": `
resource "example" "this" {
  value = "first"
  depends_on = []
  setting { name = "replacement" }
  lifecycle { create_before_destroy = true }
  connection { user = "override" }
  provisioner "local-exec" { command = "override" }
}
`,
		"z_override.tf": `
resource "example" "this" {
  value = "last"
}
`,
	})
	e := New()
	resources, _, _, err := e.EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 2)
	r := resources[0]
	require.Equal(t, "this", r.Name)
	require.Equal(t, filepath.Join(dir, "main.tf"), r.DefinedIn)
	doc := AttributesToDocument(&r)
	require.Equal(t, "last", doc["value"])
	require.Equal(t, map[string]interface{}{"name": "replacement"}, doc["setting"])
	require.Equal(t, map[string]interface{}{"name": "stays"}, doc["preserved"])
	require.Equal(t, map[string]interface{}{"prevent_destroy": true, "create_before_destroy": true}, doc["lifecycle"])
	require.Equal(t, map[string]interface{}{"user": "override"}, doc["connection"])
	require.Equal(t, map[string]interface{}{"local-exec": map[string]interface{}{"command": "override"}}, doc["provisioner"])
	require.Equal(t, filepath.Join(dir, "main.tf"), r.Body.Attributes["depends_on"].SrcRange.Filename)
	require.Equal(t, filepath.Join(dir, "z_override.tf"), r.Body.Attributes["value"].SrcRange.Filename)
	overrides := e.ResourceOverrides(t.Context(), dir)
	require.Len(t, overrides, 1)
	require.Len(t, overrides[0].Contributions, 2)
	require.Equal(t, filepath.Join(dir, "a_override.tf"), overrides[0].Contributions[0].TypeRange.Filename)
	require.Equal(t, filepath.Join(dir, "z_override.tf"), overrides[0].Contributions[1].TypeRange.Filename)
	require.Same(t, overrides[0].Declaration.Body, r.DeclarationBody)
}

func TestSkipRootResourcesKeepsEffectiveOverrides(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"variables.tf":    `variable "value" { default = "base" }`,
		"resource.tf":     `resource "example" "this" { value = var.value }`,
		"override.tf":     "// kics_terraform_vars: selected.tfvars\nresource \"example\" \"this\" { value = var.value }",
		"selected.tfvars": `value = "selected"`,
	})
	e := New()
	e.SetSkipRootResources(true)
	worker := e.Fork()
	resources, _, _, err := worker.EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, cty.StringVal("selected"), resources[0].Attributes["value"])
	require.NotNil(t, resources[0].DeclarationBody)
}

func TestResourceOverridesExpandInsideCalledModule(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `module "first" { source = "../child" }
module "second" { source = "../child" }`,
	})
	child := writeModule(t, root, "child", map[string]string{
		"main.tf": `
variable "values" {
  type    = set(string)
  default = ["old"]
}
resource "example" "counted" {
  count = 1
  value = count.index
}
resource "example" "keyed" {
  for_each = toset(["old"])
  value    = each.key
}
data "example" "source" {
  value = "base"
  other = "retained"
}
`,
		"override.tf": `
variable "values" { default = ["new", "new"] }
resource "example" "counted" { count = 2 }
resource "example" "keyed" { for_each = var.values }
data "example" "source" { value = "override" }
`,
	})
	e := New()
	resources, _, _, err := e.EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 8)
	require.Equal(t, 1, e.DataBlockEvaluations(), "the second call reuses the child evaluation")
	values := make(map[string]cty.Value)
	for _, r := range resources {
		require.Equal(t, filepath.Join(child, "main.tf"), r.DefinedIn)
		require.NotNil(t, r.DeclarationBody)
		require.Equal(t, r.DefinedIn, r.DeclarationBody.SrcRange.Filename)
		require.Len(t, r.CallChain, 1)
		require.Equal(t, r.ModuleAddress, "module."+r.CallChain[0].ModuleName)
		address, ok := r.TerraformAddress()
		require.True(t, ok)
		values[address] = r.Attributes["value"]
		if r.Data {
			require.Equal(t, cty.StringVal("retained"), r.Attributes["other"])
			require.Equal(t, filepath.Join(child, "override.tf"), r.Body.Attributes["value"].SrcRange.Filename)
		}
	}
	want := make(map[string]cty.Value)
	for _, call := range []string{"first", "second"} {
		prefix := "module." + call + "."
		want[prefix+"example.counted[0]"] = cty.NumberIntVal(0)
		want[prefix+"example.counted[1]"] = cty.NumberIntVal(1)
		want[prefix+`example.keyed["new"]`] = cty.StringVal("new")
		want[prefix+"data.example.source"] = cty.StringVal("override")
	}
	require.Equal(t, want, values)
}

func TestExplicitRootVarsRekeyCachedOverride(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "root", map[string]string{
		"main.tf": `// kics_terraform_vars: selected.tfvars
variable "value" { default = "base" }
resource "example" "this" { value = var.value }`,
		"override.tf":     `resource "example" "this" { other = true }`,
		"selected.tfvars": `value = "directive"`,
	})
	e := New().Fork()
	check := func(value string) {
		t.Helper()
		resources, _, _, err := e.EvaluateModule(t.Context(), dir, e.LoadRootVarsWithContext(t.Context(), dir))
		require.NoError(t, err)
		require.Len(t, resources, 1)
		require.Equal(t, cty.StringVal(value), resources[0].Attributes["value"])
	}
	check("directive")
	e.SetExplicitRootVars(map[string]cty.Value{})
	check("base")
	for _, value := range []string{"first", "second", "first"} {
		e.SetExplicitRootVars(map[string]cty.Value{"value": cty.StringVal(value)})
		check(value)
	}
	require.Equal(t, 3, e.EvalCacheSize())
	e.SetExplicitRootVars(nil)
	check("directive")
}

func TestResourceOverrideDirectiveResolvesLocalsAndDataPerFile(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `// kics_terraform_vars: base.tfvars
variable "n" { default = 1 }
variable "action" { default = "s3:ListBucket" }
locals { action = lower(var.action) }
data "aws_iam_policy_document" "example" {
  statement {
    actions   = [local.action]
    resources = ["*"]
  }
}
resource "example" "this" {
  count = var.n
  policy = data.aws_iam_policy_document.example.json
}
`,
		"override.tf": `// kics_terraform_vars: override.tfvars.json
resource "example" "this" {
  action = local.action
  dynamic "setting" {
    for_each = [local.action]
    content { name = setting.value }
  }
}
`,
		"base.tfvars":          "n = 2\naction = \"s3:GetObject\"\n",
		"override.tfvars.json": `{"n":3,"action":"s3:PutObject"}`,
	})
	e := New()
	resources, _, _, err := e.EvaluateModule(t.Context(), dir, e.LoadRootVarsWithContext(t.Context(), dir))
	require.NoError(t, err)
	require.Len(t, resources, 3)
	r := findResource(t, resources, "example", "this[1]")
	doc := AttributesToDocument(&r)
	require.Contains(t, doc["policy"], "s3:getobject")
	require.Equal(t, "s3:putobject", doc["action"])
	require.Equal(t, map[string]interface{}{"name": "s3:putobject"}, doc["setting"])

	overrides := e.ResourceOverrides(t.Context(), dir)
	require.Len(t, overrides, 1)
	projected := e.OverrideDocument(t.Context(), &overrides[0], e.StandaloneOverrideScope(t.Context(), dir))
	require.Contains(t, projected["policy"], "s3:getobject")
	require.Equal(t, doc["action"], projected["action"])
	require.Equal(t, doc["setting"], projected["setting"])
}

func TestResourceOverrideDirectiveUsesResolvedDependencies(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `// kics_terraform_vars: selected.tfvars
variable "suffix" { default = "default" }
module "child" { source = "../child" }
resource "example" "dependency" { value = "public" }
locals {
  acl  = module.child.acl
  name = "${example.dependency.value}-${var.suffix}"
  n    = length(module.child.keys) + (var.suffix == "selected" ? 1 : 0)
}
data "aws_iam_policy_document" "late" {
  statement {
    actions   = ["s3:${var.suffix}"]
    resources = [module.child.arn, example.dependency.value]
  }
}
resource "example" "counted" {
  count = local.n
  acl   = local.acl
  policy = data.aws_iam_policy_document.late.json
}
resource "example" "keyed" {
  for_each = toset([local.name])
  name     = each.key
}
`,
		"override.tf": `resource "example" "counted" { enabled = true }
resource "example" "keyed" { enabled = true }`,
		"selected.tfvars": `suffix = "selected"`,
	})
	writeModule(t, root, "child", map[string]string{
		"main.tf": `output "acl" { value = "public-read" }
output "keys" { value = ["one"] }
output "arn" { value = "arn:aws:s3:::example" }`,
	})
	e := New()
	ctx := t.Context()
	resources, _, _, err := e.EvaluateModule(ctx, dir, e.LoadRootVarsWithContext(ctx, dir))
	require.NoError(t, err)
	require.Len(t, resources, 5)
	counted := findResource(t, resources, "example", "counted[1]")
	require.Equal(t, cty.StringVal("public-read"), counted.Attributes["acl"])
	require.Contains(t, counted.Attributes["policy"].AsString(), `"s3:selected"`)
	require.Contains(t, counted.Attributes["policy"].AsString(), `"arn:aws:s3:::example"`)
	require.Contains(t, counted.Attributes["policy"].AsString(), `"public"`)
	keyed := findResource(t, resources, "example", `keyed["public-selected"]`)
	require.Equal(t, cty.StringVal("public-selected"), keyed.Attributes["name"])
	for _, override := range e.ResourceOverrides(ctx, dir) {
		if override.Declaration.Labels[1] == "counted" {
			projected := e.OverrideDocument(ctx, &override, counted.Scope)
			require.Equal(t, "public-read", projected["acl"])
			require.Equal(t, json.Number("2"), projected["count"])
		}
	}
}

func TestResourceOverrideDirectiveRetainsPartialPolicies(t *testing.T) {
	for _, source := range []struct{ name, contents string }{
		{"policy.tf", `data "aws_iam_policy_document" "example" {
  count = var.policies
  statement {
    actions   = [var.action]
    resources = [var.arn]
  }
}`},
		{"policy.tf.json", `{"data":{"aws_iam_policy_document":{"example":{"count":"${var.policies}","statement":[
  {"actions":["${var.action}"],"resources":["${var.arn}"]}
]}}}}`},
	} {
		t.Run(source.name, func(t *testing.T) {
			dir := writeModule(t, t.TempDir(), "root", map[string]string{
				"main.tf": `// kics_terraform_vars: base.tfvars
variable "action" { default = "s3:ListBucket" }
variable "arn" { type = string }
variable "policies" { default = 0 }
locals { policy = data.aws_iam_policy_document.example[0].json }
resource "example" "this" {
  base_policy = local.policy
}
`,
				"override.tf": `// kics_terraform_vars: override.tfvars
resource "example" "this" {
  policy = local.policy
  dynamic "setting" {
    for_each = ["loop"]
    iterator = var
    content {
      label  = var.value
      policy = data.aws_iam_policy_document.example[0].json
    }
  }
  dynamic "masked" {
    for_each = [{}]
    iterator = data
    content { policy = data.aws_iam_policy_document.example[0].json }
  }
}
`,
				source.name:       source.contents,
				"base.tfvars":     "action = \"s3:GetObject\"\npolicies = 1\n",
				"override.tfvars": "action = \"*\"\npolicies = 1\n",
			})
			e := New()
			ctx := t.Context()
			resources, _, _, err := e.EvaluateModule(ctx, dir, e.LoadRootVarsWithContext(ctx, dir))
			require.NoError(t, err)
			r := findResource(t, resources, "example", "this")
			overrides := e.ResourceOverrides(ctx, dir)
			require.Len(t, overrides, 1)
			for _, doc := range []map[string]interface{}{
				AttributesToDocument(&r),
				e.OverrideDocument(ctx, &overrides[0], r.Scope),
				e.OverrideDocument(ctx, &overrides[0], e.StandaloneOverrideScope(ctx, dir)),
			} {
				require.Contains(t, doc["base_policy"], `["s3:GetObject"]`)
				require.Contains(t, doc["policy"], `["*"]`)
				require.Contains(t, doc["policy"], "${var.arn}")
				require.Equal(t, map[string]interface{}{"label": "loop", "policy": doc["policy"]}, doc["setting"])
				require.Equal(t, map[string]interface{}{"policy": "${data.aws_iam_policy_document.example[0].json}"}, doc["masked"])
			}
		})
	}
}

func TestResourceOverrideDirectivePreservesDataFilesOwnSelection(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "root", map[string]string{
		"main.tf": `variable "action" { default = "*" }
variable "arn" { type = string }
resource "example" "this" {
  original = data.aws_iam_policy_document.example.json
}
`,
		"policy.tf": `// kics_terraform_vars: policy.tfvars
data "aws_iam_policy_document" "example" {
  statement {
    actions   = [var.action]
    resources = [var.arn]
  }
}
`,
		"override.tf": `// kics_terraform_vars: consumer.tfvars
data "aws_iam_policy_document" "example" { version = "2012-10-17" }
resource "example" "this" { effective = data.aws_iam_policy_document.example.json }
`,
		"policy.tfvars":   `action = "s3:GetObject"`,
		"consumer.tfvars": `action = "s3:ListBucket"`,
	})
	e := New()
	ctx := t.Context()
	resources, _, _, err := e.EvaluateModule(ctx, dir, e.LoadRootVarsWithContext(ctx, dir))
	require.NoError(t, err)
	r := findResource(t, resources, "example", "this")
	doc := AttributesToDocument(&r)
	require.Contains(t, doc["original"], `["s3:GetObject"]`)
	require.Contains(t, doc["original"], "${var.arn}")
	require.Equal(t, doc["original"], doc["effective"])
}

func TestResourceOverrideDirectiveRefreshesDataWhenDefaultLocalIsUnchanged(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{
		"main.tf": `// kics_terraform_vars: selected.tfvars
variable "use_child" { default = false }
module "child" { source = "../child" }
locals { arn = var.use_child ? module.child.arn : "arn:aws:s3:::default" }
data "aws_iam_policy_document" "policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = [local.arn]
  }
}
resource "example" "this" { policy = data.aws_iam_policy_document.policy.json }
`,
		"override.tf":     `data "aws_iam_policy_document" "policy" { version = "2012-10-17" }`,
		"selected.tfvars": "use_child = true\n",
	})
	writeModule(t, root, "child", map[string]string{
		"main.tf": `output "arn" { value = "arn:aws:s3:::selected" }`,
	})
	e := New()
	ctx := t.Context()
	resources, _, _, err := e.EvaluateModule(ctx, dir, e.LoadRootVarsWithContext(ctx, dir))
	require.NoError(t, err)
	r := findResource(t, resources, "example", "this")
	require.True(t, r.Attributes["policy"].IsKnown())
	require.Contains(t, r.Attributes["policy"].AsString(), "arn:aws:s3:::selected")
}

func TestResourceOverrideJSON(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `
resource "example" "this" {
  value = "base"
  lifecycle {
    prevent_destroy       = true
    create_before_destroy = false
  }
}
`,
		"override.tf.json": `{"resource":{"example":{"this":{
  "value":"json","lifecycle":{"create_before_destroy":true}
}}}}`,
	})
	resources, _, _, err := New().EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	r := resources[0]
	require.Equal(t, filepath.Join(dir, "main.tf"), r.DefinedIn)
	require.Equal(t, filepath.Join(dir, "override.tf.json"), r.Body.Attributes["value"].SrcRange.Filename)
	require.Equal(t, map[string]interface{}{
		"value": "json",
		"lifecycle": map[string]interface{}{
			"create_before_destroy": true,
			"prevent_destroy":       true,
		},
	}, AttributesToDocument(&r))
}

func TestResourceOverrideDynamicBlocks(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `
resource "example" "this" {
  option { name = "original" }
  dynamic "option" {
    for_each = ["also-original"]
    content { name = option.value }
  }
  dynamic "retained" {
    for_each = ["retained"]
    content { name = retained.value }
  }
}
`,
		"override.tf.json": `{"resource":{"example":{"this":{
  "dynamic":{"option":{"for_each":["effective"],"content":{"name":"${option.value}"}}}
}}}}`,
	})
	resources, _, _, err := New().EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	doc := AttributesToDocument(&resources[0])
	require.Equal(t, map[string]interface{}{"name": "effective"}, doc["option"])
	require.Equal(t, map[string]interface{}{"name": "retained"}, doc["retained"])
}

func TestOrphanOverridesStayStandaloneInTheirModule(t *testing.T) {
	root := writeModule(t, t.TempDir(), "module", map[string]string{
		"main.tf": `resource "example" "this" { value = "declared" }`,
	})
	env := writeModule(t, root, "environments/dev", map[string]string{
		"settings_override.tf": `
variable "replicas" { default = 2 }
resource "example" "this" {
  count = var.replicas
  value = "override"
}
data "example" "source" { value = "override" }
`,
	})
	e := New()
	resources, _, _, err := e.EvaluateModule(t.Context(), env, nil)
	require.NoError(t, err)
	require.Len(t, resources, 3)
	require.Empty(t, e.ResourceOverrides(t.Context(), env))
	for i, want := range []string{"example.this[0]", "example.this[1]", "data.example.source"} {
		address, complete := resources[i].TerraformAddress()
		require.True(t, complete)
		require.Equal(t, want, address)
		require.Equal(t, filepath.Join(env, "settings_override.tf"), resources[i].DefinedIn)
		require.Equal(t, cty.StringVal("override"), resources[i].Attributes["value"])
	}
	resources, _, _, err = e.EvaluateModule(t.Context(), root, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, cty.StringVal("declared"), resources[0].Attributes["value"])
}

func TestOverrideWithAmbiguousBaseStaysStandalone(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"a.tf":        `resource "example" "this" { value = "first" }`,
		"b.tf":        `resource "example" "this" { value = "second" }`,
		"override.tf": `resource "example" "this" { value = "standalone" }`,
	})
	e := New()
	resources, _, _, err := e.EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, 3)
	require.Empty(t, e.ResourceOverrides(t.Context(), dir))
	for i, want := range []string{"first", "second", "standalone"} {
		require.Equal(t, cty.StringVal(want), resources[i].Attributes["value"])
	}
}
