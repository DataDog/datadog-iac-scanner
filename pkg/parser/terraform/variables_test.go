/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// filepath: filepath.FromSlash("../../test/fixtures/test_helm"),

type mergeMapsTest struct {
	name string
	args struct {
		baseMap converter.VariableMap
		newMap  converter.VariableMap
	}
	want converter.VariableMap
}

type inputVarTest struct {
	name     string
	filename string
	want     converter.VariableMap
	wantErr  bool
}

func setInputVariablesDefaultValues(filename string) (converter.VariableMap, error) {
	parsedFile, err := readAndParseFile(vfs.DiskFS{}, filename)
	if err != nil || parsedFile == nil {
		return nil, err
	}
	content, _, _ := parsedFile.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "variable",
				LabelNames: []string{"name"},
			},
		},
	})

	defaultValuesMap := make(converter.VariableMap)
	for _, block := range content.Blocks {
		if len(block.Labels) == 0 || block.Labels[0] == "" {
			continue
		}
		attr, _ := block.Body.JustAttributes()
		if len(attr) == 0 {
			continue
		}
		if defaultValue, exists := attr["default"]; exists {
			defaultVar, _ := defaultValue.Expr.Value(nil)
			defaultValuesMap[block.Labels[0]] = defaultVar
		}
	}
	return defaultValuesMap, nil
}

func TestMergeMaps(t *testing.T) {
	tests := []mergeMapsTest{
		{
			name: "Should merge the second map on the first map",
			args: struct {
				baseMap converter.VariableMap
				newMap  converter.VariableMap
			}{
				baseMap: converter.VariableMap{
					"test": cty.StringVal("test"),
				},
				newMap: converter.VariableMap{
					"new": cty.StringVal("new"),
				},
			},
			want: converter.VariableMap{
				"test": cty.StringVal("test"),
				"new":  cty.StringVal("new"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeMaps(tt.args.baseMap, tt.args.newMap)
			require.Equal(t, tt.want, tt.args.baseMap)
		})
	}
}

func TestSetInputVariablesDefaultValues(t *testing.T) {
	tests := []inputVarTest{
		{
			name:     "Should get default variable values from tf file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "test.tf"),
			want: converter.VariableMap{
				"local_default_var": cty.StringVal("local_default"),
			},
			wantErr: false,
		},
		{
			name:     "Should get default variable values from tf file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "variables.tf"),
			want: converter.VariableMap{
				"default_var_file": cty.StringVal("default_var_file"),
			},
			wantErr: false,
		},
		{
			name:     "Should get empty map from variable blockless file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "test_without_variables_block.tf"),
			want:     converter.VariableMap{},
			wantErr:  false,
		},
		{
			name:     "Should get an error when trying to set input variables from inexistent file",
			filename: filepath.FromSlash("not_found.tf"),
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultValues, err := setInputVariablesDefaultValues(tt.filename)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, defaultValues)
		})
	}
}

func TestGetInputVariablesFromFile(t *testing.T) {
	tests := []inputVarTest{
		{
			name:     "Should get variables from file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "variable_set.auto.tfvars"),
			want: converter.VariableMap{
				"test1": cty.BoolVal(false),
				"test2": cty.TupleVal([]cty.Value{cty.BoolVal(false), cty.BoolVal(true)}),
				"map1": cty.ObjectVal(map[string]cty.Value{
					"map1key1": cty.StringVal("map2Key1"),
				}),
				"map2": cty.ObjectVal(map[string]cty.Value{
					"map2Key1": cty.StringVal("nestedMap"),
				}),
			},
			wantErr: false,
		},
		{
			name:     "Should get an error when trying to set input variables from inexistent file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "invalid.tfvars"),
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "Should get an error when trying to set input variables from inexistent file 2",
			filename: filepath.FromSlash("not_found.tf"),
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputVars, err := getInputVariablesFromFile(t.Context(), vfs.DiskFS{}, tt.filename)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, inputVars)
		})
	}
}

func TestExtractInputVariablesUnsetRequiredIsUnknown(t *testing.T) {
	src := []byte(`variable "required" { type = string }`)
	file, diags := hclsyntax.ParseConfig(src, "variables.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags)
	got := extractInputVariables(file.Body.(*hclsyntax.Body), "variables.tf")
	require.True(t, got["required"].RawEquals(cty.UnknownVal(cty.DynamicPseudoType)))
}

func TestGetInputVariables(t *testing.T) {
	tests := []inputVarTest{
		{
			name:     "Should load input variables",
			filename: filepath.FromSlash("../../../test/fixtures/test_terraform_variables"),
			want: converter.VariableMap{
				"var": cty.ObjectVal(map[string]cty.Value{
					"test1": cty.BoolVal(false),
					"test2": cty.TupleVal([]cty.Value{cty.BoolVal(false), cty.BoolVal(true)}),
					"map1": cty.ObjectVal(map[string]cty.Value{
						"map1key1": cty.StringVal("map2Key1"),
					}),
					"map2": cty.ObjectVal(map[string]cty.Value{
						"map2Key1": cty.StringVal("nestedMap"),
					}),
					"map3": cty.ObjectVal(map[string]cty.Value{
						"map3Key1": cty.StringVal("givenByVar"),
					}),
					"test_terraform":    cty.StringVal("terraform.tfvars"),
					"default_var_file":  cty.StringVal("default_var_file"),
					"local_default_var": cty.StringVal("local_default"),
					"invalid_attr":      cty.UnknownVal(cty.DynamicPseudoType),
				}),
				"local": cty.EmptyObjectVal,
			},
			wantErr: false,
		},
		{
			name:     "Should load input variables",
			filename: filepath.FromSlash("../../../test/fixtures/test_terraform_variables/test_variables_comment_path.tf"),
			want: converter.VariableMap{
				"var": cty.ObjectVal(map[string]cty.Value{
					"map3": cty.ObjectVal(map[string]cty.Value{
						"map3Key1": cty.StringVal("givenByVar"),
					}),
				}),
				"local": cty.EmptyObjectVal,
			},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileContent, _ := os.ReadFile(tt.filename)
			result := getInputVariables(ctx, vfs.DiskFS{}, tt.filename, string(fileContent), "../../../test/fixtures/test_terraform_variables/varsToUse/varsToUse.tf", nil, "")
			require.Equal(t, tt.want, result)
		})
	}
}

func TestGetInputVariables_TofuShadowsTf(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tf"), []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tofu"), []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.tf"), []byte(`
variable "other" { default = "kept" }
`), 0o600))

	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", nil, "")
	vars := got["var"].AsValueMap()
	require.Equal(t, "from-tofu", vars["bucket"].AsString())
	require.Equal(t, "kept", vars["other"].AsString())
}

func TestGetInputVariables_ExcludedTofuTwinKept(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "variables.tf")
	tofu := filepath.Join(dir, "variables.tofu")
	require.NoError(t, os.WriteFile(tf, []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(tofu, []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))

	allow := map[string]struct{}{filepath.ToSlash(tf): {}}
	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, "")
	vars := got["var"].AsValueMap()
	require.Equal(t, "from-tf", vars["bucket"].AsString())
}

func TestGetInputVariables_InventoriedTwinKeepsOwnVars(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "variables.tf")
	tofu := filepath.Join(dir, "variables.tofu")
	require.NoError(t, os.WriteFile(tf, []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(tofu, []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))

	allow := map[string]struct{}{
		filepath.ToSlash(tf):   {},
		filepath.ToSlash(tofu): {},
	}
	fromTF := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, tf)
	require.Equal(t, "from-tf", fromTF["var"].AsValueMap()["bucket"].AsString())
	fromTofu := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, tofu)
	require.Equal(t, "from-tofu", fromTofu["var"].AsValueMap()["bucket"].AsString())
}

func TestGetInputVariables_AllowMissFallsBackToDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tf"), []byte(`
variable "bucket" { default = "from-tf" }
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tofu"), []byte(`
variable "bucket" { default = "from-tofu" }
`), 0o600))

	allow := map[string]struct{}{filepath.ToSlash(filepath.Join(t.TempDir(), "other.tf")): {}}
	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", allow, "")
	vars := got["var"].AsValueMap()
	require.Equal(t, "from-tofu", vars["bucket"].AsString())
}

func writeTerraformDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	return dir
}

func rootLocals(t *testing.T, files map[string]string) map[string]cty.Value {
	t.Helper()
	dir := writeTerraformDir(t, files)
	return getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", nil, "")["local"].AsValueMap()
}

// requireLocal fails, instead of panicking, when name is not resolved.
func requireLocal(t *testing.T, locals map[string]cty.Value, name string, want cty.Value) {
	t.Helper()
	require.Contains(t, locals, name)
	require.True(t, want.RawEquals(locals[name]), "local.%s = %#v, want %#v", name, locals[name], want)
}

// requireUnresolvedLocal checks that name is not resolved: missing from the
// locals, as an unknown value would let go-cty fold it into known results.
func requireUnresolvedLocal(t *testing.T, locals map[string]cty.Value, name string) {
	t.Helper()
	require.NotContains(t, locals, name, "local.%s = %#v, want unresolved", name, locals[name])
}

func TestGetInputVariables_LocalsReadVariableDefaults(t *testing.T) {
	locals := rootLocals(t, map[string]string{"main.tf": `
variable "env" {
  default = "prod"
}
locals {
  is_prod   = var.env == "prod"
  retention = local.is_prod ? 90 : 30
  tags      = merge({ team = "core" }, { env = var.env })
}
`})
	requireLocal(t, locals, "is_prod", cty.True)
	requireLocal(t, locals, "retention", cty.NumberIntVal(90))
	requireLocal(t, locals, "tags", cty.ObjectVal(map[string]cty.Value{
		"team": cty.StringVal("core"),
		"env":  cty.StringVal("prod"),
	}))
}

func TestGetInputVariables_LocalsReadVariableDefinitionsFiles(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf": `
variable "env" {
  default = "prod"
}
variable "enc" {
  default = true
}
locals {
  is_prod = var.env == "prod"
  enc     = var.enc
}
`,
		"terraform.tfvars": `env = "dev"`,
		"x.auto.tfvars":    `enc = false`,
	})
	requireLocal(t, locals, "is_prod", cty.False)
	requireLocal(t, locals, "enc", cty.False)
}

func TestGetInputVariables_LocalsReadExplicitVariablesFile(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"main.tf": `
variable "env" {
  default = "prod"
}
locals {
  name = "logs-${var.env}"
}
`,
		"terraform.tfvars": `env = "dev"`,
		"ci.tfvars":        `env = "ci"`,
	})
	vars := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", filepath.Join(dir, "ci.tfvars"), nil, "")
	requireLocal(t, vars["local"].AsValueMap(), "name", cty.StringVal("logs-ci"))
}

func TestGetInputVariables_LocalsReadLocalsOfOtherFiles(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"locals.tf": `
locals {
  base_tags = { team = "core" }
  retention = 90
}
`,
		"main.tf": `
locals {
  tags      = merge(local.base_tags, { app = "x" })
  keep_days = local.retention
}
`,
	})
	requireLocal(t, locals, "keep_days", cty.NumberIntVal(90))
	requireLocal(t, locals, "tags", cty.ObjectVal(map[string]cty.Value{
		"team": cty.StringVal("core"),
		"app":  cty.StringVal("x"),
	}))
}

func TestGetInputVariables_LocalsReadingVariablesWithoutValueStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{"main.tf": `
variable "nodef" {
  type = string
}
variable "acl" {
  default = "private"
}
locals {
  is_prod   = var.nodef == "prod"
  retention = local.is_prod ? 90 : 30
  tried     = try(var.nodef, "fallback")
  coalesced = coalesce(var.nodef, "x")
  checked   = can(var.nodef) ? "yes" : "no"
  null_cmp  = var.nodef == null ? "null" : "set"
  with_def  = try(var.acl, "public-read")
}
`})
	for _, name := range []string{"is_prod", "retention", "tried", "coalesced", "checked", "null_cmp"} {
		requireUnresolvedLocal(t, locals, name)
	}
	requireLocal(t, locals, "with_def", cty.StringVal("private"))
}

func TestGetInputVariables_PartiallyKnownLocalsStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{"main.tf": `
variable "nodef" {
  type = string
}
variable "env" {
  default = "prod"
}
locals {
  tags = { env = var.env, owner = var.nodef }
  list = [var.env, var.nodef]
  name = "${var.env}-${var.nodef}"
}
`})
	for _, name := range []string{"tags", "list", "name"} {
		requireUnresolvedLocal(t, locals, name)
	}
}

func TestGetInputVariables_JSONLocalsReadVariables(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf.json": `{
  "variable": { "env": { "default": "prod" } },
  "locals": [
    { "is_prod": "${var.env == \"prod\"}" },
    { "retention": "${local.is_prod ? 90 : 30}" }
  ]
}`,
		"locals.tf": `
locals {
  name = local.retention > 60 ? "long" : "short"
}
`,
	})
	requireLocal(t, locals, "is_prod", cty.True)
	requireLocal(t, locals, "retention", cty.NumberIntVal(90))
	requireLocal(t, locals, "name", cty.StringVal("long"))
}

func TestParser_ResourceAttributesReadLocalsResolvedFromVariables(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"variables.tf": `
variable "env" {
  default = "prod"
}
variable "nodef" {
  type = string
}
`,
		"locals.tf": `
locals {
  is_prod = var.env == "prod"
  unknown = var.nodef == "prod"
}
`,
	})
	main := filepath.Join(dir, "main.tf")
	src := []byte(`
resource "aws_cloudwatch_log_group" "known" {
  retention_in_days = local.is_prod ? 90 : 30
}
resource "aws_cloudwatch_log_group" "unknown" {
  retention_in_days = local.unknown ? 90 : 30
}
`)
	require.NoError(t, os.WriteFile(main, src, 0o600))

	_, docs, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	groups := docs[0]["resource"].(model.Document)["aws_cloudwatch_log_group"].(model.Document)
	requireNumber(t, groups["known"].(model.Document)["retention_in_days"], 90)
	require.Equal(t, "${local.unknown ? 90 : 30}", groups["unknown"].(model.Document)["retention_in_days"])
}

func TestParser_JSONResourceAttributesReadLocalsResolvedFromVariables(t *testing.T) {
	src := `{
  "variable": { "env": { "default": "prod" }, "flag": { "type": "bool" } },
  "locals": { "is_prod": "${var.env == \"prod\"}", "unknown": "${var.flag}" },
  "resource": { "aws_cloudwatch_log_group": { "g": {
    "retention_in_days": "${local.is_prod ? 90 : 30}",
    "try_unknown": "${try(local.unknown ? 0 : 30, 90)}"
  } } }
}`
	dir := writeTerraformDir(t, map[string]string{"main.tf.json": src})
	main := filepath.Join(dir, "main.tf.json")

	_, docs, _, _, err := NewDefault().Parse(context.Background(), []byte(src), main, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	group := docs[0]["resource"].(model.Document)["aws_cloudwatch_log_group"].(model.Document)["g"].(model.Document)
	requireNumber(t, group["retention_in_days"], 90)
	// local.unknown is missing, as before, so try takes its fallback.
	requireNumber(t, group["try_unknown"], 90)
}

// A local that does not resolve is missing from the converter context, as
// before: an expression reading it renders as unresolved text, except under
// try and can, which take their fallback as they did before.
func TestParser_ResourceAttributesReadUnresolvedLocalsAsMissing(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"variables.tf": `
variable "known" {
  type    = bool
  default = true
}
variable "flag" {
  type = bool
}
`,
		"locals.tf": `
locals {
  known_default = var.known
  unknown       = var.flag
  workspace     = terraform.workspace == "production"
  module_dir    = "${path.module}/policies"
}
`,
	})
	main := filepath.Join(dir, "main.tf")
	src := []byte(`
resource "aws_cloudwatch_log_group" "g" {
  try_unknown   = try(local.unknown ? 0 : 30, 90)
  can_unknown   = can(local.unknown) ? 0 : 90
  try_known     = try(local.known_default ? 0 : 30, 90)
  workspace     = local.workspace ? 0 : 30
  direct_path   = "${path.module}/policies"
  local_path    = local.module_dir
}
`)
	require.NoError(t, os.WriteFile(main, src, 0o600))

	_, docs, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	group := docs[0]["resource"].(model.Document)["aws_cloudwatch_log_group"].(model.Document)["g"].(model.Document)
	requireNumber(t, group["try_unknown"], 90)
	requireNumber(t, group["can_unknown"], 90)
	require.Equal(t, "${local.workspace ? 0 : 30}", group["workspace"])
	requireNumber(t, group["try_known"], 0)
	// A local reading path gets the value the converter gives path itself.
	require.Equal(t, filepath.ToSlash(dir)+"/policies", stringifyValue(group["direct_path"]))
	require.Equal(t, stringifyValue(group["direct_path"]), stringifyValue(group["local_path"]))
}

// An unresolved local is not folded into a known value by go-cty, neither in
// resource attributes nor in the locals blocks of the document:
// length([local.blocked.missing]) fails in Terraform, so try returns 0.
func TestParser_UnresolvedLocalsAreNotFoldedIntoKnownValues(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{"main.tf": `
locals {
  blocked = sensitive({ present = 1 })
  days    = try(length([local.blocked.missing]) == 1 ? 90 : 0, 0)
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = try(length([local.blocked.missing]) == 1 ? 90 : 0, 0)
}
`})
	path := filepath.Join(dir, "main.tf")
	src, err := os.ReadFile(path)
	require.NoError(t, err)
	_, docs, _, _, err := NewDefault().Parse(context.Background(), src, path, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	group := docs[0]["resource"].(model.Document)["aws_cloudwatch_log_group"].(model.Document)["g"].(model.Document)
	requireNumber(t, group["retention_in_days"], 0)
	requireNumber(t, docs[0]["locals"].(model.Document)["days"], 0)
}

func rootVariables(t *testing.T, files map[string]string) (vars, locals map[string]cty.Value) {
	t.Helper()
	dir := writeTerraformDir(t, files)
	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", nil, "")
	return got["var"].AsValueMap(), got["local"].AsValueMap()
}

// An override file replaces only the arguments it sets of a variable, after
// every ordinary file, whatever the names sort to.
func TestGetInputVariables_OverrideFilesMergeVariableArguments(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  cty.Value
	}{
		{
			name: "type only, sorting first",
			files: map[string]string{
				"zmain.tf":      "variable \"days\" {\n  type = string\n  default = 0\n}",
				"a_override.tf": `variable "days" { type = number }`,
			},
			want: cty.NumberIntVal(0),
		},
		{
			name: "type only, JSON",
			files: map[string]string{
				"zmain.tf.json":      `{"variable": {"days": {"type": "string", "default": 0}}}`,
				"a_override.tf.json": `{"variable": {"days": {"type": "number"}}}`,
			},
			want: cty.NumberIntVal(0),
		},
		{
			name: "default only, sorting first",
			files: map[string]string{
				"zmain.tf":      "variable \"days\" {\n  type = number\n  default = 0\n}",
				"a_override.tf": `variable "days" { default = 90 }`,
			},
			want: cty.NumberIntVal(90),
		},
		{
			name: "description only keeps the default",
			files: map[string]string{
				"main.tf":       "variable \"days\" {\n  type = number\n  default = 0\n}",
				"z_override.tf": `variable "days" { description = "sample" }`,
			},
			want: cty.NumberIntVal(0),
		},
		{
			name: "later override wins",
			files: map[string]string{
				"main.tf":       `variable "days" { default = 0 }`,
				"a_override.tf": `variable "days" { default = 30 }`,
				"b_override.tf": `variable "days" { default = 60 }`,
			},
			want: cty.NumberIntVal(60),
		},
		{
			name: "variable definitions file still wins",
			files: map[string]string{
				"main.tf":          `variable "days" { default = 0 }`,
				"a_override.tf":    `variable "days" { type = string }`,
				"terraform.tfvars": `days = 7`,
			},
			want: cty.StringVal("7"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars, _ := rootVariables(t, tt.files)
			require.True(t, tt.want.RawEquals(vars["days"]), "var.days = %#v, want %#v", vars["days"], tt.want)
		})
	}
}

func TestParser_VariableOverrideDecidesDirectReference(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"zmain.tf": `
variable "days" {
  type    = string
  default = 0
}
locals {
  days = var.days == 0 ? 0 : 90
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = var.days == 0 ? 0 : 90
  via_local         = local.days
}
`,
		"a_override.tf": `variable "days" { type = number }`,
	})
	group := parseLogGroup(t, dir, "zmain.tf")
	requireNumber(t, group["retention_in_days"], 0)
	requireNumber(t, group["via_local"], 0)
}

// A non-nullable variable given null takes its default, a nullable one keeps
// null.
func TestGetInputVariables_NonNullableVariableGivenNullTakesDefault(t *testing.T) {
	declare := func(nullable string) map[string]string {
		return map[string]string{
			"main.tf": `
variable "days" {
  type     = number
  default  = 0
  nullable = ` + nullable + `
}
variable "required" {
  type     = number
  nullable = false
}
locals {
  days = coalesce(var.days, 90)
}
`,
			"terraform.tfvars": "days = null\nrequired = null\n",
		}
	}
	vars, locals := rootVariables(t, declare("false"))
	require.True(t, vars["days"].RawEquals(cty.NumberIntVal(0)), "%#v", vars["days"])
	require.False(t, vars["required"].IsKnown(), "a null without a default is rejected: %#v", vars["required"])
	requireLocal(t, locals, "days", cty.NumberIntVal(0))

	vars, locals = rootVariables(t, declare("true"))
	require.True(t, vars["days"].IsNull(), "%#v", vars["days"])
	requireLocal(t, locals, "days", cty.NumberIntVal(90))
}

// Root variables convert to their type as Terraform converts them.
func TestGetInputVariables_VariableTypeConversions(t *testing.T) {
	vars, _ := rootVariables(t, map[string]string{"main.tf": `
variable "number" {
  type    = number
  default = "90"
}
variable "string" {
  type    = string
  default = 90
}
variable "bool" {
  type    = bool
  default = "false"
}
variable "any" {
  type    = any
  default = [1, "two"]
}
variable "tuple" {
  type    = tuple([number, string])
  default = ["1", 2]
}
variable "list" {
  type    = list(string)
  default = [1, 2]
}
variable "optional" {
  type    = list(object({ enabled = optional(bool, false) }))
  default = [{}, { enabled = null }]
}
variable "null" {
  type    = object({ enabled = optional(bool, false) })
  default = null
}
variable "invalid" {
  type    = number
  default = "bad"
}
`})
	enabled := cty.ObjectVal(map[string]cty.Value{"enabled": cty.False})
	for name, want := range map[string]cty.Value{
		"number":   cty.NumberIntVal(90),
		"string":   cty.StringVal("90"),
		"bool":     cty.False,
		"any":      cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.StringVal("two")}),
		"tuple":    cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.StringVal("2")}),
		"list":     cty.ListVal([]cty.Value{cty.StringVal("1"), cty.StringVal("2")}),
		"optional": cty.ListVal([]cty.Value{enabled, enabled}),
		"null":     cty.NullVal(cty.Object(map[string]cty.Type{"enabled": cty.Bool})),
	} {
		require.True(t, want.RawEquals(vars[name]), "var.%s = %#v, want %#v", name, vars[name], want)
	}
	require.False(t, vars["invalid"].IsKnown())
}

// A JSON default, and a JSON variable definitions file value, is a literal
// value, as Terraform reads it: "${0}" stays that string, and conforming it to
// string keeps it.
func TestGetInputVariables_JSONDefaultsAreLiteral(t *testing.T) {
	vars, _ := rootVariables(t, map[string]string{
		"main.tf.json": `{"variable": {
  "text":   {"type": "string", "default": "${0}"},
  "object": {"type": "object({text=string})", "default": {"text": "${0}"}},
  "input":  {"type": "string"}
}}`,
		"hcl.tf":                `variable "escaped" { default = "$${0}" }`,
		"terraform.tfvars.json": `{"input": "${0}"}`,
	})
	literal := cty.StringVal("${0}")
	require.True(t, vars["text"].RawEquals(literal), "%#v", vars["text"])
	require.True(t, vars["object"].RawEquals(cty.ObjectVal(map[string]cty.Value{"text": literal})), "%#v", vars["object"])
	require.True(t, vars["input"].RawEquals(literal), "%#v", vars["input"])
	require.True(t, vars["escaped"].RawEquals(literal), "%#v", vars["escaped"])
}

func TestParser_JSONLiteralDefaultDecidesDirectReference(t *testing.T) {
	src := `{
  "variable": {"text": {"type": "string", "default": "${0}"}},
  "resource": {"aws_cloudwatch_log_group": {"g": {
    "name": "sample",
    "retention_in_days": "${try(length(var.text),4) == 4 ? 0 : 90}"
  }}}
}`
	dir := writeTerraformDir(t, map[string]string{"main.tf.json": src})
	path := filepath.Join(dir, "main.tf.json")
	_, docs, _, _, err := NewDefault().Parse(context.Background(), []byte(src), path, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	group := docs[0]["resource"].(model.Document)["aws_cloudwatch_log_group"].(model.Document)["g"].(model.Document)
	requireNumber(t, group["retention_in_days"], 0)
}
