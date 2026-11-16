/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// writeTree writes files under a new repository root and returns the root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	return root
}

func evaluate(t *testing.T, root, unit string) *Unit {
	t.Helper()
	u, err := New(nil, root).EvaluateUnit(context.Background(), filepath.Join(root, unit))
	require.NoError(t, err)
	return u
}

func requireInput(t *testing.T, u *Unit, name string, want cty.Value) {
	t.Helper()
	input, ok := u.Inputs[name]
	require.True(t, ok, "input %q missing", name)
	require.True(t, input.Value.RawEquals(want), "input %q = %#v, want %#v", name, input.Value, want)
}

func requireUnknown(t *testing.T, u *Unit, name string) {
	t.Helper()
	input, ok := u.Inputs[name]
	require.True(t, ok, "input %q missing", name)
	require.False(t, input.Value.IsWhollyKnown(), "input %q = %#v, want unknown", name, input.Value)
}

func TestEvaluateUnit_SourceAndInputRanges(t *testing.T) {
	root := writeTree(t, map[string]string{
		"live/prod/terragrunt.hcl": `terraform {
  source = "../../modules//bucket"
}

inputs = {
  name = "logs"
  tags = {
    team = "sec"
  }
}
`,
	})
	u := evaluate(t, root, "live/prod/terragrunt.hcl")
	config := filepath.Join(root, "live/prod/terragrunt.hcl")

	require.Equal(t, config, u.ConfigFile)
	require.Equal(t, filepath.Dir(config), u.Dir)
	require.True(t, u.SourceKnown)
	require.Equal(t, "../../modules//bucket", u.Source)
	require.Equal(t, 2, u.SourceRange.Start.Line)
	require.False(t, u.Skip)

	requireInput(t, u, "name", cty.StringVal("logs"))
	require.Equal(t, config, u.Inputs["name"].Range.Filename)
	require.Equal(t, 6, u.Inputs["name"].Range.Start.Line)
	require.Equal(t, 7, u.Inputs["tags"].Range.Start.Line)
	require.Equal(t, 9, u.Inputs["tags"].Range.End.Line, "a multi-line input spans its whole item")
	require.Equal(t, 5, u.InputsRange.Start.Line)
}

func TestEvaluateUnit_NoTerraformBlock(t *testing.T) {
	root := writeTree(t, map[string]string{"app/terragrunt.hcl": `inputs = { name = "app" }`})
	u := evaluate(t, root, "app/terragrunt.hcl")
	require.True(t, u.SourceKnown)
	require.Empty(t, u.Source)
}

// The common layout: a root.hcl every unit includes, computing the module
// source from the unit's path and providing shared inputs.
func TestEvaluateUnit_IncludeShallowMerge(t *testing.T) {
	root := writeTree(t, map[string]string{
		"root.hcl": `locals {
  region = "eu-west-1"
}
terraform {
  source = "${get_parent_terragrunt_dir()}/modules//${path_relative_to_include()}"
}
inputs = {
  region = local.region
  tags   = { owner = "platform", env = "unknown" }
  unit   = get_terragrunt_dir()
}
`,
		"prod/bucket/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}
inputs = {
  tags = { env = "prod" }
}
`,
	})
	u := evaluate(t, root, "prod/bucket/terragrunt.hcl")

	require.Equal(t, root+"/modules//prod/bucket", u.Source)
	require.Equal(t, filepath.Join(root, "root.hcl"), u.SourceRange.Filename)
	requireInput(t, u, "region", cty.StringVal("eu-west-1"))
	requireInput(t, u, "unit", cty.StringVal(u.Dir))
	requireInput(t, u, "tags", cty.ObjectVal(map[string]cty.Value{"env": cty.StringVal("prod")}))
	require.Equal(t, filepath.Join(root, "root.hcl"), u.Inputs["region"].Range.Filename)
	require.Equal(t, 8, u.Inputs["region"].Range.Start.Line)
	require.Equal(t, u.ConfigFile, u.Inputs["tags"].Range.Filename)
	require.Equal(t, u.ConfigFile, u.InputsRange.Filename)
	require.Equal(t, []string{filepath.Join(root, "root.hcl")}, u.Includes)
}

func TestEvaluateUnit_IncludeDeepMerge(t *testing.T) {
	root := writeTree(t, map[string]string{
		"root.hcl": `inputs = {
  tags  = { owner = "platform", env = "unknown" }
  cidrs = ["10.0.0.0/16"]
}`,
		"prod/terragrunt.hcl": `include "root" {
  path           = find_in_parent_folders("root.hcl")
  merge_strategy = "deep"
}
inputs = {
  tags  = { env = "prod" }
  cidrs = ["10.1.0.0/16"]
}`,
	})
	u := evaluate(t, root, "prod/terragrunt.hcl")
	requireInput(t, u, "tags", cty.ObjectVal(map[string]cty.Value{
		"owner": cty.StringVal("platform"), "env": cty.StringVal("prod"),
	}))
	requireInput(t, u, "cidrs", cty.TupleVal([]cty.Value{cty.StringVal("10.0.0.0/16"), cty.StringVal("10.1.0.0/16")}))
}

func TestEvaluateUnit_IncludeNoMergeAndExpose(t *testing.T) {
	root := writeTree(t, map[string]string{
		"env.hcl": `locals {
  env = "staging"
}
inputs = { from_env = true }`,
		"staging/app/terragrunt.hcl": `include "env" {
  path           = find_in_parent_folders("env.hcl")
  expose         = true
  merge_strategy = "no_merge"
}
locals {
  name = "app-${include.env.locals.env}"
}
inputs = {
  name = local.name
  env  = include.env.inputs.from_env
}`,
	})
	u := evaluate(t, root, "staging/app/terragrunt.hcl")
	requireInput(t, u, "name", cty.StringVal("app-staging"))
	requireInput(t, u, "env", cty.True)
	_, merged := u.Inputs["from_env"]
	require.False(t, merged, "no_merge keeps the included inputs out")
}

func TestEvaluateUnit_PathFunctionsInIncludedFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"live/root.hcl": `inputs = {
  to_include   = path_relative_to_include()
  from_include = path_relative_from_include()
  parent_dir   = get_parent_terragrunt_dir()
  unit_dir     = get_terragrunt_dir()
  from_repo    = get_path_from_repo_root()
  to_repo      = get_path_to_repo_root()
  repo         = get_repo_root()
}`,
		"live/eu/db/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}`,
	})
	u := evaluate(t, root, "live/eu/db/terragrunt.hcl")
	requireInput(t, u, "to_include", cty.StringVal("eu/db"))
	requireInput(t, u, "from_include", cty.StringVal("../.."))
	requireInput(t, u, "parent_dir", cty.StringVal(filepath.Join(root, "live")))
	requireInput(t, u, "unit_dir", cty.StringVal(filepath.Join(root, "live/eu/db")))
	requireInput(t, u, "from_repo", cty.StringVal("live/eu/db"))
	requireInput(t, u, "to_repo", cty.StringVal("../../.."))
	requireInput(t, u, "repo", cty.StringVal(root))
}

func TestEvaluateUnit_NestedIncludesAreIgnored(t *testing.T) {
	root := writeTree(t, map[string]string{
		"top.hcl": `inputs = { top = true }`,
		"a/mid.hcl": `include "top" {
  path = find_in_parent_folders("top.hcl")
}
inputs = { mid = true }`,
		"a/b/terragrunt.hcl": `include "mid" {
  path = find_in_parent_folders("mid.hcl")
}`,
	})
	u := evaluate(t, root, "a/b/terragrunt.hcl")
	requireInput(t, u, "mid", cty.True)
	_, ok := u.Inputs["top"]
	require.False(t, ok)
}

func TestEvaluateUnit_ReadTerragruntConfig(t *testing.T) {
	root := writeTree(t, map[string]string{
		"prod/env.hcl": `locals {
  env      = "prod"
  own_dir  = get_terragrunt_dir()
  unit_dir = get_original_terragrunt_dir()
}`,
		"prod/app/terragrunt.hcl": `locals {
  env = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  missing = read_terragrunt_config("nope.hcl", { locals = { env = "fallback" } })
}
inputs = {
  env      = local.env.locals.env
  own_dir  = local.env.locals.own_dir
  unit_dir = local.env.locals.unit_dir
  fallback = local.missing.locals.env
}`,
	})
	u := evaluate(t, root, "prod/app/terragrunt.hcl")
	requireInput(t, u, "env", cty.StringVal("prod"))
	requireInput(t, u, "own_dir", cty.StringVal(filepath.Join(root, "prod")))
	requireInput(t, u, "unit_dir", cty.StringVal(filepath.Join(root, "prod/app")))
	requireInput(t, u, "fallback", cty.StringVal("fallback"))
}

func TestEvaluateUnit_ReadTerragruntConfigCycle(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.hcl": `locals { b = read_terragrunt_config("b.hcl") }`,
		"b.hcl": `locals { a = read_terragrunt_config("a.hcl") }`,
		"unit/terragrunt.hcl": `locals {
  a = read_terragrunt_config("../a.hcl")
}
inputs = { a = local.a.locals.b.locals.a }`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")
	requireUnknown(t, u, "a")
}

func TestEvaluateUnit_ReadTfvarsFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"unit/common.tfvars": `instance_type = "t3.micro"
count = 2`,
		"unit/terragrunt.hcl": `inputs = jsondecode(read_tfvars_file("common.tfvars"))`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")
	requireInput(t, u, "instance_type", cty.StringVal("t3.micro"))
	requireInput(t, u, "count", cty.NumberIntVal(2))
}

func TestEvaluateUnit_LocalsOrderAndCycles(t *testing.T) {
	root := writeTree(t, map[string]string{
		"unit/terragrunt.hcl": `locals {
  full  = "${local.base}-${local.env}"
  base  = "svc"
  env   = "dev"
  loop1 = local.loop2
  loop2 = local.loop1
}
inputs = {
  full = local.full
  loop = local.loop1
}`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")
	requireInput(t, u, "full", cty.StringVal("svc-dev"))
	requireUnknown(t, u, "loop")
}

// Nothing reads the environment or runs: values only known when Terragrunt
// runs are unknown.
func TestEvaluateUnit_RuntimeValuesAreUnknown(t *testing.T) {
	t.Setenv("TG_TEST_REGION", "us-east-1")
	root := writeTree(t, map[string]string{
		"unit/terragrunt.hcl": `inputs = {
  with_default    = get_env("TG_TEST_REGION", "eu-west-3")
  without_default = get_env("TG_TEST_REGION")
  cmd             = run_cmd("echo", "hi")
  secret          = sops_decrypt_file("secrets.yaml")
  account         = get_aws_account_id()
  command         = get_terraform_command()
  needs_vars      = contains(get_terraform_commands_that_need_vars(), "plan")
}`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")
	requireInput(t, u, "with_default", cty.StringVal("eu-west-3"))
	requireUnknown(t, u, "without_default")
	requireUnknown(t, u, "cmd")
	requireUnknown(t, u, "secret")
	requireUnknown(t, u, "account")
	requireInput(t, u, "command", cty.StringVal("plan"))
	requireInput(t, u, "needs_vars", cty.True)
}

func TestEvaluateUnit_ConfinedToRepository(t *testing.T) {
	outside := writeTree(t, map[string]string{
		"root.hcl":   `inputs = { leaked = true }`,
		"secret.txt": "s3cr3t",
	})
	root := writeTree(t, map[string]string{
		"unit/terragrunt.hcl": `include "outside" {
  path = "` + filepath.Join(outside, "root.hcl") + `"
}
inputs = {
  found  = find_in_parent_folders("root.hcl", "not-found")
  secret = file("` + filepath.Join(outside, "secret.txt") + `")
}`,
	})
	// A root.hcl above the repository root must not be found either.
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(root), "root.hcl"), []byte(`inputs = {}`), 0o644))
	t.Cleanup(func() { _ = os.Remove(filepath.Join(filepath.Dir(root), "root.hcl")) })

	u := evaluate(t, root, "unit/terragrunt.hcl")
	_, leaked := u.Inputs["leaked"]
	require.False(t, leaked)
	requireInput(t, u, "found", cty.StringVal("not-found"))
	requireUnknown(t, u, "secret")

	_, err := New(nil, root).EvaluateUnit(context.Background(), filepath.Join(outside, "root.hcl"))
	require.Error(t, err)
}

func TestEvaluateUnit_SkipExcludeAndFeatures(t *testing.T) {
	root := writeTree(t, map[string]string{
		"root.hcl": `skip = true`,
		"skipped/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}`,
		"unskipped/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}
skip = false`,
		"excluded/terragrunt.hcl": `feature "off" {
  default = true
}
exclude {
  if      = feature.off.value
  actions = ["plan", "apply"]
}`,
		"output-only/terragrunt.hcl": `exclude {
  if      = true
  actions = ["output"]
}`,
		"unknown/terragrunt.hcl": `exclude {
  if      = get_env("DISABLE") == "1"
  actions = ["all"]
}`,
	})
	require.True(t, evaluate(t, root, "skipped/terragrunt.hcl").Skip)
	require.False(t, evaluate(t, root, "unskipped/terragrunt.hcl").Skip)
	require.True(t, evaluate(t, root, "excluded/terragrunt.hcl").Skip)
	require.False(t, evaluate(t, root, "output-only/terragrunt.hcl").Skip)
	require.False(t, evaluate(t, root, "unknown/terragrunt.hcl").Skip)
}

func TestEvaluateUnit_UnknownSource(t *testing.T) {
	root := writeTree(t, map[string]string{
		"unit/terragrunt.hcl": `terraform {
  source = run_cmd("pick-module")
}`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")
	require.False(t, u.SourceKnown)
	_, _, ok := u.Call()
	require.False(t, ok)
}

func TestEvaluateUnit_ParseError(t *testing.T) {
	root := writeTree(t, map[string]string{"unit/terragrunt.hcl": `inputs = {`})
	_, err := New(nil, root).EvaluateUnit(context.Background(), filepath.Join(root, "unit/terragrunt.hcl"))
	require.Error(t, err)
}

func TestUnitCall(t *testing.T) {
	root := writeTree(t, map[string]string{
		"root.hcl": `inputs = { region = "eu-west-1" }`,
		"unit/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}
terraform {
  source = "../modules/bucket"
}
inputs = {
  name = "logs"
}`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")
	call, inputs, ok := u.Call()
	require.True(t, ok)
	require.Equal(t, CallLabel, call.Label)
	require.Equal(t, "../modules/bucket", call.Source)
	require.Equal(t, u.ConfigFile, call.CallerFile)
	require.Equal(t, 5, call.Range.Start.Line)
	require.Equal(t, map[string]cty.Value{"name": cty.StringVal("logs"), "region": cty.StringVal("eu-west-1")}, inputs)
	require.Contains(t, call.Body.Attributes, "name")
	require.Equal(t, 8, call.Body.Attributes["name"].SrcRange.Start.Line)
	require.NotContains(t, call.Body.Attributes, "region", "inputs set in an included file are not positioned in the unit")

	u.Source = ""
	call, _, ok = u.Call()
	require.True(t, ok)
	require.Equal(t, "./", call.Source)

	u.Skip = true
	_, _, ok = u.Call()
	require.False(t, ok)
}

func TestEvaluateUnit_InputRangesThroughMerge(t *testing.T) {
	root := writeTree(t, map[string]string{
		"unit/terragrunt.hcl": `locals {
  common = { region = "eu-west-1" }
}
inputs = merge(
  local.common,
  { name = "a" },
  { name = "b" },
)
`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")
	requireInput(t, u, "name", cty.StringVal("b"))
	require.Equal(t, 7, u.Inputs["name"].Range.Start.Line, "the last object setting a key wins")
	requireInput(t, u, "region", cty.StringVal("eu-west-1"))
	require.Equal(t, u.InputsRange, u.Inputs["region"].Range, "a computed key falls back to the inputs attribute")
}

func TestModuleSource(t *testing.T) {
	tests := []struct{ source, wantSource, wantVersion string }{
		{"tfr:///terraform-aws-modules/vpc/aws?version=5.8.1", "terraform-aws-modules/vpc/aws", "5.8.1"},
		{"tfr:///terraform-aws-modules/iam/aws//modules/iam-role?version=5.0.0", "terraform-aws-modules/iam/aws//modules/iam-role", "5.0.0"},
		{"tfr://registry.example.com/acme/vpc/aws?version=1.2.0", "registry.example.com/acme/vpc/aws", "1.2.0"},
		{"tfr:///acme/vpc/aws", "acme/vpc/aws", ""},
		{"git::https://example.com/m.git//vpc?ref=v1.0.0", "git::https://example.com/m.git//vpc?ref=v1.0.0", ""},
		{"../modules//vpc", "../modules//vpc", ""},
	}
	for _, tt := range tests {
		source, version := moduleSource(tt.source)
		require.Equal(t, tt.wantSource, source, tt.source)
		require.Equal(t, tt.wantVersion, version, tt.source)
	}
}

func TestUnitCall_RegistrySource(t *testing.T) {
	root := writeTree(t, map[string]string{
		"vpc/terragrunt.hcl": `terraform {
  source = "tfr:///terraform-aws-modules/vpc/aws?version=5.8.1"
}`,
	})
	call, _, ok := evaluate(t, root, "vpc/terragrunt.hcl").Call()
	require.True(t, ok)
	require.Equal(t, "terraform-aws-modules/vpc/aws", call.Source)
	require.Equal(t, "5.8.1", call.Version)
}
