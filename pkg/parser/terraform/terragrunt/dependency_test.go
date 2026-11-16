/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

const appWithDependency = `dependency "vpc" {
  config_path = "../vpc"
  mock_outputs = {
    vpc_id = "vpc-mock"
    cidr   = "10.0.0.0/16"
  }
}
dependency "db" {
  config_path  = "../db"
  skip_outputs = true
  mock_outputs = { endpoint = "db.mock" }
}
dependency "cache" {
  config_path = "../cache"
}
inputs = {
  vpc_id   = dependency.vpc.outputs.vpc_id
  cidr     = dependency.vpc.outputs.cidr
  endpoint = dependency.db.outputs.endpoint
  cache    = dependency.cache.outputs.host
}`

func dependencyTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"vpc/terragrunt.hcl":   `terraform { source = "../modules/vpc" }`,
		"db/terragrunt.hcl":    `terraform { source = "../modules/db" }`,
		"cache/terragrunt.hcl": `terraform { source = "../modules/cache" }`,
		"app/terragrunt.hcl":   appWithDependency,
	})
}

// Nothing reads state: outputs are mocks, or unknown without one.
func TestEvaluateUnit_DependencyMocks(t *testing.T) {
	root := dependencyTree(t)
	u := evaluate(t, root, "app/terragrunt.hcl")
	requireInput(t, u, "vpc_id", cty.StringVal("vpc-mock"))
	requireInput(t, u, "endpoint", cty.StringVal("db.mock"))
	requireUnknown(t, u, "cache")
	require.Equal(t, []string{
		filepath.Join(root, "cache/terragrunt.hcl"),
		filepath.Join(root, "db/terragrunt.hcl"),
		filepath.Join(root, "vpc/terragrunt.hcl"),
	}, u.Dependencies)
}

// Outputs the scan evaluated win when known; the mock fills the rest, and
// skip_outputs keeps the mock.
func TestEvaluateUnit_DependencyEvaluatedOutputs(t *testing.T) {
	root := dependencyTree(t)
	outputs := map[string]cty.Value{
		filepath.Join(root, "vpc/terragrunt.hcl"): cty.ObjectVal(map[string]cty.Value{
			"vpc_id": cty.UnknownVal(cty.String),
			"cidr":   cty.StringVal("10.1.0.0/16"),
		}),
		filepath.Join(root, "db/terragrunt.hcl"): cty.ObjectVal(map[string]cty.Value{
			"endpoint": cty.StringVal("db.real"),
		}),
		filepath.Join(root, "cache/terragrunt.hcl"): cty.ObjectVal(map[string]cty.Value{
			"host": cty.StringVal("cache.real"),
		}),
	}
	u, err := New(nil, root).WithDependencyOutputs(outputs).EvaluateUnit(
		context.Background(), filepath.Join(root, "app/terragrunt.hcl"))
	require.NoError(t, err)
	requireInput(t, u, "vpc_id", cty.StringVal("vpc-mock"))
	requireInput(t, u, "cidr", cty.StringVal("10.1.0.0/16"))
	requireInput(t, u, "endpoint", cty.StringVal("db.mock"))
	requireInput(t, u, "cache", cty.StringVal("cache.real"))
}

func TestEvaluateUnit_DependencyFromInclude(t *testing.T) {
	root := writeTree(t, map[string]string{
		"live/root.hcl": `dependency "vpc" {
  config_path  = "${get_terragrunt_dir()}/../vpc"
  mock_outputs = { vpc_id = "vpc-mock" }
}`,
		"live/vpc/terragrunt.hcl": `terraform { source = "../../modules/vpc" }`,
		"live/app/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}
inputs = { vpc_id = dependency.vpc.outputs.vpc_id }`,
	})
	u := evaluate(t, root, "live/app/terragrunt.hcl")
	requireInput(t, u, "vpc_id", cty.StringVal("vpc-mock"))
	require.Equal(t, []string{filepath.Join(root, "live/vpc/terragrunt.hcl")}, u.Dependencies)
}

func TestEvaluateUnit_ExtraArgumentsVarOverrides(t *testing.T) {
	root := writeTree(t, map[string]string{
		"common.tfvars": `acl = "public-read"
region = "eu-west-1"`,
		"unit/prod.tfvars":          `region = "eu-west-3"`,
		"unit/settings.tfvars.json": `{"versioning": false}`,
		"unit/terragrunt.hcl": `terraform {
  source = "../modules/bucket"

  extra_arguments "vars" {
    commands  = get_terraform_commands_that_need_vars()
    arguments = ["-var-file=${get_parent_terragrunt_dir()}/../common.tfvars", "-var", "tags={team=\"sec\"}"]
    required_var_files = ["prod.tfvars"]
    optional_var_files = ["missing.tfvars", "settings.tfvars.json"]
  }

  extra_arguments "init_only" {
    commands  = ["init"]
    arguments = ["-var-file=prod.tfvars"]
  }
}`,
	})
	u := evaluate(t, root, "unit/terragrunt.hcl")

	var names []string
	for _, override := range u.VarOverrides {
		names = append(names, override.Name)
	}
	require.Equal(t, []string{"acl", "region", "tags", "region", "versioning"}, names)
	require.Equal(t, filepath.Join(root, "common.tfvars"), u.VarOverrides[0].Range.Filename)
	require.Equal(t, 1, u.VarOverrides[0].Range.Start.Line)
	require.True(t, u.VarOverrides[2].Value.RawEquals(cty.ObjectVal(map[string]cty.Value{"team": cty.StringVal("sec")})))
	require.Equal(t, u.ConfigFile, u.VarOverrides[2].Range.Filename)
	require.True(t, u.VarOverrides[3].Value.RawEquals(cty.StringVal("eu-west-3")))
	require.True(t, u.VarOverrides[4].Value.RawEquals(cty.False))
}

func TestParseVarArguments(t *testing.T) {
	require.Equal(t, []varArgument{
		{file: "a.tfvars"},
		{file: "b.tfvars"},
		{name: "x", value: "1"},
		{name: "y", value: "a=b"},
	}, parseVarArguments([]string{
		"-var-file=a.tfvars", "--var-file", "b.tfvars", "-lock=false", "-var", "x=1", "-var=y=a=b", "-var",
	}))
}
