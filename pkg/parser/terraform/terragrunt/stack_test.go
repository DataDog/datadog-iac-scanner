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

const bucketUnitTemplate = `terraform {
  source = "${get_repo_root()}/modules/bucket"
}

inputs = {
  name = "${values.env}-logs"
  acl  = values.acl
}
`

func expandStack(t *testing.T, root, stack string) map[string]*StackUnit {
	t.Helper()
	units, err := New(nil, root).ExpandStack(context.Background(), filepath.Join(root, stack))
	require.NoError(t, err)
	byName := map[string]*StackUnit{}
	for _, unit := range units {
		byName[unit.Name] = unit
	}
	return byName
}

func TestExpandStack(t *testing.T) {
	root := writeTree(t, map[string]string{
		"units/bucket/terragrunt.hcl": bucketUnitTemplate,
		"live/prod/terragrunt.stack.hcl": `locals {
  env = "prod"
}

unit "logs" {
  source = "../../units/bucket"
  path   = "logs"
  values = {
    env = local.env
    acl = "public-read"
  }
}

unit "remote" {
  source = "git::https://example.com/units.git//bucket"
  path   = "remote"
}
`,
	})
	units := expandStack(t, root, "live/prod/terragrunt.stack.hcl")
	require.Len(t, units, 1, "remote unit sources are not expanded")
	logs := units["logs"]
	stackFile := filepath.Join(root, "live/prod/terragrunt.stack.hcl")
	generated := filepath.Join(root, "live/prod/.terragrunt-stack/logs")

	require.Equal(t, stackFile, logs.StackFile)
	require.Equal(t, filepath.Join(root, "units/bucket/terragrunt.hcl"), logs.SourceConfig)
	require.Equal(t, filepath.Join(generated, "terragrunt.hcl"), logs.Unit.ConfigFile)
	require.Equal(t, root+"/modules/bucket", logs.Unit.Source)
	requireInput(t, logs.Unit, "name", cty.StringVal("prod-logs"))
	requireInput(t, logs.Unit, "acl", cty.StringVal("public-read"))
	require.Equal(t, "acl", logs.Unit.Inputs["acl"].ValuesKey)
	require.Empty(t, logs.Unit.Inputs["name"].ValuesKey, "an input computed from a value is not the value itself")

	call, _, ok := logs.Call()
	require.True(t, ok)
	require.Equal(t, "logs", call.Label)
	require.Equal(t, stackFile, call.CallerFile)
	require.Equal(t, generated, call.SourceDir)
	require.Equal(t, 5, call.Range.Start.Line, "anchored at the unit block")
	require.Contains(t, call.Body.Attributes, "acl")
	require.Equal(t, stackFile, call.Body.Attributes["acl"].SrcRange.Filename)
	require.Equal(t, 10, call.Body.Attributes["acl"].SrcRange.Start.Line, "where the stack sets the value")
	require.NotContains(t, call.Body.Attributes, "name")
}

func TestExpandStack_Nested(t *testing.T) {
	root := writeTree(t, map[string]string{
		"units/bucket/terragrunt.hcl": bucketUnitTemplate,
		"stacks/storage/terragrunt.stack.hcl": `unit "logs" {
  source = "${get_repo_root()}/units/bucket"
  path   = "logs"
  values = {
    env = values.env
    acl = "private"
  }
}
`,
		"live/terragrunt.stack.hcl": `stack "storage" {
  source = "../stacks/storage"
  path   = "storage"
  values = { env = "dev" }
}
`,
	})
	units := expandStack(t, root, "live/terragrunt.stack.hcl")
	require.Len(t, units, 1)
	logs := units["storage_logs"]
	require.NotNil(t, logs)
	require.Equal(t, filepath.Join(root, "live/terragrunt.stack.hcl"), logs.StackFile)
	require.Equal(t, 1, logs.Block.Start.Line, "a nested stack's unit is anchored at the outer stack block")
	require.Equal(t,
		filepath.Join(root, "live/.terragrunt-stack/storage/.terragrunt-stack/logs/terragrunt.hcl"),
		logs.Unit.ConfigFile)
	requireInput(t, logs.Unit, "name", cty.StringVal("dev-logs"))
}

func TestExpandStack_DependenciesBetweenUnits(t *testing.T) {
	root := writeTree(t, map[string]string{
		"units/vpc/terragrunt.hcl": `terraform { source = "${get_repo_root()}/modules/vpc" }`,
		"units/app/terragrunt.hcl": `terraform { source = "${get_repo_root()}/modules/app" }
dependency "vpc" {
  config_path  = "../vpc"
  mock_outputs = { id = "vpc-mock" }
}
inputs = { vpc_id = dependency.vpc.outputs.id }
`,
		"live/terragrunt.stack.hcl": `unit "vpc" {
  source = "../units/vpc"
  path   = "vpc"
}
unit "app" {
  source = "../units/app"
  path   = "app"
}
`,
	})
	units := expandStack(t, root, "live/terragrunt.stack.hcl")
	vpcConfig := units["vpc"].Unit.ConfigFile
	require.Equal(t, []string{vpcConfig}, units["app"].Unit.Dependencies)
	requireInput(t, units["app"].Unit, "vpc_id", cty.StringVal("vpc-mock"))

	again, err := units["app"].WithDependencyOutputs(context.Background(), map[string]cty.Value{
		vpcConfig: cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("vpc-123")}),
	})
	require.NoError(t, err)
	requireInput(t, again.Unit, "vpc_id", cty.StringVal("vpc-123"))
}

// A unit generated into the repository itself is scanned as a unit.
func TestExpandStack_NoDotStackAlreadyGenerated(t *testing.T) {
	root := writeTree(t, map[string]string{
		"units/bucket/terragrunt.hcl": bucketUnitTemplate,
		"live/logs/terragrunt.hcl":    `inputs = {}`,
		"live/terragrunt.stack.hcl": `unit "logs" {
  source                  = "../units/bucket"
  path                    = "logs"
  no_dot_terragrunt_stack = true
}
unit "audit" {
  source                  = "../units/bucket"
  path                    = "audit"
  no_dot_terragrunt_stack = true
}
`,
	})
	units := expandStack(t, root, "live/terragrunt.stack.hcl")
	require.Len(t, units, 1)
	require.Equal(t, filepath.Join(root, "live/audit/terragrunt.hcl"), units["audit"].Unit.ConfigFile)
}
