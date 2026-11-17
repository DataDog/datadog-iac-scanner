/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestTerraformAddressForBlockKindsAndNestedModule(t *testing.T) {
	scope := &model.TerraformScope{
		RootModule:    ".",
		ModuleAddress: `module.network["blue"]`,
		Blocks: map[model.TerraformBlock]bool{
			{Kind: "resource", Type: "aws_s3_bucket", Name: "web"}: true,
			{Kind: "data", Type: "aws_vpc", Name: "current"}:       true,
			{Kind: "variable", Name: "region"}:                     true,
		},
	}
	file := &model.FileMetadata{Kind: model.KindTerraform, TerraformScope: scope}
	for _, tc := range []struct{ typ, name, suffix, want string }{
		{"aws_s3_bucket", "web", `[0]`, `module.network["blue"].aws_s3_bucket.web[0]`},
		{"data.aws_vpc", "current", "", `module.network["blue"].data.aws_vpc.current`},
		{"variable", "region", "", `module.network["blue"].var.region`},
	} {
		got, ok := terraformAddressFor(file, tc.typ, tc.name, tc.suffix)
		require.True(t, ok)
		require.Equal(t, tc.want, got)
	}
	_, ok := terraformAddressFor(file, "aws_s3_bucket", "missing", "")
	require.False(t, ok)
}

func TestTerraformAddressForPlanUsesNativeAddress(t *testing.T) {
	file := &model.FileMetadata{Kind: model.KindTerraformPlan, TerraformScope: &model.TerraformScope{
		RootModule: "stacks/prod/tfplan.json",
		PlanAddresses: map[model.PlanResourceKey]string{
			{Section: "aws_s3_bucket", Key: "web[0]"}:             "module.app.aws_s3_bucket.web[0]",
			{Section: "data.aws_caller_identity", Key: "current"}: "data.aws_caller_identity.current",
		},
	}}
	got, ok := terraformAddressFor(file, "aws_s3_bucket", "web[0]", "")
	require.True(t, ok)
	require.Equal(t, "module.app.aws_s3_bucket.web[0]", got)
	got, ok = terraformAddressFor(file, "aws_caller_identity", "current", "")
	require.True(t, ok)
	require.Equal(t, "data.aws_caller_identity.current", got)
}

func TestTerraformVarsScopeUsesTheVarsFileAsRoot(t *testing.T) {
	root := t.TempDir()
	file := &model.FileMetadata{Kind: model.KindTerraform, FilePath: filepath.Join(root, "stacks", "prod", "terraform.tfvars")}
	inspector := &Inspector{repoPath: root}
	inspector.stampTerraformScopes(model.FileMetadatas{file})
	require.Equal(t, "stacks/prod/terraform.tfvars", file.TerraformScope.RootModule)
	got, ok := terraformAddressFor(file, "variable", "region", "")
	require.True(t, ok)
	require.Equal(t, "var.region", got)
}

func TestExpandedEphemeralBlocksDoNotClaimBaseAddress(t *testing.T) {
	file := &model.FileMetadata{Kind: model.KindTerraform, Document: model.Document{
		"ephemeral": map[string]interface{}{
			"aws_secretsmanager_secret_version": map[string]interface{}{
				"secret": map[string]interface{}{"for_each": "var.secrets"},
			},
		},
	}}
	inspector := &Inspector{}
	inspector.stampTerraformScopes(model.FileMetadatas{file})
	_, ok := terraformAddressFor(file, "ephemeral.aws_secretsmanager_secret_version", "secret", "")
	require.False(t, ok, "the evaluator does not materialize ephemeral for_each instances")
}
