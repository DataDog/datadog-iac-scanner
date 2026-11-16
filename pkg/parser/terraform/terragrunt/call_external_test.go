/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/terragrunt"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/stretchr/testify/require"
)

// End to end with tfeval: the unit's inputs reach the module's resources.
func TestUnitCall_EvaluatesModule(t *testing.T) {
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	for name, content := range map[string]string{
		"modules/bucket/main.tf": `
variable "name" {}
variable "acl" { default = "private" }
resource "aws_s3_bucket" "this" {
  bucket = var.name
  acl    = var.acl
}`,
		"root.hcl": `terraform {
  source = "${get_parent_terragrunt_dir()}/modules//bucket"
}`,
		"prod/logs/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}
inputs = {
  name = "prod-logs"
  acl  = "public-read"
}`,
	} {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	u, err := terragrunt.New(nil, root).EvaluateUnit(context.Background(), filepath.Join(root, "prod/logs/terragrunt.hcl"))
	require.NoError(t, err)
	call, inputs, ok := u.Call()
	require.True(t, ok)

	resources, _, visited, err := tfeval.New().EvaluateCall(context.Background(), &tfeval.SyntheticCall{
		Label: call.Label, Source: call.Source, Version: call.Version,
		CallerFile: call.CallerFile, Range: call.Range, Body: call.Body,
	}, inputs)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	bucket := resources[0]
	require.Equal(t, "module.terragrunt", bucket.ModuleAddress)
	require.Equal(t, "prod-logs", bucket.Attributes["bucket"].AsString())
	require.Equal(t, "public-read", bucket.Attributes["acl"].AsString())
	require.Equal(t, u.ConfigFile, bucket.CallChain[0].CalledFrom)
	require.True(t, visited[filepath.Join(root, "modules/bucket")])
}
