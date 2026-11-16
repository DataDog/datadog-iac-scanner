/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

const syntheticBucketModule = `
variable "name" {}
variable "acl" { default = "private" }
resource "aws_s3_bucket" "this" {
  bucket = var.name
  acl    = var.acl
}
output "path_root" { value = path.root }
`

func syntheticCall(callerFile, source string) *SyntheticCall {
	return &SyntheticCall{
		Label:      "terragrunt",
		Source:     source,
		CallerFile: callerFile,
		Range: hcl.Range{
			Filename: callerFile,
			Start:    hcl.Pos{Line: 2, Column: 3},
			End:      hcl.Pos{Line: 2, Column: 30},
		},
	}
}

func TestEvaluateCall_BindsInputsAndRecordsCallSite(t *testing.T) {
	root := t.TempDir()
	module := writeModule(t, root, "modules/bucket", map[string]string{"main.tf": syntheticBucketModule})
	unit := writeModule(t, root, "live/prod", map[string]string{"terragrunt.hcl": ""})
	callerFile := filepath.Join(unit, "terragrunt.hcl")

	body := &hclsyntax.Body{Attributes: hclsyntax.Attributes{
		"acl": &hclsyntax.Attribute{
			Name:     "acl",
			Expr:     &hclsyntax.LiteralValueExpr{Val: cty.StringVal("public-read")},
			SrcRange: hcl.Range{Filename: callerFile, Start: hcl.Pos{Line: 5, Column: 3}, End: hcl.Pos{Line: 5, Column: 22}},
		},
	}}
	call := syntheticCall(callerFile, "../../modules/bucket")
	call.Body = body

	e := New()
	resources, outputs, visited, err := e.EvaluateCall(context.Background(), call, map[string]cty.Value{
		"name": cty.StringVal("logs"),
		"acl":  cty.StringVal("public-read"),
	})
	require.NoError(t, err)

	bucket := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, bucket.Attributes, "bucket", "logs")
	requireString(t, bucket.Attributes, "acl", "public-read")
	require.Equal(t, "module.terragrunt", bucket.ModuleAddress)
	require.Len(t, bucket.CallChain, 1)
	site := bucket.CallChain[0]
	require.Equal(t, "terragrunt", site.ModuleName)
	require.Equal(t, "../../modules/bucket", site.Source)
	require.Equal(t, callerFile, site.CalledFrom)
	require.Equal(t, 2, site.CalledLine)
	require.Same(t, body, site.Body)

	require.True(t, visited[module], "the called directory is reported as visited")
	require.Equal(t, module, outputs["path_root"].AsString(), "the called module is its own root")
}

func TestEvaluateCall_FallsBackToDefaults(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "modules/bucket", map[string]string{"main.tf": syntheticBucketModule})
	unit := writeModule(t, root, "live/dev", map[string]string{"terragrunt.hcl": ""})

	resources, _, _, err := New().EvaluateCall(context.Background(),
		syntheticCall(filepath.Join(unit, "terragrunt.hcl"), "../../modules//bucket"),
		map[string]cty.Value{"name": cty.StringVal("dev")})
	require.NoError(t, err)

	bucket := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, bucket.Attributes, "acl", "private")
}

func TestEvaluateCall_NestedModulesExtendTheChain(t *testing.T) {
	root := t.TempDir()
	child := writeModule(t, root, "modules/bucket", map[string]string{"main.tf": syntheticBucketModule})
	wrapper := writeModule(t, root, "modules/wrapper", map[string]string{"main.tf": `
variable "name" {}
module "bucket" {
  source = "../bucket"
  name   = var.name
}
`})
	unit := writeModule(t, root, "live/prod", map[string]string{"terragrunt.hcl": ""})

	e := New()
	e.SetTrackModuleInstances(true)
	resources, _, visited, err := e.EvaluateCall(context.Background(),
		syntheticCall(filepath.Join(unit, "terragrunt.hcl"), "../../modules/wrapper"),
		map[string]cty.Value{"name": cty.StringVal("nested")})
	require.NoError(t, err)

	bucket := findResource(t, resources, "aws_s3_bucket", "this")
	requireString(t, bucket.Attributes, "bucket", "nested")
	require.Equal(t, "module.terragrunt.module.bucket", bucket.ModuleAddress)
	require.Len(t, bucket.CallChain, 2)
	require.Equal(t, "terragrunt", bucket.CallChain[0].ModuleName)
	require.Equal(t, "bucket", bucket.CallChain[1].ModuleName)
	require.True(t, visited[wrapper])
	require.True(t, visited[child])
	require.Equal(t, map[string]string{
		"module.terragrunt":               wrapper,
		"module.terragrunt.module.bucket": child,
	}, instanceAddresses(e.TakeModuleInstances()))
}

func TestEvaluateCall_RemoteSourceUsesResolver(t *testing.T) {
	root := t.TempDir()
	fetched := writeModule(t, root, "cache/bucket", map[string]string{"main.tf": syntheticBucketModule})
	unit := writeModule(t, root, "live/prod", map[string]string{"terragrunt.hcl": ""})
	callerFile := filepath.Join(unit, "terragrunt.hcl")

	e := New()
	var gotSource, gotVersion, gotCaller, gotName string
	e.SetRemoteResolver(func(source, version, caller, name string) (string, string, bool) {
		gotSource, gotVersion, gotCaller, gotName = source, version, caller, name
		return fetched, fetched, true
	})
	call := syntheticCall(callerFile, "terraform-aws-modules/s3-bucket/aws")
	call.Version = "4.1.0"
	resources, _, visited, err := e.EvaluateCall(context.Background(), call,
		map[string]cty.Value{"name": cty.StringVal("remote")})
	require.NoError(t, err)

	requireString(t, findResource(t, resources, "aws_s3_bucket", "this").Attributes, "bucket", "remote")
	require.Equal(t, "terraform-aws-modules/s3-bucket/aws", gotSource)
	require.Equal(t, "4.1.0", gotVersion)
	require.Equal(t, callerFile, gotCaller)
	require.Equal(t, "terragrunt", gotName)
	require.True(t, visited[fetched])
}

func TestEvaluateCall_UnresolvedSourceIsNotEvaluated(t *testing.T) {
	root := t.TempDir()
	unit := writeModule(t, root, "live/prod", map[string]string{"terragrunt.hcl": ""})
	callerFile := filepath.Join(unit, "terragrunt.hcl")

	for name, call := range map[string]*SyntheticCall{
		"missing local dir":   syntheticCall(callerFile, "../../modules/missing"),
		"remote, no resolver": syntheticCall(callerFile, "git::https://example.invalid/m.git"),
		"no source":           syntheticCall(callerFile, ""),
	} {
		t.Run(name, func(t *testing.T) {
			resources, _, visited, err := New().EvaluateCall(context.Background(), call, nil)
			require.ErrorIs(t, err, ErrModuleNotEvaluated)
			require.Empty(t, resources)
			require.Empty(t, visited)
		})
	}
}

func TestEvaluateCall_CanceledContext(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "modules/bucket", map[string]string{"main.tf": syntheticBucketModule})
	unit := writeModule(t, root, "live/prod", map[string]string{"terragrunt.hcl": ""})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resources, _, visited, err := New().EvaluateCall(ctx,
		syntheticCall(filepath.Join(unit, "terragrunt.hcl"), "../../modules/bucket"), nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, resources)
	require.Empty(t, visited)
}
