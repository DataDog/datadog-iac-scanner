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

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty/gocty"
)

func Test_getDataSourcePolicy_localAliasOfDataJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  base_json = data.aws_iam_policy_document.base.json
}
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "combined" {
  source_policy_documents = [local.base_json]
  statement {
    sid     = "Own"
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	var data map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(result["data"], &data))
	require.Equal(t,
		`{"Statement":[{"Actions":["sqs:*"],"Effect":"Allow","Sid":"Base"},{"Actions":["s3:GetObject"],"Effect":"Allow","Sid":"Own"}],"Version":"2012-10-17"}`+"\n",
		data["aws_iam_policy_document"]["combined"]["json"])
}

func Test_getDataSourcePolicy_localTryFallbackUpdatesWhenDataArrives(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  base_json = try(data.aws_iam_policy_document.base.json, data.aws_iam_policy_document.root.json)
}
data "aws_iam_policy_document" "root" {
  statement {
    sid     = "Root"
    actions = ["iam:GetUser"]
  }
}
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "combined" {
  source_policy_documents = [local.base_json]
  statement {
    sid     = "Own"
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	var data map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(result["data"], &data))
	require.Contains(t, data["aws_iam_policy_document"]["combined"]["json"], `"Sid":"Base"`)
	require.NotContains(t, data["aws_iam_policy_document"]["combined"]["json"], `"Sid":"Root"`)
}
