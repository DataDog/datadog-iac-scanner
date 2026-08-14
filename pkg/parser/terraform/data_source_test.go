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

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

func Test_getDataSourcePolicy(t *testing.T) {
	type args struct {
		currentPath  string
		resourceName string
		inputVars    converter.VariableMap // nil means empty map
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "should load data source as json without errors 1",
			args: args{
				currentPath:  filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_data_source"),
				resourceName: "test_destination_policy",
			},
			want: `{"Statement":[{"Actions":["logs:*"],"Effect":"Allow","Principals":{"AWS":["data.aws_caller_identity.current.id"]}}]}
`,
		},
		{
			name: "should load data source as json without errors 2",
			args: args{
				currentPath:  filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_data_source"),
				resourceName: "test_example",
			},
			want: `{"Id":"lala","Statement":[{"Actions":["s3:ListAllMyBuckets","s3:GetBucketLocation"],"Resources":["arn:aws:s3:::*"],"Sid":"1"},{"Actions":["s3:ListBucket"],"Condition":{"StringLike":{"s3:prefix":["","home/","home/&{aws:username}/"]}},"Resources":["arn:aws:s3:::test"]},{"Actions":["s3:*"],"Resources":["arn:aws:s3:::test/home/&{aws:username}","arn:aws:s3:::test/home/&{aws:username}/*"]}]}
`,
		},
		{
			// "var" present but no default: raises "Unsupported attribute".
			name: "should not drop policy when scalar fields reference variables with no default (production var context)",
			args: args{
				currentPath:  filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_data_source_unknown_vars"),
				resourceName: "partial_unknowns",
				inputVars:    converter.VariableMap{"var": cty.EmptyObjectVal},
			},
			want: `{"Statement":[{"Actions":["s3:GetObject"],"Effect":"Allow","Resources":["arn:aws:s3:::my-bucket/*"]}]}
`,
		},
		{
			// "var" absent entirely: raises "Unknown variable".
			name: "should not drop policy when scalar fields reference variables with no var context",
			args: args{
				currentPath:  filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_data_source_unknown_vars"),
				resourceName: "partial_unknowns",
			},
			want: `{"Statement":[{"Actions":["s3:GetObject"],"Effect":"Allow","Resources":["arn:aws:s3:::my-bucket/*"]}]}
`,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputVars := tt.args.inputVars
			if inputVars == nil {
				inputVars = make(converter.VariableMap)
			}
			result := getDataSourcePolicy(ctx, vfs.DiskFS{}, tt.args.currentPath, inputVars)
			data, ok := result["data"]
			if !ok {
				t.FailNow()
			}
			var awsPolicyMap map[string]map[string]map[string]string
			err := gocty.FromCtyValue(data, &awsPolicyMap)
			if err != nil {
				t.Errorf("getDataSourcePolicy() error = %v", err)
			}
			got, ok := awsPolicyMap["aws_iam_policy_document"][tt.args.resourceName]["json"]
			if !ok {
				t.FailNow()
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_getDataSourcePolicy_ignoresFilesWithoutPolicyDocuments(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	writeFile("no_policy.tf", `
resource "aws_s3_bucket" "bucket" {
  bucket = "example"
}

data "aws_caller_identity" "current" {}
`)
	writeFile("policy.tf", `
data "aws_iam_policy_document" "doc" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example/*"]
  }
}
`)

	result := getDataSourcePolicy(context.Background(), vfs.DiskFS{}, dir, make(converter.VariableMap))
	data, ok := result["data"]
	require.True(t, ok, "expected a data entry in the variable map")

	var awsPolicyMap map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(data, &awsPolicyMap))

	policies := awsPolicyMap["aws_iam_policy_document"]
	require.Len(t, policies, 1, "only the declared policy document should be collected")
	require.Equal(t,
		"{\"Statement\":[{\"Actions\":[\"s3:GetObject\"],\"Resources\":[\"arn:aws:s3:::example/*\"]}]}\n",
		policies["doc"]["json"],
	)
}

func Test_getDataSourcePolicy_noPolicyDocumentsInDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_s3_bucket" "bucket" {
  bucket = "example"
}
`), 0o600))

	result := getDataSourcePolicy(context.Background(), vfs.DiskFS{}, dir, make(converter.VariableMap))
	data, ok := result["data"]
	require.True(t, ok, "expected a data entry even when no policies are declared")

	var awsPolicyMap map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(data, &awsPolicyMap))
	require.Empty(t, awsPolicyMap["aws_iam_policy_document"])
}

func Test_getDataSourcePolicy_arnWithDataPartitionReference(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "positive.tf"), []byte(`
data "aws_iam_policy_document" "glue-example-policy" {
  statement {
    actions = ["glue:*"]
    resources = ["arn:data.aws_partition.current.partition:glue:data.aws_region.current.name:data.aws_caller_identity.current.account_id:*"]
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
  }
}

resource "aws_glue_resource_policy" "example" {
  policy = data.aws_iam_policy_document.glue-example-policy.json
}
`), 0o600))

	result := getDataSourcePolicy(context.Background(), vfs.DiskFS{}, dir, make(converter.VariableMap))
	data, ok := result["data"]
	require.True(t, ok)

	var awsPolicyMap map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(data, &awsPolicyMap))

	policy, ok := awsPolicyMap["aws_iam_policy_document"]["glue-example-policy"]["json"]
	require.True(t, ok, "policy document should be parsed despite data.aws_partition in ARN")
	require.Contains(t, policy, "glue:*")
}

func Test_getDataSourcePolicy_whitespaceInBlockHeader(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.tf"), []byte(`
data	"aws_iam_policy_document"	"doc" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example/*"]
  }
}
`), 0o600))

	result := getDataSourcePolicy(context.Background(), vfs.DiskFS{}, dir, make(converter.VariableMap))
	data, ok := result["data"]
	require.True(t, ok)

	var awsPolicyMap map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(data, &awsPolicyMap))

	policies := awsPolicyMap["aws_iam_policy_document"]
	require.Contains(t, policies, "doc")
	require.Contains(t, policies["doc"]["json"], "s3:GetObject")
}
