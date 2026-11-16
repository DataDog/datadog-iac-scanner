/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const terragruntUnit = `terraform {
  source = "../modules/bucket"
  backend "s3" {}
}

inputs = {
  name = "logs"
  // dd-iac-scan ignore-line
  acl  = "public-read"
}

resource "aws_s3_bucket" "not_terraform" {}
`

// A Terragrunt file yields one empty document, so no rule matches its blocks,
// and keeps its ignore comments for findings attributed to it.
func TestParse_TerragruntFile(t *testing.T) {
	for _, path := range []string{"live/prod/terragrunt.hcl", "live/terragrunt.stack.hcl"} {
		t.Run(path, func(t *testing.T) {
			resolved, documents, ignoreLines, _, err := NewDefault().Parse(
				context.Background(), []byte(terragruntUnit), path, true, 15)
			require.NoError(t, err)
			require.Equal(t, []model.Document{{}}, documents)
			require.ElementsMatch(t, []int{8, 9}, ignoreLines)
			require.Equal(t, terragruntUnit, string(resolved))
		})
	}
}

func TestParse_TerragruntFileSyntaxError(t *testing.T) {
	_, _, _, _, err := NewDefault().Parse(context.Background(), []byte("inputs = {"), "terragrunt.hcl", true, 15)
	require.Error(t, err)
}
