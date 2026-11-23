/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluateModule_SkipRootResourcesMatchesChildResults(t *testing.T) {
	t.Run("unreferenced root resource files are deferred and child modules match", func(t *testing.T) {
		root := t.TempDir()
		modDir := filepath.Join(root, "mod")
		require.NoError(t, os.MkdirAll(modDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(modDir, "main.tf"), []byte(`
variable "bucket_name" { type = string }
resource "aws_s3_bucket" "b" {
  bucket = var.bucket_name
}
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "storage" {
  source      = "./mod"
  bucket_name = "my-bucket"
}
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "resources.tf"), []byte(`
resource "aws_vpc" "unused" {
  cidr_block = "10.0.0.0/16"
}
`), 0o600))

		fullEval := New()
		fullRes, _, fullDirs, err := fullEval.EvaluateModule(context.Background(), root, nil)
		require.NoError(t, err)

		skipEval := New()
		skipEval.SetSkipRootResources(true)
		skipRes, _, skipDirs, err := skipEval.EvaluateModule(context.Background(), root, nil)
		require.NoError(t, err)

		var expectedChild []ResolvedResource
		for _, r := range fullRes {
			if r.ModuleAddress != "" {
				expectedChild = append(expectedChild, r)
			}
		}
		require.Equal(t, len(expectedChild), len(skipRes))
		require.Equal(t, expectedChild[0].Attributes["bucket"], skipRes[0].Attributes["bucket"])
		require.Equal(t, fullDirs, skipDirs)
	})

	t.Run("root resources referenced by a module call are still parsed and preinjected", func(t *testing.T) {
		root := t.TempDir()
		modDir := filepath.Join(root, "mod")
		require.NoError(t, os.MkdirAll(modDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(modDir, "main.tf"), []byte(`
variable "cidr" { type = string }
resource "aws_subnet" "s" {
  cidr_block = var.cidr
}
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "net" {
  source = "./mod"
  cidr   = aws_vpc.main.cidr_block
}
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "vpc.tf"), []byte(`
resource "aws_vpc" "main" {
  cidr_block = "10.42.0.0/16"
}
`), 0o600))

		skipEval := New()
		skipEval.SetSkipRootResources(true)
		skipRes, _, _, err := skipEval.EvaluateModule(context.Background(), root, nil)
		require.NoError(t, err)
		require.Len(t, skipRes, 1)
		require.Equal(t, "10.42.0.0/16", skipRes[0].Attributes["cidr_block"].AsString())
	})
}
