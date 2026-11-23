/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"context"
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/hclcache"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

func buildMultiRootTerraformFiles(roots int) map[string]string {
	files := map[string]string{
		"modules/bucket/variables.tf": `variable "bucket_name" {
  type = string
}
variable "acl" {
  type    = string
  default = "private"
}
`,
		"modules/bucket/main.tf": `resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  acl    = var.acl
}
`,
	}
	for i := range roots {
		prefix := fmt.Sprintf("stacks/env_%03d", i)
		files[prefix+"/variables.tf"] = fmt.Sprintf(`variable "env" {
  type    = string
  default = "env-%03d"
}
`, i)
		files[prefix+"/locals.tf"] = `locals {
  bucket_name = "logs-${var.env}"
}
`
		files[prefix+"/policy.tf"] = `data "aws_iam_policy_document" "read" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${local.bucket_name}/*"]
  }
}
`
		files[prefix+"/main.tf"] = `module "logs" {
  source      = "../../modules/bucket"
  bucket_name = local.bucket_name
  acl         = "public-read"
}

resource "aws_s3_bucket_policy" "read" {
  bucket = local.bucket_name
  policy = data.aws_iam_policy_document.read.json
}
`
		files[prefix+"/terraform.tfvars"] = fmt.Sprintf("env = \"prod-%03d\"\n", i)
	}
	return files
}

func TestTerraformScanParsesEachHCLFileOnce(t *testing.T) {
	files := buildMultiRootTerraformFiles(3)
	root := writeRepo(t, files)

	bucketRule := syntheticQuery("test-public-bucket", "terraform", "Terraform", `	input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].acl", [name])`)

	for _, modulesMode := range []TerraformModulesSetting{TerraformModulesOff, TerraformModulesOn} {
		t.Run("terraform_modules_"+string(modulesMode), func(t *testing.T) {
			params := terraformParams(root)
			params.TerraformModules = modulesMode

			cache := hclcache.New()
			ctx := hclcache.WithCache(context.Background(), cache)

			c, err := NewClient(ctx, params, &consolePrinter.Printer{})
			require.NoError(t, err)
			c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
				return &stubQuerySource{queries: []model.QueryMetadata{bucketRule}}, nil
			}

			results, err := c.executeScan(ctx)
			require.NoError(t, err)
			require.NotNil(t, results)
			require.Len(t, results.Results, 3, "each root's instantiated module resource should produce a finding")

			stats := cache.Stats()
			require.Equal(t, int64(len(files)), stats.Misses,
				"every HCL file (.tf and .tfvars) must be parsed at most once across modulegraph, legacy conversion, module discovery, and tfeval")
			require.Greater(t, stats.Hits, int64(len(files)*2),
				"subsequent scan phases should reuse cached HCL syntax trees")
			require.Equal(t, 0, stats.Entries,
				"shared HCL cache must be released before OPA query execution")
			require.Equal(t, int64(0), stats.LiveSourceBytes,
				"live source bytes must be zero after release")
		})
	}
}

func BenchmarkTerraformScanMultiRoot(b *testing.B) {
	files := buildMultiRootTerraformFiles(100)
	root := writeRepo(b, files)
	bucketRule := syntheticQuery("test-public-bucket", "terraform", "Terraform", `	input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].acl", [name])`)

	run := func(b *testing.B, maxCacheBytes int64) {
		b.Helper()
		b.ReportAllocs()
		for b.Loop() {
			params := terraformParams(root)
			params.TerraformModules = TerraformModulesOff
			cache := hclcache.NewWithMaxSourceBytes(maxCacheBytes)
			ctx := hclcache.WithCache(context.Background(), cache)
			c, err := NewClient(ctx, params, &consolePrinter.Printer{})
			require.NoError(b, err)
			c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
				return &stubQuerySource{queries: []model.QueryMetadata{bucketRule}}, nil
			}
			results, err := c.executeScan(ctx)
			require.NoError(b, err)
			require.Len(b, results.Results, 100)
		}
	}

	b.Run("shared_cache", func(b *testing.B) {
		run(b, hclcache.DefaultMaxSourceBytes)
	})
	b.Run("budget_capped_1B_uncached", func(b *testing.B) {
		run(b, 1)
	})
}
