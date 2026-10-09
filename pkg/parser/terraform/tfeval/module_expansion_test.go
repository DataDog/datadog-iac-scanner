/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func bucketModule(t *testing.T, root string) string {
	t.Helper()
	return writeModule(t, root, "bucket", map[string]string{
		"main.tf": `
variable "name" {}
variable "encrypt" { default = true }
resource "aws_s3_bucket" "this" {
  bucket    = var.name
  encrypted = var.encrypt
}
output "name" { value = aws_s3_bucket.this.bucket }
`,
	})
}

func TestEvaluateModule_ExpandsModuleForEach(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "buckets" {
  source   = "../bucket"
  for_each = {
    prod = { encrypt = true }
    dev  = { encrypt = false }
  }
  name    = "bucket-${each.key}"
  encrypt = each.value.encrypt
}

module "logs" {
  source = "../bucket"
  name   = "${module.buckets["prod"].name}-logs"
}
`,
	})

	e := New()
	e.SetTrackModuleInstances(true)
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	byAddr := resourcesByAddress(resources)
	prod, ok := byAddr[`module.buckets["prod"]/aws_s3_bucket.this`]
	require.True(t, ok, "instances are addressed by their for_each key: %v", byAddr)
	requireString(t, prod.Attributes, "bucket", "bucket-prod")
	require.True(t, prod.Attributes["encrypted"].True())

	dev := byAddr[`module.buckets["dev"]/aws_s3_bucket.this`]
	requireString(t, dev.Attributes, "bucket", "bucket-dev")
	require.True(t, dev.Attributes["encrypted"].False(), "each.value must reach the instance's inputs")

	requireString(t, byAddr["module.logs/aws_s3_bucket.this"].Attributes, "bucket", "bucket-prod-logs")

	addresses := make([]string, 0)
	for _, instance := range e.TakeModuleInstances() {
		addresses = append(addresses, instance.ModuleAddress)
	}
	sort.Strings(addresses)
	require.Equal(t, []string{`module.buckets["dev"]`, `module.buckets["prod"]`, "module.logs"}, addresses)
}

func TestEvaluateModule_ExpandsModuleCount(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
variable "enabled" { default = false }

module "replicas" {
  source = "../bucket"
  count  = 2
  name   = "replica-${count.index}"
}

module "disabled" {
  source = "../bucket"
  count  = var.enabled ? 1 : 0
  name   = "never"
}

output "second" { value = module.replicas[1].name }
output "replica_count" { value = length(module.replicas) }
`,
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	byAddr := resourcesByAddress(resources)
	require.Len(t, byAddr, 2)
	requireString(t, byAddr["module.replicas[0]/aws_s3_bucket.this"].Attributes, "bucket", "replica-0")
	requireString(t, byAddr["module.replicas[1]/aws_s3_bucket.this"].Attributes, "bucket", "replica-1")

	require.True(t, outputs["second"].RawEquals(cty.StringVal("replica-1")), "second = %#v", outputs["second"])
	require.True(t, outputs["replica_count"].RawEquals(cty.NumberIntVal(2)), "replica_count = %#v", outputs["replica_count"])
}

func TestEvaluateModule_UnknownModuleExpansionEvaluatesOnce(t *testing.T) {
	root := t.TempDir()
	bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
variable "names" {}

module "buckets" {
  source   = "../bucket"
  for_each = var.names
  name     = each.key
  encrypt  = false
}

output "names" { value = module.buckets }
`,
	})

	resources, outputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)

	require.Len(t, resources, 1)
	require.Equal(t, "module.buckets", resources[0].ModuleAddress)
	require.False(t, resources[0].Attributes["bucket"].IsKnown())
	require.True(t, resources[0].Attributes["encrypted"].False())
	require.False(t, outputs["names"].IsKnown(), "outputs of an unexpanded call are unknown")
}

func TestEvaluateModule_TruncatedModuleCountKeepsModuleScanned(t *testing.T) {
	root := t.TempDir()
	bucket := bucketModule(t, root)
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "many" {
  source = "../bucket"
  count  = 12
  name   = "b-${count.index}"
}
`,
	})

	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, maxCountExpansion)

	abs, err := filepath.Abs(bucket)
	require.NoError(t, err)
	require.Contains(t, e.NotEvaluatedDirs(), abs)
}
