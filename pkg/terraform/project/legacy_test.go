/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/stretchr/testify/require"
)

func legacy(t *testing.T, files map[string]string) (string, []map[string]any) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	docs := Legacy(scan.Roots, LegacyOptions{
		Base:        scan.Base,
		Placeholder: testPlaceholder,
		FileID: func(path string) (string, bool) {
			rel, err := filepath.Rel(scan.Base, path)
			if err != nil {
				return "", false
			}
			rel = filepath.ToSlash(rel)
			_, ok := files[rel]
			return "id:" + rel, ok
		},
	})
	return scan.Base, docs
}

func docByID(docs []map[string]any, id string) map[string]any {
	for _, d := range docs {
		if d["id"] == id {
			return d
		}
	}
	return nil
}

func TestJoinRootKeepsTheBaseSeparator(t *testing.T) {
	require.Equal(t, "infra/main.tf", JoinRoot("infra", "main.tf"))
	require.Equal(t, "infra/mod/main.tf", JoinRoot("infra", "mod/main.tf"))
	require.Equal(t, "/ws/pkg/main.tf", JoinRoot("/ws/repo", "../pkg/main.tf"))
	require.Equal(t, filepath.Join(`C:\repo\infra`, "mod", "main.tf"), JoinRoot(`C:\repo\infra`, "mod/main.tf"))
	require.Equal(t, "/ws/pkg/main.tf", JoinRoot("/ws/repo", "../pkg/main.tf"))
	require.Equal(t, "C:/ws/pkg/main.tf", JoinRoot("C:/ws/repo", "../pkg/main.tf"))
}

func TestLegacyResourceShape(t *testing.T) {
	base, docs := legacy(t, map[string]string{
		"main.tf": `
variable "acl" {
  type    = string
  default = "private"
}

locals {
  env = "prod"
}

provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "west"
  region = "us-west-2"
}

resource "aws_s3_bucket" "b" {
  bucket = "b-${local.env}"
  acl    = var.acl
  count  = 2

  versioning {
    enabled = true
  }
}

resource "aws_security_group" "sg" {
  ingress {
    from_port = 22
  }
  ingress {
    from_port = 443
  }
}
`,
	})
	require.Len(t, docs, 1)
	doc := docByID(docs, "id:main.tf")
	require.NotNil(t, doc)
	require.Equal(t, filepath.Join(base, "main.tf"), doc["file"])

	buckets := get(doc, "resource", "aws_s3_bucket").(map[string]any)
	require.Len(t, buckets, 2, "one entry per instance")
	require.Contains(t, buckets, "b[1]")
	bucket := buckets["b[0]"].(map[string]any)
	require.Equal(t, "b-prod", bucket["bucket"])
	require.Equal(t, "private", bucket["acl"])
	require.NotContains(t, bucket, "count")
	require.Equal(t, map[string]any{"enabled": true}, bucket["versioning"])

	ingress := get(doc, "resource", "aws_security_group", "sg", "ingress").([]any)
	require.Len(t, ingress, 2)
	require.Equal(t, int64(443), ingress[1].(map[string]any)["from_port"])

	require.Equal(t, "private", get(doc, "variable", "acl", "default"))
	require.Equal(t, "prod", get(doc, "locals", "env"))
	providers, ok := get(doc, "provider", "aws").([]any)
	require.True(t, ok)
	require.Len(t, providers, 2)
}

func TestLegacyUnknownAndModules(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"main.tf": `
variable "kms" {}

resource "aws_s3_bucket" "b" {
  kms_key_id = var.kms
}

module "m" {
  source = "./mod"
  name   = "x"
}
`,
		"mod/main.tf": `
variable "name" {}

resource "aws_s3_bucket" "inner" {
  bucket = var.name
}
`,
	})
	root := docByID(docs, "id:main.tf")
	require.NotNil(t, root)
	require.Equal(t, "${var.kms}", get(root, "resource", "aws_s3_bucket", "b", "kms_key_id"))
	require.Nil(t, get(root, "module", "m"), "a local call is read through the module's own document")

	var mod map[string]any
	for _, d := range docs {
		if id, _ := d["id"].(string); strings.HasPrefix(id, "id:mod/main.tf\x00") {
			mod = d
		}
	}
	require.NotNil(t, mod)
	require.Equal(t, "x", get(mod, "resource", "aws_s3_bucket", "inner", "bucket"))
}

func TestLegacySkipsUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "a" "b" {}`), 0o600))
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	docs := Legacy(scan.Roots, LegacyOptions{
		Base:   scan.Base,
		FileID: func(string) (string, bool) { return "", false },
	})
	require.Empty(t, docs)
}

func TestLegacyReportsModuleVariablesOnceAcrossRoots(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"a/main.tf": `
module "m" {
  source = "../mod"
  name   = "a"
}
`,
		"b/main.tf": `
module "m" {
  source = "../mod"
  name   = "b"
}
`,
		"mod/main.tf": `
variable "name" {}
resource "aws_s3_bucket" "inner" { bucket = var.name }
`,
	})
	var vars, resources int
	for _, d := range docs {
		if get(d, "variable", "name") != nil {
			vars++
		}
		if get(d, "resource", "aws_s3_bucket", "inner") != nil {
			resources++
		}
	}
	require.Equal(t, 1, vars, "the module variable is written once")
	require.Equal(t, 2, resources, "each root still gets its own resource instance")
}

func TestLegacyCloudWatchFilterKeepsNormalizedPattern(t *testing.T) {
	pattern := `{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) }`
	_, docs := legacy(t, map[string]string{
		"main.tf": fmt.Sprintf(`
resource "aws_cloudwatch_log_metric_filter" "cis" {
  count          = 1
  name           = "CIS"
  pattern        = %q
  log_group_name = "lg"
  metric_transformation {
    name      = "CIS"
    namespace = "ns"
    value     = "1"
  }
}
`, pattern),
	})
	require.NotEmpty(t, docs)
	doc := docs[0]
	resources, _ := doc["resource"].(map[string]any)
	filters, _ := resources["aws_cloudwatch_log_metric_filter"].(map[string]any)
	require.NotEmpty(t, filters)
	inst, _ := filters["cis[0]"].(map[string]any)
	got, _ := inst["pattern"].(string)
	require.Contains(t, got, "_dd_filter_expr")
	require.NotEqual(t, pattern, got)
}
