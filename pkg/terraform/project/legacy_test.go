/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"context"
	"encoding/json"
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
	scan, err := model.Load(context.Background(), dir, &model.Options{})
	require.NoError(t, err)
	docs := legacyDocMaps(LegacyDocs(scan.Roots, LegacyOptions{
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
	}))
	return scan.Base, docs
}

func legacyDocMaps(docs []*LegacyDoc) []map[string]any {
	out := make([]map[string]any, len(docs))
	for i := range docs {
		out[i] = docs[i].Doc
	}
	return out
}

func docByID(docs []map[string]any, id string) map[string]any {
	for _, d := range docs {
		if d["id"] == id {
			return d
		}
	}
	return nil
}

// docWithIDPrefix is the document whose id starts with prefix.
func docWithIDPrefix(docs []map[string]any, prefix string) map[string]any {
	for _, d := range docs {
		if id, _ := d["id"].(string); strings.HasPrefix(id, prefix) {
			return d
		}
	}
	return nil
}

// TestLegacyValues pins the value the legacy view carries at one path of one
// document, where it has to match what the previous engine's documents held.
func TestLegacyValues(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		// doc is the id prefix of the document read.
		doc  string
		path []string
		want any
	}{
		{
			// The previous engine left a module's variables unset in its
			// written documents, so a try reading one stayed unknown.
			name: "module output try failing on a bound variable keeps its text",
			files: map[string]string{
				"main.tf": `
locals {
  src = { probe_source = "fire" }
}
module "m" {
  source = "./mod"
  in_val = local.src
}
`,
				"mod/main.tf": `
variable "in_val" {}
output "out_missing" {
  value = try(var.in_val.missing, { probe_source = "fire" })
}
`,
			},
			doc:  "id:mod/main.tf",
			path: []string{"output", "out_missing", "value"},
			want: `${try(var.in_val.missing, { probe_source = "fire" })}`,
		},
		{
			name: "module output try failing on a variable default answers from its fallback",
			files: map[string]string{
				"main.tf": `
module "m" {
  source = "./mod"
}
`,
				"mod/main.tf": `
variable "in_val" {
  default = { probe_source = "fire" }
}
output "out_missing" {
  value = try(var.in_val.missing, "fallback")
}
`,
			},
			doc:  "id:mod/main.tf",
			path: []string{"output", "out_missing", "value"},
			want: "fallback",
		},
		{
			name:  "variable type keyword keeps its written text",
			files: map[string]string{"main.tf": `variable "v" { type = string }`},
			doc:   "id:main.tf",
			path:  []string{"variable", "v", "type"},
			want:  "${string}",
		},
		{
			name:  "variable type constructor keeps its written text",
			files: map[string]string{"main.tf": `variable "v" { type = map(string) }`},
			doc:   "id:main.tf",
			path:  []string{"variable", "v", "type"},
			want:  "${map(string)}",
		},
		{
			// The previous engine's module instance documents kept for_each
			// as evaluated, narrowed to the instance's own element.
			name: "module instance keeps its for_each narrowed to the instance",
			files: map[string]string{
				"main.tf": `module "m" { source = "./mod" }`,
				"mod/main.tf": `
resource "aws_subnet" "s" {
  for_each = { a = "10.0.0.0/24", b = "10.0.1.0/24" }
  cidr     = each.value
}
`,
			},
			doc:  "id:mod/main.tf",
			path: []string{"resource", "aws_subnet", `s["b"]`, "for_each"},
			want: map[string]any{"b": "10.0.1.0/24"},
		},
		{
			name: "module instance keeps its count",
			files: map[string]string{
				"main.tf":     `module "m" { source = "./mod" }`,
				"mod/main.tf": `resource "aws_subnet" "s" { count = 2 }`,
			},
			doc:  "id:mod/main.tf",
			path: []string{"resource", "aws_subnet", "s[1]", "count"},
			want: int64(2),
		},
		{
			// A dynamic block whose collection does not resolve may generate
			// any number of blocks; the previous engine kept it as written.
			name: "dynamic block over an unknown collection keeps its written shape",
			files: map[string]string{"main.tf": `
resource "google_sql_database_instance" "i" {
  settings {
    dynamic "ip_configuration" {
      for_each = var.ip_configurations
      content {
        ipv4_enabled = false
      }
    }
  }
}
`},
			doc:  "id:main.tf",
			path: []string{"resource", "google_sql_database_instance", "i", "settings"},
			want: map[string]any{"dynamic": map[string]any{"ip_configuration": map[string]any{
				"for_each": "${var.ip_configurations}",
				"content":  map[string]any{"ipv4_enabled": false},
			}}},
		},
		{
			name:  "variable type written as a quoted string keeps its value",
			files: map[string]string{"main.tf": `variable "v" { type = " " }`},
			doc:   "id:main.tf",
			path:  []string{"variable", "v", "type"},
			want:  " ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, docs := legacy(t, tc.files)
			d := docWithIDPrefix(docs, tc.doc)
			require.NotNil(t, d)
			require.Equal(t, tc.want, get(d, tc.path...))
		})
	}
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

resource "google_storage_bucket" "special" {
  for_each = {
    "$${literal}"  = "dollar"
    "%%{template}" = "percent"
  }
  name = each.key
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
	special := get(doc, "resource", "google_storage_bucket").(map[string]any)
	require.Equal(t, "${literal}", special[`special["${literal}"]`].(map[string]any)["name"])
	require.Equal(t, "%{template}", special[`special["%{template}"]`].(map[string]any)["name"])

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

func TestLegacyNestedModuleKeepsKnownTagKeyWithUnknownValue(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"main.tf": `
variable "team" {}

module "parent" {
  source = "./parent"
  team   = var.team
}
`,
		"parent/main.tf": `
variable "team" {}

locals {
  tags = {
    team    = var.team
    literal = "$${local.not_a_dependency}"
  }
}

module "child" {
  source = "./child"
  tags   = local.tags
}
`,
		"parent/child/main.tf": `
variable "tags" {
  type = map(string)
  default = {}
}

locals {
  tags = merge({ terraform_managed = "true" }, var.tags)
}

resource "google_compute_instance" "vm" {
  labels = local.tags
}
`,
	})
	d := docWithIDPrefix(docs, "id:parent/child/main.tf\x00")
	require.NotNil(t, d)
	labels, ok := get(d, "resource", "google_compute_instance", "vm", "labels").(map[string]any)
	require.True(t, ok, "the nested module input should keep its map shape")
	_, ok = labels["team"]
	require.True(t, ok, "a known tag key remains present even when its value is unknown")
	require.Equal(t, "${local.not_a_dependency}", labels["literal"], "an escaped interpolation remains literal string data")
}

func TestLegacyNestedModulePreservesKnownJSONArgument(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"main.tf": `
module "bucket" {
  source = "./bucket"
  additional_statements = [{
    Principal = "*"
    Resource  = ["arn:aws:s3:::example/*"]
  }]
}
`,
		"bucket/main.tf": `
variable "additional_statements" {
  type    = list(any)
  default = []
}

resource "aws_s3_bucket" "bucket" {
  bucket = "example"
}

locals {
  default_statements = [{
    Principal = "*"
    Resource  = ["arn:aws:s3:::${aws_s3_bucket.bucket.bucket}/*"]
  }]
  all_statements = concat(local.default_statements, var.additional_statements)
  full_policy = {
    Statement = local.all_statements
  }
}

resource "aws_s3_bucket_policy" "bucket" {
  policy = jsonencode(local.full_policy)
}
`,
	})
	d := docWithIDPrefix(docs, "id:bucket/main.tf\x00")
	require.NotNil(t, d)
	policyText, ok := get(d, "resource", "aws_s3_bucket_policy", "bucket", "policy").(string)
	require.True(t, ok, "the legacy policy attribute should be a JSON string")
	var policy map[string]any
	require.NoError(t, json.Unmarshal([]byte(policyText), &policy))
	statements, ok := policy["Statement"].([]any)
	require.True(t, ok)
	require.Len(t, statements, 2)
	provided, ok := statements[1].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "*", provided["Principal"], "the provided argument survives list coercion, concatenation and JSON encoding")
}

func TestLegacyJSONExprDoesNotReuseDottedKeyCollision(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"main.tf": `
variable "dotted" {}
variable "nested" {}

resource "aws_iam_policy" "p" {
  policy = jsonencode({
    "a.b" = var.dotted
    a = { b = var.nested }
  })
}
`,
	})
	d := docByID(docs, "id:main.tf")
	require.NotNil(t, d)
	policyText, ok := get(d, "resource", "aws_iam_policy", "p", "policy").(string)
	require.True(t, ok)
	var policy map[string]any
	require.NoError(t, json.Unmarshal([]byte(policyText), &policy))
	require.Equal(t, testPlaceholder, policy["a.b"], "an ambiguous path must not reuse the nested leaf expression")
	require.Equal(t, testPlaceholder, get(policy, "a", "b"), "the nested leaf must not reuse the dotted key expression")
}

func TestLegacySkipsUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "a" "b" {}`), 0o600))
	scan, err := model.Load(context.Background(), dir, &model.Options{})
	require.NoError(t, err)
	docs := legacyDocMaps(LegacyDocs(scan.Roots, LegacyOptions{
		Base:   scan.Base,
		FileID: func(string) (string, bool) { return "", false },
	}))
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

// The model computes the document of a data source Terraform derives from its
// configuration (aws_iam_policy_document), replacing an unresolved part with
// the unknown marker; the legacy view keeps the interpolation text the
// previous engine carried, both for data source references and for resource
// references the view keeps unseen.
func TestLegacyKeepsDataDocumentReferenceText(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"main.tf": `
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "own_account" {
  statement {
    sid    = "EnableIAMUserPermissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "key_admin" {
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["${aws_kms_key.key.arn}"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "key" {
  policy = data.aws_iam_policy_document.own_account.json
}

resource "aws_kms_key" "other" {
  policy = data.aws_iam_policy_document.key_admin.json
}
`,
	})
	d := docByID(docs, "id:main.tf")
	resources := d["resource"].(map[string]any)
	keys := resources["aws_kms_key"].(map[string]any)
	own := keys["key"].(map[string]any)["policy"].(string)
	require.Contains(t, own, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
		"the own-account principal keeps the interpolation text the previous engine carried")
	other := keys["other"].(map[string]any)["policy"].(string)
	require.Contains(t, other, "${aws_kms_key.key.arn}",
		"a resource reference the view keeps unseen stays its source text")
}

// An undeclared .tfvars key still resolves: the previous engine merged every
// key the variable files define into its documents, while the model binds
// only the variables the module declares.
func TestLegacyResolvesUndeclaredRootVariable(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"main.tf": `
resource "aws_instance" "example" {
  ami              = "ami-005e54dee72cc1d00"
  instance_type    = "t2.micro"
  user_data_base64 = var.init_aws_cli
}
`,
		"terraform.tfvars": `init_aws_cli = "aGVsbG8="
`,
	})
	d := docByID(docs, "id:main.tf")
	res := d["resource"].(map[string]any)["aws_instance"].(map[string]any)["example"].(map[string]any)
	require.Equal(t, "aGVsbG8=", res["user_data_base64"])
}

// A reference to another block of the module keeps its source text in every
// position, the way the documents the published rules were written against
// carried it, while variables, locals and module inputs still resolve.
func TestLegacyKeepsReferenceText(t *testing.T) {
	_, docs := legacy(t, map[string]string{
		"main.tf": `
variable "tags" {
  type    = map(string)
  default = { env = "dev" }
}

locals {
  base = "b-"
}

data "aws_partition" "current" {}

resource "aws_s3_bucket" "b" {
  bucket = "bbb"
}

resource "aws_s3_bucket" "c" {
  bucket        = aws_s3_bucket.b.bucket
  arn           = "arn:${aws_s3_bucket.b.arn}"
  force_destroy = true

  versioning {
    enabled = true
  }
}

resource "aws_security_group" "sg" {
  ingress {
    security_groups = [aws_s3_bucket.b.id]
  }

  egress {
    description = missing_resource.x.description
  }
}

resource "aws_iam_policy" "p" {
  count  = 2
  name   = "p-${count.index}"
  policy = jsonencode({
    Resource = data.aws_partition.current.partition
  })
}

resource "aws_iam_role" "r" {
  for_each = var.tags
  name     = "r-${each.key}-${local.base}"
}

resource "aws_iam_role" "u" {
  name = "u-${var.absent}"
}

locals {
  alias = aws_s3_bucket.b.bucket
  label = local.base
}

resource "aws_s3_bucket" "d" {
  bucket        = local.alias
  force_destroy = true

  logging {
    target_bucket = aws_s3_bucket.b.id
  }

  outer {
    inner {
      value = aws_s3_bucket.b.bucket
    }
  }

  aliases = { alias = aws_s3_bucket.b.bucket }

  replication {
    role = "arn"
  }
  replication {
    role = "arn"
  }
  replication {
    role = aws_s3_bucket.b.bucket
  }
}

resource "aws_lb" "front" {
  subnets = [aws_subnet.web[count.index].id]
}

resource "aws_lb" "front2" {
  subnets = [aws_subnet.web[0].id]
}

resource "aws_instance" "src" {
  instance_type = "t2.micro"
  flag          = "fire"
}

resource "aws_subnet" "web" {
  cidr_block = "10.0.0.0/8"
}

resource "aws_s3_bucket" "e" {
  bucket = aws_instance.src.flag ? "safe" : "fire"
}

resource "aws_s3_bucket" "g" {
  bucket = format("%sSuffix", aws_subnet.web[count.index].id)
}

resource "aws_s3_bucket" "h" {
  bucket = try(var.in_val.missing, {a = 1})
}

module "mod" {
  source = "./mod"
  in_val = {}
}
`,
		"mod/main.tf": `variable "in_val" { type = any }

output "out" {
  value = try(var.in_val.missing, {a = 1})
}`,
	})
	doc := docByID(docs, "id:main.tf")
	require.NotNil(t, doc)

	buckets := get(doc, "resource", "aws_s3_bucket").(map[string]any)
	c := buckets["c"].(map[string]any)
	require.Equal(t, "${aws_s3_bucket.b.bucket}", c["bucket"], "a cross-resource reference stays its source text")
	require.Equal(t, "arn:${aws_s3_bucket.b.arn}", c["arn"], "the known part of a template is kept around the reference text")

	sg := get(doc, "resource", "aws_security_group", "sg", "ingress").(map[string]any)
	require.Equal(t, []any{"${aws_s3_bucket.b.id}"}, sg["security_groups"], "references inside collections keep their source text")
	require.Equal(t, "${missing_resource.x.description}", get(doc, "resource", "aws_security_group", "sg", "egress", "description"),
		"a nested attribute whose value evaluation could not resolve keeps its source text")

	policies := get(doc, "resource", "aws_iam_policy").(map[string]any)
	for _, key := range []string{"p[0]", "p[1]"} {
		p := policies[key].(map[string]any)
		require.Equal(t, "p-"+key[len(key)-2:len(key)-1], p["name"], "count.index still resolves")
		var policy map[string]any
		require.NoError(t, json.Unmarshal([]byte(p["policy"].(string)), &policy))
		require.Equal(t, "${data.aws_partition.current.partition}", policy["Resource"],
			"a reference inside jsonencode keeps its source text in the JSON value")
	}

	roles := get(doc, "resource", "aws_iam_role").(map[string]any)
	require.Equal(t, "r-env-b-", roles[`r["env"]`].(map[string]any)["name"], "each.key and locals still resolve")

	u := get(doc, "resource", "aws_iam_role", "u").(map[string]any)
	require.Equal(t, "u-${var.absent}", u["name"], "a variable with no value stays its source text, as main kept it")

	d := buckets["d"].(map[string]any)
	require.Equal(t, "${local.alias}", d["bucket"],
		"a local reading a block of the module stays out of the rendering context, so its consumer keeps the reference text")
	require.Equal(t, "${aws_s3_bucket.b.id}", get(d, "logging", "target_bucket"),
		"a reference two nested blocks deep keeps its source text")
	require.Equal(t, "${aws_s3_bucket.b.bucket}", get(d, "outer", "inner", "value"),
		"a fully known reference two nested blocks deep keeps its source text")
	require.Equal(t, map[string]any{"alias": "${aws_s3_bucket.b.bucket}"}, d["aliases"],
		"an object with a plain identifier key keeps its reference value")
	replications := d["replication"].([]any)
	require.Equal(t, "arn", replications[0].(map[string]any)["role"], "an element with no reference keeps its value")
	require.Equal(t, "${aws_s3_bucket.b.bucket}", replications[2].(map[string]any)["role"],
		"a later element holding a known reference keeps its source text")

	lb := get(doc, "resource", "aws_lb", "front").(map[string]any)
	require.Equal(t, []any{"${aws_subnet.web[count.index].id}"}, lb["subnets"],
		"an indexed selector reading count.index keeps its source text")
	require.Equal(t, "${aws_subnet.web[0].id}", get(doc, "resource", "aws_lb", "front2", "subnets").([]any)[0],
		"a known indexed reference keeps its source text")

	eBucket := buckets["e"].(map[string]any)
	require.Equal(t, "${aws_instance.src.flag ? \"safe\" : \"fire\"}", eBucket["bucket"],
		"a conditional over a known source value keeps its whole written text")

	gBucket := buckets["g"].(map[string]any)
	require.Equal(t, "${aws_subnet.web[count.index].id}Suffix", gBucket["bucket"],
		"an indexed reference inside a function argument keeps its source text in the placed part")

	hBucket := buckets["h"].(map[string]any)
	require.Equal(t, map[string]any{"a": int64(1)}, hBucket["bucket"],
		"a try whose reference argument errors answers from its fallback, as main evaluated it")

	mod := docWithIDPrefix(docs, "id:mod/main.tf")
	require.NotNil(t, mod)
	require.Equal(t, "${try(var.in_val.missing, {a = 1})}", get(mod, "output", "out", "value"),
		"a module output of a try falling back on a variable with no default keeps its text, as main kept it")

	locals, _ := doc["locals"].(map[string]any)
	require.Equal(t, "${aws_s3_bucket.b.bucket}", locals["alias"],
		"the locals section keeps the reference text of a local the view cannot resolve")
	require.Equal(t, "b-", locals["label"], "a chain of locals resolves through the local namespace")
}

func TestLegacyDynamicSourceAlignmentTracksExpansion(t *testing.T) {
	_, docs := legacy(t, map[string]string{"main.tf": `resource "example" "x" {
  dynamic "parent" {
    for_each = ["one", "two"]
    content {
      name = parent.value
      child {
        name = parent.value
        leaf { name = parent.value }
      }
    }
  }
  parent {
    name = "static"
    child { name = "static-child" }
  }
}`})
	d := docWithIDPrefix(docs, "id:main.tf")
	parent := get(d, "resource", "example", "x", "parent").([]any)
	require.Len(t, parent, 3)
	for i, want := range []string{"one", "two"} {
		child, ok := parent[i].(map[string]any)["child"].(map[string]any)
		require.True(t, ok, "parent[%d].child should keep the single-block object shape", i)
		leaf, ok := child["leaf"].(map[string]any)
		require.True(t, ok, "parent[%d].child.leaf should keep the single-block object shape", i)
		require.Equal(t, want, leaf["name"])
	}
	staticChild, ok := parent[2].(map[string]any)["child"].(map[string]any)
	require.True(t, ok, "the following static parent should keep its own singleton child")
	require.Equal(t, "static-child", staticChild["name"])
	require.NotContains(t, staticChild, "leaf")
}

func TestLegacyLifecycleMetadataIsPreservedPerInstance(t *testing.T) {
	_, docs := legacy(t, map[string]string{"main.tf": `resource "example" "x" {
  count = 2
  name = "x"
  lifecycle {
    prevent_destroy = true
    ignore_changes = [tags]
    precondition {
      condition = true
      error_message = "instance ${count.index}"
    }
  }
}`})
	d := docWithIDPrefix(docs, "id:main.tf")
	for i, key := range []string{"x[0]", "x[1]"} {
		resource := get(d, "resource", "example", key).(map[string]any)
		lifecycle := resource["lifecycle"].(map[string]any)
		require.Equal(t, true, lifecycle["prevent_destroy"])
		require.Equal(t, []any{"${tags}"}, lifecycle["ignore_changes"])
		precondition := lifecycle["precondition"].(map[string]any)
		require.Equal(t, fmt.Sprintf("instance %d", i), precondition["error_message"])
	}
}
