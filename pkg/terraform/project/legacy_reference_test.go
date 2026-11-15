/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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

	var mod map[string]any
	for _, d := range docs {
		if id, _ := d["id"].(string); strings.HasPrefix(id, "id:mod/main.tf") {
			mod = d
		}
	}
	require.NotNil(t, mod)
	require.Equal(t, map[string]any{"a": int64(1)}, get(mod, "output", "out", "value"),
		"the module output of a try over a known module input answers from its fallback, as main evaluated a same-module try")

	e := buckets["e"].(map[string]any)
	require.Equal(t, "${aws_instance.src.flag ? \"safe\" : \"fire\"}", e["bucket"],
		"a conditional reading a block of the module keeps its whole written text")

	g := buckets["g"].(map[string]any)
	require.Contains(t, g["bucket"], "aws_subnet.web[count.index]",
		"an indexed reference inside a function argument keeps its source text")

	locals, _ := doc["locals"].(map[string]any)
	require.Equal(t, "${aws_s3_bucket.b.bucket}", locals["alias"],
		"the locals section keeps the reference text of a local the view cannot resolve")
	require.Equal(t, "b-", locals["label"], "a chain of locals resolves through the local namespace")
}
