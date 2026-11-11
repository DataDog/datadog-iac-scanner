/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/open-policy-agent/regal/pkg/linter"
	"github.com/open-policy-agent/regal/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const terraformQueryHeader = `package datadog

import rego.v1

import data.generic.common as common

import data.generic.terraform as tf
`

// lintContract returns the "title level row" of each violation of the
// contract category in content, read from file.
func lintContract(t *testing.T, file, content string) []string {
	t.Helper()
	ctx := context.Background()
	prepared, err := linter.NewLinter().
		WithCustomRulesFromFS(regalRulesFS, "regalrules").
		WithDisableAll(true).
		WithEnabledCategories("contract").
		Prepare(ctx)
	require.NoError(t, err)
	input, err := rules.InputFromText(file, content)
	require.NoError(t, err)
	res, err := prepared.WithInputModules(&input).Lint(ctx)
	require.NoError(t, err)
	out := make([]string, 0, len(res.Violations))
	for i := range res.Violations {
		v := &res.Violations[i]
		assert.Equal(t, "contract", v.Category)
		out = append(out, fmt.Sprintf("%s %s %d", v.Title, v.Level, v.Location.Row))
	}
	sort.Strings(out)
	return out
}

func TestRegalContractRules(t *testing.T) {
	const query = "queries/terraform/aws/rule/query.rego"
	for _, tc := range []struct {
		name, file, body string
		want             []string
	}{
		{
			name: "contract rule",
			file: query,
			body: `
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	some i, rule in tf.nested(b, "rule")
	count(tf.related(b, "aws_s3_bucket_versioning", "bucket")) == 0
	walk(rule.filter, [_, v])
	result := common.finding(b, ["rule", i], {"key": v})
}
`,
		},
		{
			name: "internal fields",
			file: query,
			body: `
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	b._dd_meta.kind == "resource"
	object.get(input, "_dd", {}) != {}
	result := {"_dd_id": b.id, "path": []}
}
`,
			want: []string{
				"bound-finding error 13", "internal-fields error 11", "internal-fields error 12", "internal-fields error 13",
			},
		},
		{
			name: "unknown placeholder",
			file: query,
			body: `
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	b.acl != "\u0000dd-unknown-1234"
	not startswith(b.acl, "dd-unknown")
	count(split(b.id, "\u0000")) == 1
	result := common.finding(b, ["acl"], {})
}
`,
			want: []string{"unknown-placeholder error 11", "unknown-placeholder error 12"},
		},
		{
			name: "input document in a Terraform rule",
			file: "query.rego",
			body: `
DatadogPolicy contains result if {
	some doc in input.document
	b := doc.resource.aws_s3_bucket[_]
	result := common.finding(b, [], {})
}
`,
			want: []string{"input-document error 10"},
		},
		{
			name: "input document in a rule of another platform",
			file: "queries/dockerfile/rule/query.rego",
			body: `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	result := {"documentId": doc.id, "searchKey": "FROM"}
}
`,
		},
		{
			name: "contains common.finding",
			file: query,
			body: `
DatadogPolicy contains common.finding(b, ["acl"], {}) if {
	some b in tf.blocks("aws_s3_bucket")
}
`,
			want: []string{"bound-finding error 9"},
		},
		{
			name: "legacy result object",
			file: query,
			body: `
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	result := {"documentId": "d", "searchKey": "s", "resourceType": "t", "resourceName": "n"}
}
`,
			want: []string{"bound-finding error 11"},
		},
		{
			name: "tf.finding",
			file: query,
			body: `
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	result := tf.finding(b, ["acl"], {})
}

helper(b) := data.generic.terraform.finding(b, [], {})
`,
			want: []string{"terraform-finding error 11", "terraform-finding error 14"},
		},
		{
			name: "nested tf.blocks loops",
			file: query,
			body: `
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	v := tf.blocks("aws_s3_bucket_versioning")[_]
	v.bucket == b.id
	result := common.finding(b, [], {})
}

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	count([p | some _, p in tf.data_blocks("aws_iam_policy_document"); p.bucket == b.id]) == 0
	result := common.finding(b, [], {})
}

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	count(tf.blocks("aws_cloudtrail")) == 0
	result := common.finding(b, [], {})
}
`,
			want: []string{"nested-blocks-loop warning 11", "nested-blocks-loop warning 18"},
		},
		{
			name: "walk over a block",
			file: query,
			body: `
DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	walk(b, [path, _])
	result := common.finding(b, path, {})
}

DatadogPolicy contains result if {
	p := tf.first(tf.data_blocks("aws_iam_policy_document"))
	[_, v] := walk(p)
	result := common.finding(p, [], {"key": v})
}

DatadogPolicy contains result if {
	walk(input, [_, v])
	result := common.finding(v, [], {})
}
`,
			want: []string{"walk-block error 11", "walk-block error 17", "walk-block error 22"},
		},
		{
			name: "library",
			file: "libraries/terraform.rego",
			body: `package generic.terraform

import rego.v1

blocks(type) := object.get(input._dd, ["blocks", "resource", type], [])

finding(block, path, details) := object.union(details, {"_dd_id": block._dd_meta.id, "path": path})

walked(b) := [v | walk(b, [_, v])]
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := tc.body
			if content[0] == '\n' {
				content = terraformQueryHeader + content
			}
			got := lintContract(t, tc.file, content)
			if len(tc.want) == 0 {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// The contract rules check the default rules in their repository; custom rule
// validation only reports the datadog category.
func TestValidate_IgnoresContractRules(t *testing.T) {
	errs := ValidateRegoStructure(terraformQueryHeader + `
DatadogPolicy contains result if {
	some doc in input.document
	result := {"documentId": doc.id, "searchKey": "s", "resourceType": "t", "resourceName": "n", "x": "_dd_meta"}
}
`)
	for _, e := range errs {
		assert.NotContains(t, e.Code, "contract/")
	}
}
