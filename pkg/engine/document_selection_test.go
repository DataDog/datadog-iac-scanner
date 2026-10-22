/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

const selectionLibrary = `package generic.terraform

import rego.v1

has_target_resource(bucketName, resourceName) if {
	resource := input.document[i].resource[resourceName][_]
	split(resource.bucket, ".")[1] == bucketName
}

uses_everything if {
	count(input.document) > 0
}

pure(resource) := resource.name
`

func selectionOf(t *testing.T, query string) docSelector {
	t.Helper()
	mod, err := ast.ParseModuleWithOpts("lib", selectionLibrary, ast.ParserOptions{RegoVersion: ast.RegoV1})
	require.NoError(t, err)
	return querySelector(query, libraryFunctions(mod))
}

func selectedKeys(sel docSelector) []string {
	keys := make([]string, 0, len(sel.keys))
	for k := range sel.keys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestQuerySelector(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		all   bool
		keys  []string
	}{
		{
			name: "one block type, with the document id",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	not r.versioning
	result := {"documentId": input.document[i].id, "resourceName": name}
}`,
			keys: []string{"resource.aws_s3_bucket"},
		},
		{
			name: "a negated lookup of another type on any document",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	not input.document[_].resource.aws_s3_bucket_policy[name]
	result := {"documentId": input.document[i].id}
}`,
			keys: []string{"resource.aws_s3_bucket", "resource.aws_s3_bucket_policy"},
		},
		{
			name: "a document alias",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	doc := input.document[_]
	r := doc.data.aws_iam_policy_document[name]
	result := {"documentId": doc.id}
}`,
			keys: []string{"data.aws_iam_policy_document"},
		},
		{
			name: "iterating the documents with some",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some doc in input.document
	m := doc.module[name]
	result := {"documentId": doc.id}
}`,
			keys: []string{"module"},
		},
		{
			name: "a library function naming the type by a constant argument",
			query: `package datadog
import rego.v1
import data.generic.terraform as tf_lib
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	not tf_lib.has_target_resource(name, "aws_s3_bucket_public_access_block")
	result := {"documentId": input.document[i].id}
}`,
			keys: []string{"resource.aws_s3_bucket", "resource.aws_s3_bucket_public_access_block"},
		},
		{
			name: "a library function given a pure value",
			query: `package datadog
import rego.v1
import data.generic.terraform as tf_lib
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	tf_lib.pure(r) == "x"
	result := {"documentId": input.document[i].id}
}`,
			keys: []string{"resource.aws_s3_bucket"},
		},
		{
			name: "a whole document handed to a function, when it holds the type",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	doc := input.document[i]
	doc.resource.aws_s3_bucket[name]
	check(doc)
	result := {"documentId": input.document[i].id}
}
check(doc) if doc.resource.aws_s3_bucket_acl
`,
			keys: []string{"resource.aws_s3_bucket"},
		},
		{
			name: "a type held in a variable",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource[type][name]
	not r.tags
	result := {"documentId": input.document[i].id}
}`,
			keys: []string{"resource.*"},
		},
		{
			name: "the documents counted",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	count(input.document) > 1
	result := {"documentId": "x"}
}`,
			all: true,
		},
		{
			name: "a document picked by position",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	buckets := [name | input.document[_].resource.aws_s3_bucket[name]]
	count(buckets) >= 2
	result := {"documentId": input.document[0].id}
}`,
			all: true,
		},
		{
			name: "a document index used as a value",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	result := {"documentId": input.document[i].id, "position": i}
}`,
			all: true,
		},
		{
			name: "a whole document read without selecting it",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	doc := input.document[i]
	not doc.resource.aws_s3_bucket
	result := {"documentId": doc.id}
}`,
			// Reading the id requires nothing but a document.
			keys: []string{"id"},
		},
		{
			name: "a field picked by a variable on an unselected document",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some field
	input.document[i][field]
	result := {"documentId": "x"}
}`,
			all: true,
		},
		{
			name: "every document has to pass",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	every doc in input.document { doc.resource.aws_s3_bucket }
	result := {"documentId": "x"}
}`,
			all: true,
		},
		{
			name: "input handed to a builtin",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	walk(input, [path, value])
	value == "x"
	result := {"documentId": "x"}
}`,
			all: true,
		},
		{
			name: "a library rule reading every document",
			query: `package datadog
import rego.v1
import data.generic.terraform as tf_lib
DatadogPolicy contains result if {
	tf_lib.uses_everything
	r := input.document[i].resource.aws_s3_bucket[name]
	result := {"documentId": input.document[i].id}
}`,
			all: true,
		},
		{
			name: "a library function given a type that is not a constant",
			query: `package datadog
import rego.v1
import data.generic.terraform as tf_lib
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	some t in {"a", "b"}
	tf_lib.has_target_resource(name, t)
	result := {"documentId": input.document[i].id}
}`,
			all: true,
		},
		{
			name: "an unknown library rule",
			query: `package datadog
import rego.v1
import data.generic.terraform as tf_lib
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	tf_lib.not_defined(r)
	result := {"documentId": input.document[i].id}
}`,
			all: true,
		},
		{
			name: "input replaced with with",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	helper with input as {}
	result := {"documentId": input.document[i].id}
}
helper if true
`,
			all: true,
		},
		{
			name: "an unselected document read in a negation",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	not input.document[_].id == "x"
	result := {"documentId": "x"}
}`,
			keys: []string{"id"},
		},
		{
			name: "a selection inside a comprehension does not select the outer document",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	doc := input.document[i]
	names := [n | doc.resource.aws_s3_bucket[n]]
	result := {"documentId": "x", "names": names, "doc": doc}
}`,
			all: true,
		},
		{
			name: "input imported under another name",
			query: `package datadog
import rego.v1
import input.document as docs
DatadogPolicy contains result if {
	r := docs[i].resource.aws_s3_bucket[name]
	result := {"documentId": docs[i].id}
}`,
			all: true,
		},
		{
			name: "a document alias bound again in a comprehension",
			query: `package datadog
import rego.v1
DatadogPolicy contains result if {
	d := input.document[j]
	d.resource.aws_s3_bucket[_]
	ids := [x | d := input.document[i]; x := d.id]
	input.document[i].id == "x"
	result := {"documentId": "x", "ids": ids}
}`,
			all: true,
		},
		{
			name: "an unparsable query",
			query: `package datadog
DatadogPolicy contains result if {`,
			all: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel := selectionOf(t, tc.query)
			require.Equal(t, tc.all, sel.all)
			if !tc.all {
				require.Equal(t, tc.keys, selectedKeys(sel))
			}
		})
	}
}

func TestDocumentKeys(t *testing.T) {
	doc := ast.MustParseTerm(`{
		"id": "a", "file": "main.tf",
		"resource": {"aws_s3_bucket": {"b": {}}, "kafka_acl": {"k": {}}},
		"data": {},
		"module": {"m": {}}
	}`).Value.(ast.Object)
	keys := documentKeys(doc)
	sort.Strings(keys)
	require.Equal(t, []string{
		"data", "file", "id", "module", "resource", "resource.*", "resource.aws_s3_bucket", "resource.kafka_acl",
	}, keys)
}

// Rules handed only the documents they select report what they report given
// every document, inside and outside modules.
func TestInspect_DocumentSelectionKeepsFindings(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) string {
		path := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		return path
	}
	stack := write("stack/main.tf", `
module "buckets" {
  source   = "../modules/buckets"
  for_each = toset(["a", "b", "c"])
  name     = each.key
}
resource "aws_s3_bucket" "inline" {
  bucket = "inline"
}
resource "aws_s3_bucket_policy" "inline" {
  bucket = "inline"
}
`)
	mod := write("modules/buckets/main.tf", `
variable "name" { type = string }
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "${var.name}-${count.index}"
  acl    = count.index == 1 ? "public-read" : "private"
}
resource "kafka_acl" "k" {
  resource_name = var.name
}
data "aws_iam_policy_document" "p" {
  statement { actions = ["s3:*"] }
}
`)
	rules := map[string]string{
		"typed": `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	r.acl == "public-read"
	result := {"documentId": input.document[i].id, "resourceType": "aws_s3_bucket", "resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name])}
}`,
		"no_policy_anywhere": `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource.aws_s3_bucket[name]
	not has_policy(r.bucket)
	result := {"documentId": input.document[i].id, "resourceType": "aws_s3_bucket", "resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name])}
}
has_policy(bucket) if input.document[_].resource.aws_s3_bucket_policy[_].bucket == bucket
`,
		"counted": `package datadog
import rego.v1
DatadogPolicy contains result if {
	count([n | input.document[_].resource.kafka_acl[n]]) >= 1
	some i
	input.document[i].resource.kafka_acl[name]
	result := {"documentId": input.document[i].id, "resourceType": "kafka_acl", "resourceName": name,
		"searchKey": sprintf("kafka_acl[%s]", [name]), "position": i}
}`,
		"any_type": `package datadog
import rego.v1
DatadogPolicy contains result if {
	r := input.document[i].resource[type][name]
	not r.tags
	result := {"documentId": input.document[i].id, "resourceType": type, "resourceName": name,
		"searchKey": sprintf("%s[%s]", [type, name])}
}`,
		"data_block": `package datadog
import rego.v1
DatadogPolicy contains result if {
	d := input.document[i].data.aws_iam_policy_document[name]
	d.statement.actions[_] == "s3:*"
	result := {"documentId": input.document[i].id, "resourceType": "aws_iam_policy_document", "resourceName": name,
		"searchKey": sprintf("data.aws_iam_policy_document[%s].statement.actions", [name])}
}`,
		"module_call": `package datadog
import rego.v1
DatadogPolicy contains result if {
	m := input.document[i].module[name]
	m.source == "../modules/buckets"
	result := {"documentId": input.document[i].id, "resourceType": "module", "resourceName": name,
		"searchKey": sprintf("module[%s]", [name])}
}`,
	}
	var queries []model.QueryMetadata
	for name, content := range rules {
		queries = append(queries, model.QueryMetadata{
			Query: name, Content: content, InputData: "{}", Platform: "terraform", Aggregation: 1,
			Metadata: map[string]interface{}{"id": name, "platform": "Terraform"},
		})
	}
	sort.Slice(queries, func(i, j int) bool { return queries[i].Query < queries[j].Query })

	scan := func(disable bool) []string {
		var files model.FileMetadatas
		files = append(files, parseTerraform(t, stack)...)
		files = append(files, parseTerraform(t, mod)...)
		ins := newTestInspector(t, inspectorOpts{
			queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder,
			flagEvaluator: featureflags.NewLocalEvaluator(),
		})
		ins.disableDocumentSelection = disable
		vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, ins.GetFailedQueries())
		var out []string
		for i := range vulns {
			v := vulns[i]
			out = append(out, fmt.Sprintf("%s %s %s %s %d %s", v.QueryID, v.ModuleCallChain, v.ResourceType, v.ResourceName,
				v.Line, v.SearchKey))
		}
		sort.Strings(out)
		return out
	}
	everything := scan(true)
	selected := scan(false)
	require.NotEmpty(t, everything)
	require.Equal(t, everything, selected)

	ins := newTestInspector(t, inspectorOpts{queries: queries})
	selectors := ins.QueryLoader.querySelectors(queries)
	byName := map[string]docSelector{}
	for i := range queries {
		byName[queries[i].Query] = selectors[i]
	}
	require.True(t, byName["counted"].all, "a rule reading a document's position reads them all")
	for _, name := range []string{"typed", "no_policy_anywhere", "any_type", "data_block", "module_call"} {
		require.False(t, byName[name].all, name)
	}
}
