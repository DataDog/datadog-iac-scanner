/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const scopeTestLibrary = `package generic.terraform

import rego.v1

has_association(name) if {
	some doc in input.document
	doc.resource.azurerm_subnet_network_security_group_association[_].subnet_id == name
}

is_public(acl) if acl == "public-read"

bucket_names(doc) := {name | some name, _ in doc.resource.aws_s3_bucket}

threshold := input.arguments.threshold
`

func TestRuleDocumentScope(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		joining bool
	}{
		{"single loop", `
DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	tf_lib.is_public(resource.acl)
	input.document[i].resource.aws_s3_bucket[name].versioning
	result := {"documentId": input.document[i].id, "resourceName": name}
}`, false},
		{"single some in loop", `
DatadogPolicy contains result if {
	some doc in input.document
	some name, s in doc.resource.azurerm_subnet
	result := {"documentId": doc.id, "resourceName": name, "s": s}
}`, false},
		{"library function given the document", `
DatadogPolicy contains result if {
	some doc in input.document
	some name in tf_lib.bucket_names(doc)
	result := {"documentId": doc.id, "resourceName": name}
}`, false},
		{"comprehension over the iterated document", `
DatadogPolicy contains result if {
	some i
	input.document[i].resource.aws_s3_bucket
	names := {n | some n, _ in input.document[i].resource.aws_s3_bucket}
	count(names) > 1
	result := {"documentId": input.document[i].id}
}`, false},
		{"negation on the iterated document", `
DatadogPolicy contains result if {
	some doc in input.document
	some name, _ in doc.resource.aws_s3_bucket
	not doc.resource.aws_s3_bucket_policy[name]
	result := {"documentId": doc.id, "resourceName": name}
}`, false},
		{"rule arguments", `
DatadogPolicy contains result if {
	some doc in input.document
	some name, b in doc.resource.aws_s3_bucket
	b.size > input.arguments.max_size
	b.size > tf_lib.threshold
	result := {"documentId": doc.id, "resourceName": name}
}`, false},
		{"document index bound by some in", `
DatadogPolicy contains result if {
	some i, doc in input.document
	input.document[i].resource.aws_s3_bucket
	result := {"documentId": doc.id}
}`, false},
		{"document index used as a value", `
DatadogPolicy contains result if {
	doc := input.document[i]
	result := {"documentId": doc.id, "position": i}
}`, true},
		{"document index bound by some in used as a value", `
DatadogPolicy contains result if {
	some i, doc in input.document
	i > 0
	result := {"documentId": doc.id}
}`, true},
		{"two loops", `
DatadogPolicy contains result if {
	some doc in input.document
	some other in input.document
	doc.resource.aws_s3_bucket[name]
	not other.resource.aws_s3_bucket_policy[name]
	result := {"documentId": doc.id}
}`, true},
		{"membership in partial set over documents", `
attached contains name if {
	some doc in input.document
	some a in doc.resource.azurerm_subnet_network_security_group_association
	name := a.subnet_id
}

DatadogPolicy contains result if {
	some doc in input.document
	some name, _ in doc.resource.azurerm_subnet
	not name in attached
	result := {"documentId": doc.id}
}`, true},
		{"library function iterating documents", `
DatadogPolicy contains result if {
	some doc in input.document
	some name, _ in doc.resource.azurerm_subnet
	not tf_lib.has_association(name)
	result := {"documentId": doc.id}
}`, true},
		{"first document", `
DatadogPolicy contains result if {
	doc := input.document[0]
	result := {"documentId": doc.id}
}`, true},
		{"document indexed by a computed key", `
DatadogPolicy contains result if {
	some doc in input.document
	other := input.document[count(doc.resource) - 1]
	result := {"documentId": other.id}
}`, true},
		{"walk input", `
DatadogPolicy contains result if {
	some doc in input.document
	walk(input, [path, value])
	value == "x"
	result := {"documentId": doc.id, "path": path}
}`, true},
		{"input passed whole to a function", `
size(x) := count(x.document)

DatadogPolicy contains result if {
	some doc in input.document
	size(input) > 1
	result := {"documentId": doc.id}
}`, true},
		{"documents passed to a function", `
count_buckets(docs) := count([b | some d in docs; some b in d.resource.aws_s3_bucket])

DatadogPolicy contains result if {
	some doc in input.document
	count_buckets(input.document) > 1
	result := {"documentId": doc.id}
}`, true},
		{"document count", `
DatadogPolicy contains result if {
	some doc in input.document
	count(input.document) > 1
	result := {"documentId": doc.id}
}`, true},
		{"documents bound whole", `
DatadogPolicy contains result if {
	docs := input.document
	some doc in docs
	result := {"documentId": doc.id}
}`, true},
		{"comprehension over documents", `
DatadogPolicy contains result if {
	some doc in input.document
	names := {n | some d in input.document; some n, _ in d.resource.aws_kms_key}
	count(names) > 0
	result := {"documentId": doc.id}
}`, true},
		{"only loop inside a comprehension", `
DatadogPolicy contains result if {
	keys := [k | k := input.document[_].resource.aws_kms_key[_]]
	count(keys) > 10
	result := {"documentId": "x", "keys": keys}
}`, true},
		{"only loop inside a negation", `
DatadogPolicy contains result if {
	not input.document[_].resource.aws_cloudtrail
	result := {"documentId": "x"}
}`, true},
		{"loop inside a negation", `
DatadogPolicy contains result if {
	some doc in input.document
	doc.resource.aws_s3_bucket[name]
	not input.document[_].resource.aws_s3_bucket_policy[name]
	result := {"documentId": doc.id}
}`, true},
		{"every over documents", `
DatadogPolicy contains result if {
	some doc in input.document
	every d in input.document { not d.resource.aws_cloudtrail }
	result := {"documentId": doc.id}
}`, true},
		{"with replaces input", `
helper if input.document[0]

DatadogPolicy contains result if {
	some doc in input.document
	helper with input as {"document": [doc]}
	result := {"documentId": doc.id}
}`, true},
		{"no document read", `
DatadogPolicy contains result if {
	result := {"documentId": "x"}
}`, true},
		{"else branch reads input", `
DatadogPolicy contains result if {
	some doc in input.document
	result := {"documentId": doc.id}
} else {
	doc := input.document[0]
	result := {"documentId": doc.id}
}`, true},
		{"helper else reads input", `
helper if {
	true
} else {
	input.document[0]
}

DatadogPolicy contains result if {
	some doc in input.document
	helper
	result := {"documentId": doc.id}
}`, true},
		{"several bodies each with one loop", `
DatadogPolicy contains result if {
	some doc in input.document
	doc.resource.aws_s3_bucket[name].acl == "public-read"
	result := {"documentId": doc.id, "resourceName": name}
}

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	not resource.versioning
	result := {"documentId": input.document[i].id, "resourceName": name}
}`, false},
		{"unparseable", `DatadogPolicy contains result if {`, true},
	}
	queries := make([]model.QueryMetadata, 0, len(tests))
	for _, tt := range tests {
		query := model.QueryMetadata{Query: tt.name, Content: "package datadog\n\nimport data.generic.terraform as tf_lib\nimport rego.v1\n" + tt.rule}
		queries = append(queries, query)
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.joining, queryJoins(&query, scopeTestLibrary))
		})
	}
	together := joiningQueries(queries, scopeTestLibrary)
	for i, tt := range tests {
		require.Equal(t, tt.joining, together[i], tt.name)
	}
}

func TestTerraformJoiningQueries_KeysByScanIndexAndFollowsTheRuleset(t *testing.T) {
	local := `package datadog
import rego.v1
DatadogPolicy contains result if {
	some doc in input.document
	result := {"documentId": doc.id}
}`
	joining := `package datadog
import rego.v1
DatadogPolicy contains result if {
	some doc in input.document
	count(input.document) > 1
	result := {"documentId": doc.id}
}`
	c := &Inspector{QueryLoader: &QueryLoader{
		commonLibrary:     source.RegoLibraries{LibraryCode: "package generic.common\n"},
		platformLibraries: map[string]source.RegoLibraries{platformTerraform: {LibraryCode: scopeTestLibrary}},
	}}
	queries := []model.QueryMetadata{
		{Query: "docker", Platform: "dockerfile", Content: joining},
		{Query: "local", Platform: platformTerraform, Content: local},
		{Query: "joining", Platform: platformTerraform, Content: joining},
	}
	require.Equal(t, map[int]bool{1: false, 2: true}, c.terraformJoiningQueries(queries))

	queries[1].Content = joining
	require.Equal(t, map[int]bool{1: true, 2: true}, c.terraformJoiningQueries(queries),
		"a changed rule is classified again")
}
