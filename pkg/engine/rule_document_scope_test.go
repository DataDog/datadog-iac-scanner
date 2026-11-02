/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const scopeTestLibrary = `package generic.terraform

import rego.v1

has_association(name) if {
	some doc in input.document
	doc.resource.azurerm_subnet_network_security_group_association[_].subnet_id == name
}

is_public(acl) if acl == "public-read"
`

func TestRuleDocumentScope(t *testing.T) {
	tests := []struct {
		name  string
		rule  string
		cross bool
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
		{"walk input", `
DatadogPolicy contains result if {
	some doc in input.document
	walk(input, [path, value])
	value == "x"
	result := {"documentId": doc.id, "path": path}
}`, true},
		{"documents passed to a function", `
count_buckets(docs) := count([b | some d in docs; some b in d.resource.aws_s3_bucket])

DatadogPolicy contains result if {
	some doc in input.document
	count_buckets(input.document) > 1
	result := {"documentId": doc.id}
}`, true},
		{"comprehension over documents", `
DatadogPolicy contains result if {
	some doc in input.document
	names := {n | some d in input.document; some n, _ in d.resource.aws_kms_key}
	count(names) > 0
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
		{"recursion reaches input", `
a if { b }
b if { a; input.document[i].id }

DatadogPolicy contains result if {
	some doc in input.document
	b
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
			if got := crossDocument(&query, scopeTestLibrary); got != tt.cross {
				t.Errorf("crossDocument = %v, want %v", got, tt.cross)
			}
		})
	}
	batch := crossDocumentQueries(queries, scopeTestLibrary)
	for _, tt := range tests {
		if batch[tt.name] != tt.cross {
			t.Errorf("crossDocumentQueries[%q] = %v, want %v", tt.name, batch[tt.name], tt.cross)
		}
	}
}
