/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"maps"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

func TestRuleTargetedResourceTypes(t *testing.T) {
	queries := []model.QueryMetadata{
		{Content: `
DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	resource.acl == "public-read"
}
`},
		{Content: `
DatadogPolicy contains result if {
	some resource in input.document[i].resource["google_storage_bucket"]
	not resource.uniform_bucket_level_access
}
`},
		{Content: `
DatadogPolicy contains result if {
	module := input.document[i].module[name]
	common_lib.module_equivalent_key("aws", module.source, "aws_sqs_queue", key)
}
`},
		{Content: `
DatadogPolicy contains result if {
	data := input.document[i].data.aws_ami[name]
	not data.owners
	metadata.name == "x"
	common := data.generic.common
}
`},
		{Content: `
DatadogPolicy contains result if {
	secret := input.document[i].ephemeral.random_password[name]
	secret.result
}
`},
		{Content: `
DatadogPolicy contains result if {
	some t in ["ephemeral.aws_secretsmanager_secret"]
	startswith(t, "ephemeral.")
}
`},
		{Content: `
taggable contains resource if {
	some resource_type, resource in doc.resource
	startswith(resource_type, "azurerm_")
}
`},
	}
	library := `check_supports_tags(t) if { t == "aws_instance" }`

	targets := ruleTargetedResourceTypes(queries, library)
	if targets == nil {
		t.Fatal("expected targets from a non-empty ruleset")
	}

	for _, typ := range []string{
		"aws_s3_bucket",                       // read off a document by field
		"google_storage_bucket",               // read off a document by key
		"aws_sqs_queue",                       // passed to a library helper
		"aws_instance",                        // named only in a library
		"azurerm_anything_at_all",             // whole provider selected by prefix
		"aws_ami",                             // read off a document's data blocks
		"random_password",                     // read off a document's ephemeral blocks
		"ephemeral.aws_secretsmanager_secret", // named with its namespace in a literal
	} {
		if !targets.matches(typ) {
			t.Errorf("%s should be matched by some rule", typ)
		}
	}
	for _, typ := range []string{"vault_identity_group", "datadog_monitor", "name", "owners", "generic"} {
		if targets.matches(typ) {
			t.Errorf("%s is named by no rule and should not be matched", typ)
		}
	}
}

// With no rule text to read, the filter must not narrow the scan.
func TestRuleTargetedResourceTypes_EmptyRulesetDisablesFiltering(t *testing.T) {
	if targets := ruleTargetedResourceTypes(nil); targets != nil {
		t.Fatalf("expected nil targets, got %#v", targets)
	}
	var none *ruleTargets
	if !none.matches("anything_at_all") {
		t.Fatal("a nil filter must match everything")
	}
}

func TestDeclaresTargetedResource(t *testing.T) {
	withTypes := func(path string, types ...string) *model.FileMetadata {
		resources := model.Document{}
		for _, typ := range types {
			resources[typ] = model.Document{"this": model.Document{}}
		}
		return &model.FileMetadata{FilePath: path, Document: model.Document{"resource": resources}}
	}
	targets := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}

	cases := []struct {
		name  string
		files model.FileMetadatas
		want  bool
	}{
		{
			name:  "nothing a rule can match",
			files: model.FileMetadatas{withTypes("a.tf", "vault_policy", "random_id")},
			want:  false,
		},
		{
			name: "one targeted type anywhere is enough",
			files: model.FileMetadatas{
				withTypes("a.tf", "vault_policy"),
				withTypes("b.tf", "aws_s3_bucket"),
			},
			want: true,
		},
		{
			name:  "non-terraform files are ignored",
			files: model.FileMetadatas{withTypes("main.yaml", "aws_s3_bucket")},
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := declaresTargetedResource(tc.files, targets); got != tc.want {
				t.Fatalf("declaresTargetedResource() = %v, want %v", got, tc.want)
			}
		})
	}

	if !declaresTargetedResource(model.FileMetadatas{withTypes("a.tf", "vault_policy")}, nil) {
		t.Fatal("a nil filter must never skip evaluation")
	}
}

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
	batch := analyzeTerraformQueries(queries, scopeTestLibrary).cross
	for i, tt := range tests {
		if batch[i] != tt.cross {
			t.Errorf("crossDocumentQueries[%q] = %v, want %v", tt.name, batch[i], tt.cross)
		}
	}
}

func TestRootHasRuleTarget(t *testing.T) {
	aws := analyzeTerraformQueries([]model.QueryMetadata{{
		Query:   "s3",
		Content: "package datadog\nDatadogPolicy contains r if { input.document[_].resource.aws_s3_bucket[name]; r := name }",
	}}).targets[0]
	if aws == nil {
		t.Fatal("expected targets from aws_s3_bucket rule")
	}
	if !rootHasRuleTarget(map[string]bool{"aws_s3_bucket": true}, aws) {
		t.Fatal("aws root should match")
	}
	if rootHasRuleTarget(map[string]bool{"vault_policy": true}, aws) {
		t.Fatal("vault root should not match aws rule")
	}
	if !rootHasRuleTarget(map[string]bool{"vault_policy": true}, nil) {
		t.Fatal("nil targets must not skip")
	}
}

const typeReadsLibrary = `package generic.terraform

import rego.v1

lifecycle_rules(bucket) := [r |
	some doc in input.document
	some r in doc.resource.aws_s3_bucket_lifecycle_configuration
	r.bucket == bucket
]

supports_tags(type) if startswith(type, "aws_")
`

func TestBlockTypesRead(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want []string
	}{
		{"constant types", `
DatadogPolicy contains r if {
	some doc in input.document
	some name, _ in doc.resource.aws_s3_bucket
	not doc.data.aws_iam_policy_document[name]
	r := name
}`, []string{"aws_s3_bucket", "data.aws_iam_policy_document"}},
		{"types read by a library function", `
DatadogPolicy contains r if {
	some doc in input.document
	some name, _ in doc.resource.aws_s3_bucket
	count(tf_lib.lifecycle_rules(name)) == 0
	r := name
}`, []string{"aws_s3_bucket", "aws_s3_bucket_lifecycle_configuration"}},
		{"type bound by a variable named resource", `
DatadogPolicy contains r if {
	resource := input.document[i].resource[res][name]
	tf_lib.supports_tags(res)
	not resource.tags
	r := name
}`, nil},
		{"section used whole", `
DatadogPolicy contains r if {
	some doc in input.document
	some type, blocks in doc.resource
	r := [type, blocks]
}`, nil},
		{"section named as a string", `
DatadogPolicy contains r if {
	some doc in input.document
	some _, b in object.get(doc, "resource", {}).aws_s3_bucket
	r := b
}`, nil},
		{"untyped section", `
DatadogPolicy contains r if {
	some doc in input.document
	doc.resource.aws_s3_bucket[name]
	some m in doc.module
	r := [name, m]
}`, nil},
		{"walk", `
DatadogPolicy contains r if {
	some doc in input.document
	doc.resource.aws_s3_bucket[name]
	walk(doc, [path, _])
	r := [name, path]
}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := model.QueryMetadata{Query: tt.name, Content: "package datadog\n\nimport data.generic.terraform as tf_lib\nimport rego.v1\n" + tt.rule}
			got := analyzeTerraformQueries([]model.QueryMetadata{query}, typeReadsLibrary).targets[0]
			if tt.want == nil {
				if got != nil {
					t.Fatalf("targets = %v, want unbounded", got.types)
				}
				return
			}
			if got == nil {
				t.Fatalf("targets unbounded, want %v", tt.want)
			}
			want := map[string]bool{}
			for _, typ := range tt.want {
				want[typ] = true
			}
			if !maps.Equal(got.types, want) {
				t.Fatalf("targets = %v, want %v", got.types, want)
			}
		})
	}
}
