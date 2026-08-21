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
		"aws_s3_bucket",           // read off a document by field
		"google_storage_bucket",   // read off a document by key
		"aws_sqs_queue",           // passed to a library helper
		"aws_instance",            // named only in a library
		"azurerm_anything_at_all", // whole provider selected by prefix
	} {
		if !targets.matches(typ) {
			t.Errorf("%s should be matched by some rule", typ)
		}
	}
	for _, typ := range []string{"vault_identity_group", "datadog_monitor"} {
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
