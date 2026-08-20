/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// A rule may only be skipped when everything it can read is known to be absent.
// These cases are the ways that bound can be wrong, each of which cost real
// findings while the prefilter was being developed.
func TestRuleAnchors(t *testing.T) {
	cases := []struct {
		name        string
		rego        string
		wantBounded bool
		wantAnchors []string
	}{
		{
			name:        "a named resource type bounds the rule",
			rego:        `x := input.document[i].resource.aws_s3_bucket[name]`,
			wantBounded: true,
			wantAnchors: []string{"resource:aws_s3_bucket"},
		},
		{
			name:        "a quoted resource type bounds the rule",
			rego:        `x := input.document[i].resource["aws_s3_bucket"][name]`,
			wantBounded: true,
			wantAnchors: []string{"resource:aws_s3_bucket"},
		},
		{
			// This is resource_not_using_tags: it picks the type at evaluation
			// time, so no set read off the text bounds it.
			name:        "a resource type chosen at evaluation time is unbounded",
			rego:        `resource := input.document[i].resource[res][name]`,
			wantBounded: false,
		},
		{
			name:        "handing the whole resource map to a helper is unbounded",
			rego:        `settings_are_equal(document.resource, stage.rest_api_id)`,
			wantBounded: false,
		},
		{
			// A module branch fires on the call site, not on any resource type,
			// so the rule must still run in a repository that has module blocks.
			name:        "a module branch anchors on the module block",
			rego:        `module := input.document[i].module[name]`,
			wantBounded: true,
			wantAnchors: []string{"block:module"},
		},
		{
			name:        "a data source anchors on its own type",
			rego:        `p := input.document[i].data.aws_iam_policy_document[name]`,
			wantBounded: true,
			wantAnchors: []string{"data:aws_iam_policy_document"},
		},
		{
			// `data.generic.common` is the Rego library namespace and says
			// nothing about what the rule reads.
			name: "the rego library namespace is not a data source",
			rego: "package datadog\n\nimport data.generic.common as common_lib\n\n" +
				"DatadogPolicy contains result if {\n" +
				"\tx := input.document[i].resource.aws_vpc[n]\n" +
				"\tcommon_lib.valid_key(x, \"tags\")\n" +
				"\tresult := {\"documentId\": \"x\"}\n}\n",
			wantBounded: true,
			wantAnchors: []string{"resource:aws_vpc"},
		},
	}

	// ruleAnchors works on a parsed module, so a rule body is wrapped in one.
	// A case that needs module-level syntax supplies the whole module itself.
	asModule := func(rego string) string {
		if strings.HasPrefix(rego, "package ") {
			return rego
		}
		return policy(rego)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			anchors, bounded := ruleAnchors(asModule(tc.rego))
			if bounded != tc.wantBounded {
				t.Fatalf("bounded = %v, want %v (anchors %v)", bounded, tc.wantBounded, anchors)
			}
			if !bounded {
				return
			}
			for _, want := range tc.wantAnchors {
				if !anchors[want] {
					t.Errorf("missing anchor %q, got %v", want, anchors)
				}
			}
		})
	}
}

func policy(body string) string {
	return "package datadog\n\nDatadogPolicy contains result if {\n\t" + body +
		"\n\tresult := {\"documentId\": \"x\"}\n}\n"
}

func TestFilterQueriesByPresentAnchors(t *testing.T) {
	docs := []model.Document{{
		"resource": map[string]interface{}{
			"aws_s3_bucket": map[string]interface{}{"b": map[string]interface{}{}},
		},
	}}
	present := presentAnchors(docs)
	if !present["resource:aws_s3_bucket"] {
		t.Fatalf("expected the declared resource type to be present, got %v", present)
	}

	queries := []model.QueryMetadata{
		{Query: "matches", Platform: "terraform",
			Content: policy(`x := input.document[i].resource.aws_s3_bucket[n]`)},
		{Query: "absent", Platform: "terraform",
			Content: policy(`x := input.document[i].resource.aws_autoscaling_group[n]`)},
		{Query: "unbounded", Platform: "terraform",
			Content: policy(`x := input.document[i].resource[res][n]`)},
		{Query: "other-platform", Platform: "k8s",
			Content: policy(`x := input.document[i].resource.aws_autoscaling_group[n]`)},
	}

	kept, skipped := filterQueriesByPresentAnchors(queries, present)
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	keptNames := map[string]bool{}
	for _, q := range kept {
		keptNames[q.Query] = true
	}
	for _, want := range []string{"matches", "unbounded", "other-platform"} {
		if !keptNames[want] {
			t.Errorf("query %q must run, kept = %v", want, keptNames)
		}
	}
	if keptNames["absent"] {
		t.Errorf("a rule reading only absent types should be skipped")
	}
}
