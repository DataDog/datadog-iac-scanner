/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func parseTestModule(t *testing.T, src string) *ast.Module {
	t.Helper()
	mod, err := ast.ParseModuleWithOpts("rule.rego", src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	require.NoError(t, err)
	return mod
}

func TestAnalyzeRuleFilter_Terraform(t *testing.T) {
	t.Run("single resource type is constrained and subsettable", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_s3_bucket[%s].acl", [name])}
}`)
		f := analyzeRuleFilter(mod, "terraform", false, nil)
		require.True(t, f.constrained)
		require.True(t, f.canSubset)
		require.Equal(t, []tfResourceKey{{section: "resource", typ: "aws_s3_bucket"}}, f.tfPreds)
	})

	t.Run("cross-document helper disables subsetting but allows skipping", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
has_versioning(bucket_name) if {
	some j, vn
	v := input.document[j].resource.aws_s3_bucket_versioning[vn]
	v.bucket == bucket_name
}
DatadogPolicy contains result if {
	some i, name
	bucket := input.document[i].resource.aws_s3_bucket[name]
	not has_versioning(name)
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_s3_bucket[%s]", [name])}
}`)
		f := analyzeRuleFilter(mod, "terraform", false, nil)
		require.True(t, f.constrained)
		require.False(t, f.canSubset, "cross-doc helper must prevent subsetting")
		require.Equal(t, []tfResourceKey{{section: "resource", typ: "aws_s3_bucket"}}, f.tfPreds)
	})

	t.Run("negated resource access is not treated as positive requirement", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i
	not input.document[i].resource.aws_s3_bucket
	result := {"documentId": input.document[i].id, "searchKey": "id"}
}`)
		f := analyzeRuleFilter(mod, "terraform", false, nil)
		require.False(t, f.constrained)
	})

	t.Run("unsafe builtin is never constrained or skipped", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	_ := input.document[i].resource.aws_s3_bucket[name]
	result := http.send({})
}`)
		f := analyzeRuleFilter(mod, "terraform", false, nil)
		require.False(t, f.constrained)
	})

	t.Run("doc index variable used outside subscript disables subsetting", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	_ := input.document[i].resource.aws_s3_bucket[name]
	i == 0
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_s3_bucket[%s]", [name])}
}`)
		f := analyzeRuleFilter(mod, "terraform", false, nil)
		require.True(t, f.constrained)
		require.False(t, f.canSubset)
	})

	t.Run("multi-branch rule unions resource and module requirements", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	_ := input.document[i].resource.aws_s3_bucket[name]
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_s3_bucket[%s]", [name])}
}
DatadogPolicy contains result if {
	some i, name
	_ := input.document[i].module[name]
	result := {"documentId": input.document[i].id, "searchKey": sprintf("module[%s]", [name])}
}`)
		f := analyzeRuleFilter(mod, "terraform", false, nil)
		require.True(t, f.constrained)
		require.True(t, f.canSubset)
		require.Equal(t, []tfResourceKey{
			{section: "module"},
			{section: "resource", typ: "aws_s3_bucket"},
		}, f.tfPreds)
	})
}

func TestAnalyzeRuleFilter_KubernetesAndCloudFormation(t *testing.T) {
	t.Run("k8s kind equality filters and subsets", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
DatadogPolicy contains result if {
	document := input.document[i]
	document.kind == "Ingress"
	result := {"documentId": document.id, "searchKey": "kind"}
}`)
		f := analyzeRuleFilter(mod, "k8s", false, nil)
		require.True(t, f.constrained)
		require.True(t, f.canSubset)
		require.Equal(t, []string{"Ingress"}, f.k8sExact)
	})

	t.Run("k8s spec_info library subtree key-presence subsetting", func(t *testing.T) {
		k8sLib := parseTestModule(t, `package generic.k8s
import rego.v1
spec_info(document) := {"spec": document.spec.template.spec, "path": "spec.template.spec"} if {
	document.spec.template.spec
} else := {"spec": document.spec, "path": "spec"} if {
	document.spec
}`)
		subFuncs := extractLibSubtreeFuncs(k8sLib)
		require.True(t, subFuncs["spec_info"]["spec"])

		ruleMod := parseTestModule(t, `package datadog
import rego.v1
import data.generic.k8s as k8sLib
types := {"initContainers", "containers"}
DatadogPolicy contains result if {
	document := input.document[i]
	specInfo := k8sLib.spec_info(document)
	container := specInfo.spec[types[x]][_]
	container.securityContext.privileged == true
	result := {"documentId": document.id, "searchKey": "metadata.name"}
}`)
		f := analyzeRuleFilter(ruleMod, "k8s", false, subFuncs)
		require.True(t, f.constrained)
		require.True(t, f.canSubset)
		require.Contains(t, f.k8sKeyConjuncts, []string{"containers", "initContainers"})
		require.Contains(t, f.k8sKeyConjuncts, []string{"privileged"})
	})

	t.Run("cloudformation walk with resource.Type", func(t *testing.T) {
		mod := parseTestModule(t, `package datadog
import rego.v1
DatadogPolicy contains result if {
	docs := input.document[i]
	[path, Resources] := walk(docs)
	resource := Resources[name]
	resource.Type == "AWS::CloudFront::Distribution"
	result := {"documentId": docs.id, "searchKey": sprintf("%v", [path])}
}`)
		f := analyzeRuleFilter(mod, "cloudformation", false, nil)
		require.True(t, f.constrained)
		require.True(t, f.canSubset)
		require.Equal(t, []string{"AWS::CloudFront::Distribution"}, f.cfnTypes)
	})
}

func TestFindingNeedsLineInfoDocument(t *testing.T) {
	tests := []struct {
		name string
		file *model.FileMetadata
		key  string
		want bool
	}{
		{
			name: "terraform single bracket resource key skips line info",
			file: &model.FileMetadata{Kind: model.KindTerraform, Platform: "terraform"},
			key:  "aws_s3_bucket[my_bucket].acl",
			want: false,
		},
		{
			name: "terraform repeated nested block requires line info",
			file: &model.FileMetadata{Kind: model.KindTerraform, Platform: "terraform"},
			key:  "aws_security_group[web].ingress[0].cidr_blocks",
			want: true,
		},
		{
			name: "terraform plan always requires line info",
			file: &model.FileMetadata{Kind: model.KindTerraformPlan, Platform: "terraform"},
			key:  "aws_s3_bucket[my_bucket]",
			want: true,
		},
		{
			name: "docker compose always requires line info",
			file: &model.FileMetadata{Kind: model.KindYAML, Platform: "dockercompose"},
			key:  "services.web.privileged",
			want: true,
		},
		{
			name: "k8s anchored non-numeric key skips line info",
			file: &model.FileMetadata{Kind: model.KindYAML, Platform: "kubernetes", OriginalData: "apiVersion: apps/v1\nkind: Deployment\n"},
			key:  "metadata.name={{svc-0001}}.spec.template.spec.containers.name={{app}}.securityContext.privileged",
			want: false,
		},
		{
			name: "yaml with numeric segment requires line info",
			file: &model.FileMetadata{Kind: model.KindYAML, Platform: "kubernetes", OriginalData: "kind: Role\n"},
			key:  "rules.0.apiGroups",
			want: true,
		},
		{
			name: "yaml with bracket index requires line info",
			file: &model.FileMetadata{Kind: model.KindYAML, Platform: "ansible", OriginalData: "- name: task\n"},
			key:  "name={{task}}.policy.Statement[0].Principal",
			want: true,
		},
		{
			name: "yaml containing $ref requires line info",
			file: &model.FileMetadata{Kind: model.KindYAML, Platform: "openapi", OriginalData: "schema:\n  $REF: other.yaml\n"},
			key:  "paths.get.responses",
			want: true,
		},
		{
			name: "dockerfile skips line info",
			file: &model.FileMetadata{Kind: model.KindDOCKER, Platform: "dockerfile"},
			key:  "FROM={{alpine}}.RUN={{curl}}",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findingNeedsLineInfoDocument(tt.file, map[string]interface{}{"searchKey": tt.key})
			require.Equal(t, tt.want, got)
		})
	}
}

func TestInspect_BatchedAndPrefilteredMatchesUnbatched(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`
resource "aws_s3_bucket" "public" {
  acl = "public-read"
}
resource "aws_s3_bucket" "private" {
  bucket = "ok"
}
`), 0o600))

	// Mix of matching rules, absent-resource rules, and a rule with custom ruleConfigs.Arguments.
	queries := []model.QueryMetadata{
		{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		},
		{
			Query: "versioning_rule", Content: secondRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "versioning-rule"}, Aggregation: 1,
		},
		{
			Query: "absent_rule", InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "absent-rule"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	_ := input.document[i].resource.aws_redshift_cluster[name]
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_redshift_cluster[%s]", [name])}
}`,
		},
		{
			Query: "args_rule", InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "args-rule"}, Aggregation: 1,
			Content: `package datadog
import rego.v1
DatadogPolicy contains result if {
	some i, name
	b := input.document[i].resource.aws_s3_bucket[name]
	b.acl == input.arguments.bad_acl
	result := {"documentId": input.document[i].id, "searchKey": sprintf("aws_s3_bucket[%s].acl", [name])}
}`,
		},
	}

	files := parseTerraform(t, mainPath)
	ins := newTestInspector(t, inspectorOpts{
		queries:    queries,
		repoPath:   root,
		vb:         DefaultVulnerabilityBuilder,
		numWorkers: 2,
	})
	ins.ruleConfigs = map[string]config.IacRuleConfig{
		"args-rule": {Arguments: map[string]interface{}{"bad_acl": "public-read"}},
	}

	got, err := ins.Inspect(context.Background(), "batched", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	var gotIDs []string
	for _, v := range got {
		gotIDs = append(gotIDs, v.QueryID+":"+v.SearchKey)
	}
	sort.Strings(gotIDs)
	require.Equal(t, []string{
		"acl-rule:aws_s3_bucket[public].acl",
		"args-rule:aws_s3_bucket[public].acl",
		"versioning-rule:aws_s3_bucket[private]",
		"versioning-rule:aws_s3_bucket[public]",
	}, gotIDs)
}
