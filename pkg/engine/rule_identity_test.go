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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// providerTaggedRule reads every document of a root: a bucket is fine when
// any document of its root configures the aws provider.
const providerTaggedRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	some name, _ in doc.resource.aws_s3_bucket
	not provider_configured
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "provider configured",
		"keyActualValue": "no provider",
	}
}

provider_configured if {
	some doc in input.document
	doc.provider.aws
}
`

// documentLocalRule reads one document per finding.
const documentLocalRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	some name, _ in doc.resource.azurerm_storage_account
	result := {
		"documentId": doc.id,
		"resourceType": "azurerm_storage_account",
		"resourceName": name,
		"searchKey": sprintf("azurerm_storage_account[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "x",
		"keyActualValue": "y",
	}
}
`

// threeRoots writes root a (aws provider and a bucket), root b (a bucket) and
// root c (an Azure storage account) and parses them.
func threeRoots(t *testing.T) (string, model.FileMetadatas) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) string {
		path := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
		return path
	}
	a := write("a/main.tf", "provider \"aws\" {\n  region = \"us-east-1\"\n}\n\nresource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\"\n}\n")
	b := write("b/main.tf", "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"b\"\n}\n")
	c := write("c/main.tf", "resource \"azurerm_storage_account\" \"c\" {\n  name = \"c\"\n}\n")
	var files model.FileMetadatas
	for _, path := range []string{a, b, c} {
		files = append(files, parseTerraform(t, path)...)
	}
	return root, files
}

// Rules are named after their directory, and two providers may each have a
// rule directory of the same name. Each must keep its own per-root
// classification: the cross-document rule still runs once per root, so the
// provider configured in root a does not hide the bucket of root b.
func TestInspect_RulesSharingANameKeepTheirOwnScope(t *testing.T) {
	root, files := threeRoots(t)

	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{
			{
				Query: "shared_name", Content: providerTaggedRule, InputData: "{}", Platform: "terraform",
				Metadata: map[string]interface{}{"id": "aws-rule", "platform": "Terraform"}, Aggregation: 1,
			},
			{
				Query: "shared_name", Content: documentLocalRule, InputData: "{}", Platform: "terraform",
				Metadata: map[string]interface{}{"id": "azure-rule", "platform": "Terraform"}, Aggregation: 1,
			},
		},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       tr,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	require.Equal(t, 2, ins.LenQueriesByPlat([]string{"terraform"}))
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	got := map[string]string{}
	for i := range vulns {
		got[vulns[i].QueryID] = vulns[i].ResourceID
	}
	require.Equal(t, map[string]string{
		"aws-rule":   "aws_s3_bucket.b",
		"azure-rule": "azurerm_storage_account.c",
	}, got)
}

// A cross-document rule runs once per root that has a block it reads, and not
// at all when no root has one; either way it is one executed rule.
func TestInspect_RuleRunOverSeveralRootsIsCountedOnce(t *testing.T) {
	root, files := threeRoots(t)
	instanceRule := strings.NewReplacer("aws_s3_bucket", "aws_instance", "doc.provider.aws", "doc.resource.aws_instance.peer").
		Replace(providerTaggedRule)
	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{
			{
				Query: "bucket", Content: providerTaggedRule, InputData: "{}", Platform: "terraform",
				Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
			},
			{
				Query: "instance", Content: instanceRule, InputData: "{}", Platform: "terraform",
				Metadata: map[string]interface{}{"id": "instance-rule", "platform": "Terraform"}, Aggregation: 1,
			},
			{
				Query: "storage", Content: documentLocalRule, InputData: "{}", Platform: "terraform",
				Metadata: map[string]interface{}{"id": "storage-rule", "platform": "Terraform"}, Aggregation: 1,
			},
		},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       tr,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	require.Equal(t, 3, ins.LenQueriesByPlat([]string{"terraform"}))
	_, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Equal(t, 3, tr.ExecutingQueries)
	require.Equal(t, 3, tr.ExecutedQueries, "each rule is counted once")
}
