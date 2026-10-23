/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestScanSymlinkPlaceholdersWithoutGitMetadata(t *testing.T) {
	// Exercise the same aliased root as macOS's /var -> /private/var.
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(t.TempDir(), alias))
	repo := filepath.Join(alias, "repo")
	require.NoError(t, os.Mkdir(repo, 0o755))
	for path, content := range map[string]string{
		"shared.tf":          `variable "acl" { default = "public-read" }`,
		"stack/variables.tf": "../shared.tf",
		"stack/missing.tf":   "./unavailable.tf",
		"stack/comment.tf":   "//variables.tf",
		"stack/main.tf": `module "linked" {
  source = "../alias"
  acl = var.acl
}
module "missing" { source = "../unavailable" }`,
		"alias":       "./actual",
		"unavailable": "./gone",
		"actual/main.tf": `variable "acl" {}
resource "aws_s3_bucket" "this" { acl = var.acl }`,
	} {
		full := filepath.Join(repo, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	query := model.QueryMetadata{
		Query: "placeholder-rule", InputData: "{}", Platform: "terraform",
		Content: `package datadog
DatadogPolicy contains result if {
  some name, i
  bucket := input.document[i].resource.aws_s3_bucket[name]
  bucket.acl == "public-read"
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_s3_bucket",
    "resourceName": name,
    "searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
  }
}`,
		Metadata: map[string]interface{}{
			"id": "placeholder-rule", "legacyId": "placeholder-rule", "queryName": "Placeholder test",
			"severity": "HIGH", "platform": "Terraform", "category": "Encryption",
			"descriptionUrl": "https://example.com/rule", "descriptionText": "Test rule",
			"descriptionID": "placeholder-test", "cwe": "284",
		},
		Aggregation: 1,
	}
	params := Parameters{
		RepoPath: repo, Path: []string{repo}, QueriesPath: []string{"."},
		Platform: []string{"Terraform"}, CloudProvider: []string{"aws"},
		MaxFileSizeFlag: 5, ScanID: "placeholder-test", MaxResolverDepth: 15,
		PreviewLines:  3,
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}
	var logs bytes.Buffer
	log := zerolog.New(zerolog.SyncWriter(&logs)).Level(zerolog.DebugLevel)
	ctx := log.WithContext(t.Context())
	client, err := NewClient(ctx, &params, &consolePrinter.Printer{})
	require.NoError(t, err)
	client.querySourceFactory = func(context.Context, []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
	}
	result, err := client.Scan(ctx)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Results, 1, logs.String())
	require.Equal(t, filepath.ToSlash(filepath.Join(repo, "actual", "main.tf")), filepath.ToSlash(result.Results[0].FileName))
	require.NotNil(t, result.Results[0].ModuleAttribution)
	require.Equal(t, "stack/main.tf", result.Results[0].ModuleAttribution.CallSite.Filename)
	require.NotContains(t, logs.String(), `"level":"error"`)
}
