/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package project

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/stretchr/testify/require"
)

// The evidence block of another root keeps its nested blocks in every root
// that matches it, not only in the first one projected.
func TestCrossEvidenceKeepsNestedBlocksInEveryRoot(t *testing.T) {
	keys := LiteralKeys{"aws_s3_bucket_server_side_encryption_configuration": {"bucket": {"aws_s3_bucket": {"bucket"}}}}
	dir := t.TempDir()
	files := map[string]string{
		"prod/main.tf":  `resource "aws_s3_bucket" "b" { bucket = "acme" }`,
		"stage/main.tf": `resource "aws_s3_bucket" "b" { bucket = "acme" }`,
		"ops/main.tf": `resource "aws_s3_bucket_server_side_encryption_configuration" "e" {
  bucket = "acme"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}`,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	opts := Options{Placeholder: testPlaceholder, LiteralKeys: keys}
	idx := NewCrossIndex()
	for _, r := range scan.Roots {
		idx.Add(Project([]*model.Root{r}, opts))
	}
	opts.Cross = idx
	var names []string
	byName := map[string]*model.Root{}
	for _, r := range scan.Roots {
		n := filepath.Base(r.Dir)
		if n != "ops" {
			names = append(names, n)
			byName[n] = r
		}
	}
	sort.Strings(names)
	for _, n := range names {
		p := Project([]*model.Root{byName[n]}, opts)
		related := relatedOf(t, p, "aws_s3_bucket", "aws_s3_bucket_server_side_encryption_configuration", "bucket")
		require.Equal(t, []any{"ops/aws_s3_bucket_server_side_encryption_configuration.e"}, related, n)
		nested := get(dd(t, p), "nested", "ops/aws_s3_bucket_server_side_encryption_configuration.e", "rule")
		require.NotNil(t, nested, "root %s: the evidence block lost its nested rule list", n)
	}
}
