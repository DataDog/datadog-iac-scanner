package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// A root whose every resource expands to no instance (count = 0) has no
// modeled block. The legacy documents must not fall back to the written
// file, or a rule reports a resource that does not exist.
func TestInspect_ZeroInstanceResourceIsNotRevivedForLegacyRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "variables.tf", `variable "instance_count" { default = 0 }`)
	writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  count = var.instance_count

  bucket = "nope"
}
`)
	files := parseTerraform(t, filepath.Join(root, "main.tf"))
	files = append(files, parseTerraform(t, filepath.Join(root, "variables.tf"))...)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "bucket_rule", Content: rootBucketRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Empty(t, vulns, "a resource that expands to no instance does not exist and must not be reported")
}

// With for_each over an empty map the resource does not exist either.
func TestInspect_EmptyForEachResourceIsNotRevivedForLegacyRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "variables.tf", `variable "buckets" {
  type    = map(string)
  default = {}
}`)
	writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  for_each = var.buckets

  bucket = "nope"
}
`)
	files := parseTerraform(t, filepath.Join(root, "main.tf"))
	files = append(files, parseTerraform(t, filepath.Join(root, "variables.tf"))...)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "bucket_rule", Content: rootBucketRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, vulns)
}
