package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/stretchr/testify/require"
)

// A resource whose count or for_each expands to no instance does not exist.
// The written document never carries one for the rules to report: the parser
// resolves a count's sibling defaults regardless of any reference flag
// (parser.Resolve ignores the flag and reads the directory's variables), and
// the converter drops blocks that are zero as written. These tests pin that
// policy end to end: no legacy rule may report a resource that expands to no
// instance.

func zeroInstanceInspector(t *testing.T, root string) *Inspector {
	t.Helper()
	return newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "bucket_rule", Content: rootBucketRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
}

func TestInspect_ZeroCountResourceIsNotReported(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  count = 0

  bucket = "nope"
}
`)
	files := parseTerraformWritten(t, filepath.Join(root, "main.tf"))
	ins := zeroInstanceInspector(t, root)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Empty(t, vulns, "a resource with count = 0 does not exist")
}

func TestInspect_VariableResolvedToZeroIsNotReported(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "variables.tf", `variable "instance_count" { default = 0 }`)
	writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  count = var.instance_count

  bucket = "nope"
}
`)
	files := parseTerraformWritten(t, filepath.Join(root, "main.tf"))
	files = append(files, parseTerraformWritten(t, filepath.Join(root, "variables.tf"))...)
	ins := zeroInstanceInspector(t, root)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, vulns, "a resource whose variable resolves to zero does not exist")
}

func TestInspect_EmptyForEachResourceIsNotReported(t *testing.T) {
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
	files := parseTerraformWritten(t, filepath.Join(root, "main.tf"))
	files = append(files, parseTerraformWritten(t, filepath.Join(root, "variables.tf"))...)
	ins := zeroInstanceInspector(t, root)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, vulns, "a resource whose for_each resolves to an empty map does not exist")
}

// The variables file outside the scanned set is a different case: the model
// cannot resolve the count, keeps one instance standing for any number (a
// plan may set it), and the resource may exist. Dropping it there would be a
// false negative.
func TestInspect_UnresolvedCountStaysReported(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "variables.tf", `variable "instance_count" { default = 0 }`)
	writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  count = var.instance_count

  bucket = "nope"
}
`)
	files := parseTerraformWritten(t, filepath.Join(root, "main.tf"))
	ins := zeroInstanceInspector(t, root)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.NotEmpty(t, vulns, "a count the model cannot resolve may exist and stays reported")
}

// The written-document fallback must know whether the model ran. With the
// model run, a scanned file the modeled documents do not stand for
// contributes only the sections the model does not carry: its blocks reach
// the report through the model, and a file whose every block expanded to no
// instance holds no resource at all. With modeling skipped, the files are all
// there is. Empty modeled output and a skipped model must not be conflated.
func TestAddWrittenSections_ModelRunDoesNotReviveWrittenResources(t *testing.T) {
	written := map[string]*model.FileMetadata{
		"/repo/main.tf": {
			ID: "f1", Kind: model.KindTerraform, FilePath: "/repo/main.tf",
			Document: model.Document{"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{"gone": map[string]interface{}{}},
			}},
		},
		"/repo/terraform.tf": {
			ID: "f2", Kind: model.KindTerraform, FilePath: "/repo/terraform.tf",
			Document: model.Document{"terraform": map[string]interface{}{}},
		},
	}

	t.Run("model ran: resources are not revived", func(t *testing.T) {
		docs := (&Inspector{}).addWrittenSections(nil, nil, written, true)
		require.Len(t, docs, 1, "only the auxiliary-section file contributes")
		require.Nil(t, docs[0]["resource"], "the resource must not come back once the model has run")
		require.NotNil(t, docs[0]["terraform"], "the sections the model does not carry still do")
	})

	t.Run("modeling skipped: the files are the input", func(t *testing.T) {
		docs := (&Inspector{}).addWrittenSections(nil, nil, written, false)
		require.Len(t, docs, 2)
		for _, d := range docs {
			if d[legacyFileKey] == "/repo/main.tf" {
				require.NotNil(t, d["resource"], "with no model, the written resource is the input")
			}
		}
	})

	t.Run("model ran: files the model stands for are skipped", func(t *testing.T) {
		docs := (&Inspector{}).addWrittenSections(nil,
			[]*project.LegacyDoc{{Path: "/repo/main.tf"}}, written, true)
		require.Len(t, docs, 1)
		require.Equal(t, "/repo/terraform.tf", docs[0][legacyFileKey])
	})

	t.Run("an uncovered plan always contributes its whole document", func(t *testing.T) {
		plans := map[string]*model.FileMetadata{
			"/repo/plan.json": {
				ID: "p1", Kind: model.KindTerraformPlan, FilePath: "/repo/plan.json",
				Document: model.Document{"resource": map[string]interface{}{}},
			},
		}
		docs := (&Inspector{}).addWrittenSections(nil, nil, plans, true)
		require.Len(t, docs, 1)
		require.NotNil(t, docs[0]["resource"])
	})
}
