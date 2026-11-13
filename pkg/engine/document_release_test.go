package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// contractLibSource serves the contract libraries a contract rule imports:
// the common library defines finding, the Terraform library the input lookups.
type contractLibSource struct{ queries []model.QueryMetadata }

func (s *contractLibSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *contractLibSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	code := releaseTerraformLib
	if platform == "common" {
		code = releaseCommonLib
	}
	return source.RegoLibraries{LibraryCode: code, LibraryInputData: "{}"}, nil
}

// The libraries a contract rule needs: the engine locates findings from the
// block ids the results name, so the library only looks them up in input._dd.
const (
	releaseCommonLib = `package generic.common

import rego.v1

finding(subject, path, details) := object.union(details, {"_dd_id": subject._dd_meta.id, "path": path})

is_list(v) if is_array(v)
`

	releaseTerraformLib = `package generic.terraform

import rego.v1

import data.generic.common

_dd := object.get(input, "_dd", {})

_placeholder := object.get(_dd, "placeholder", "\u0000dd-unknown")

blocks(type) := object.get(_dd, ["blocks", "resource", type], [])

by_id(id) := object.get(_dd, ["by_id", id], _placeholder)

literal_keys := {"aws_s3_bucket_versioning": {"bucket": {"aws_s3_bucket": ["bucket"]}}}
`
)

const releaseBucketRule = `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	result := common.finding(b, [], {})
}
`

// releaseInspector is an inspector whose scan releases every scanned file's
// documents before the Terraform rules evaluate — the path a scan takes when
// its Terraform rules all read the contract input and no other platform runs.
func releaseInspector(t *testing.T, root string, rule model.QueryMetadata) *Inspector {
	t.Helper()
	ins, err := NewInspector(context.Background(), &contractLibSource{queries: []model.QueryMetadata{rule}},
		DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
		root, false, false, 1, featureflags.NewLocalEvaluator(), nil, false)
	require.NoError(t, err)
	ins.SetReleaseDocumentsAfterPayload(true)
	ins.SetReleasePostEvalData(true)
	return ins
}

// With the documents released before evaluation, a called module still models:
// its resource is found, attributed to the root call, and the finding carries
// the module call chain.
func TestInspect_DocumentReleaseKeepsModuleCallsAndAttribution(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.tf", `
module "bucket" {
  source = "./mod"
}
`)
	writeFile(t, root, filepath.Join("mod", "main.tf"), `
resource "aws_s3_bucket" "mod_bucket" {
  bucket = "called"
}
`)
	files := append(parseTerraformWritten(t, filepath.Join(root, "main.tf")),
		parseTerraformWritten(t, filepath.Join(root, "mod", "main.tf"))...)
	ins := releaseInspector(t, root, model.QueryMetadata{
		Query: "release_bucket_rule", Content: releaseBucketRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "release-bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.NotEmpty(t, vulns, "the module's resource must be found with the documents released")
	found := false
	for _, v := range vulns {
		if v.ResourceName == "mod_bucket" {
			found = true
			require.NotEmpty(t, v.ModuleCallChain, "the finding carries the module call chain")
			require.NotNil(t, v.ModuleAttribution, "the finding is attributed to the root call")
		}
	}
	require.True(t, found, "the called module's bucket is reported; got %v", vulns)
}

// Releasing the documents must not bring a resource that expands to no
// instance back: the zero-instance root reports nothing, on the release path
// like on every other.
func TestInspect_DocumentReleaseKeepsZeroInstanceResourcesDown(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "variables.tf", `variable "instance_count" { default = 0 }`)
	writeFile(t, root, "main.tf", `
resource "aws_s3_bucket" "gone" {
  count = var.instance_count

  bucket = "nope"
}
`)
	files := append(parseTerraformWritten(t, filepath.Join(root, "main.tf")),
		parseTerraformWritten(t, filepath.Join(root, "variables.tf"))...)
	ins := releaseInspector(t, root, model.QueryMetadata{
		Query: "release_bucket_rule", Content: releaseBucketRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "release-bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Empty(t, vulns, "a resource that expands to no instance does not exist")
}
