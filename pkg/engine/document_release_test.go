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

	releaseBucketRule = `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	result := common.finding(b, [], {})
}
`
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

// releaseInspector is an inspector whose scan releases every scanned file's
// documents before the Terraform rules evaluate (release true) or keeps them
// (release false) — the two configurations a scan runs in, depending on
// whether the plain JSON payload is exported.
func releaseInspector(t *testing.T, root string, rule model.QueryMetadata, release bool) *Inspector {
	t.Helper()
	ins, err := NewInspector(context.Background(), &contractLibSource{queries: []model.QueryMetadata{rule}},
		DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
		root, false, false, 1, featureflags.NewLocalEvaluator(), nil, false)
	require.NoError(t, err)
	ins.SetReleaseDocumentsAfterPayload(release)
	ins.SetReleasePostEvalData(true)
	return ins
}

func releaseModuleFiles(t *testing.T, root string) model.FileMetadatas {
	t.Helper()
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
	return append(parseTerraformWritten(t, filepath.Join(root, "main.tf")),
		parseTerraformWritten(t, filepath.Join(root, "mod", "main.tf"))...)
}

func releaseRule() model.QueryMetadata {
	return model.QueryMetadata{
		Query: "release_bucket_rule", Content: releaseBucketRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "release-bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	}
}

// Releasing the documents before evaluation must not change what the scan
// reports: the same module resource, with the same identity, whether the
// documents were released or kept.
func TestInspect_DocumentReleaseKeepsFindingsIdentical(t *testing.T) {
	run := func(t *testing.T, release bool) []model.Vulnerability {
		root := t.TempDir()
		files := releaseModuleFiles(t, root)
		ins := releaseInspector(t, root, releaseRule(), release)
		vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, ins.GetFailedQueries())

		// The release is the designed state for scans that do not export the
		// plain JSON payload: the document maps are gone once the payload the
		// rules read has been built, and legacy and export consumers reparse
		// from the kept original data. With the release off, the documents
		// are preserved.
		for _, f := range files {
			if release {
				require.Nil(t, f.Document, "released documents are absent after the scan")
			} else {
				require.NotNil(t, f.Document, "kept documents are preserved")
			}
		}
		return vulns
	}

	released := run(t, true)
	kept := run(t, false)
	require.NotEmpty(t, released, "the module's resource is found with the documents released")
	require.Len(t, released, len(kept), "the release does not change what is reported")
	for i := range released {
		require.Equal(t, kept[i].ResourceID, released[i].ResourceID, "same address either way")
		require.Equal(t, kept[i].IdentityKey, released[i].IdentityKey, "same finding identity either way")
		require.Equal(t, kept[i].SearchKey, released[i].SearchKey, "same search key either way")
		require.Equal(t, kept[i].ModuleCallChain, released[i].ModuleCallChain, "same module call chain either way")
		require.NotNil(t, released[i].ModuleAttribution, "the finding is attributed to the root call")
		require.Equal(t, kept[i].ModuleAttribution.CallSite, released[i].ModuleAttribution.CallSite,
			"same attribution either way")
	}
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
	ins := releaseInspector(t, root, releaseRule(), true)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Empty(t, vulns, "a resource that expands to no instance does not exist")
}
