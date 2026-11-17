package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// releaseInspector is an inspector whose scan releases every scanned file's
// documents before the Terraform rules evaluate (release true) or keeps them
// (release false) — the two configurations a scan runs in, depending on
// whether the plain JSON payload is exported.
func releaseInspector(t *testing.T, root string, release bool) *Inspector {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		querySource: &referenceQueriesSource{queries: []model.QueryMetadata{
			referenceQuery("release_bucket_rule", "release-bucket-rule", referenceBucketRule),
		}},
		repoPath: root, vb: DefaultVulnerabilityBuilder, tracker: &tracker.CITracker{},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
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

// Releasing the documents before evaluation must not change what the scan
// reports: the same module resource, with the same identity, whether the
// documents were released or kept.
//
// The identity fields asserted here are the ones the contract decode path
// populates. ResourceID is not among them: it is set only from a file's
// TerraformScope lookups, which this path does not build. The finding's
// identity is model.FindingIdentity — the exact input the report layer
// hashes into the DATADOG_FINGERPRINT (via GetDatadogFingerprintHash, with
// scan-constant SCIInfo) — and the fingerprint hash itself is compared too.
func TestInspect_DocumentReleaseKeepsFindingsIdentical(t *testing.T) {
	// One root for both runs: the finding identity carries the file path, so
	// the runs must scan the same directory. Each run re-parses the files, so
	// one run's released documents cannot leak into the other.
	root := t.TempDir()
	releaseModuleFiles(t, root)
	run := func(t *testing.T, release bool) []model.Vulnerability {
		files := append(parseTerraformWritten(t, filepath.Join(root, "main.tf")),
			parseTerraformWritten(t, filepath.Join(root, "mod", "main.tf"))...)
		ins := releaseInspector(t, root, release)
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
		r, k := &released[i], &kept[i]
		// The identity fields the decode path populates, and the identity and
		// fingerprint built from them.
		require.Equal(t, k.QueryID, r.QueryID)
		require.Equal(t, k.FileName, r.FileName)
		require.Equal(t, k.Line, r.Line, "same line either way")
		require.Equal(t, k.ResourceType, r.ResourceType)
		require.Equal(t, k.ResourceName, r.ResourceName)
		require.NotEmpty(t, r.SearchKey, "the search key is populated on this path")
		require.Equal(t, k.SearchKey, r.SearchKey, "same search key either way")
		require.NotEmpty(t, r.IdentityKey, "the rule's path makes the identity key non-empty")
		require.Equal(t, k.IdentityKey, r.IdentityKey, "same identity key either way")
		require.Equal(t, k.ModuleCallChain, r.ModuleCallChain, "same module call chain either way")
		require.NotNil(t, r.ModuleAttribution, "the finding is attributed to the root call")
		require.Equal(t, k.ModuleAttribution.CallSite, r.ModuleAttribution.CallSite,
			"same attribution either way")
		require.Equal(t, model.FindingIdentity(k), model.FindingIdentity(r),
			"same full finding identity either way")
		require.Equal(t,
			model.GetDatadogFingerprintHash(model.SCIInfo{}, k.FileName, k.Platform, k.ResourceType,
				k.ResourceName, k.QueryID, "", k.ModuleCallChain),
			model.GetDatadogFingerprintHash(model.SCIInfo{}, r.FileName, r.Platform, r.ResourceType,
				r.ResourceName, r.QueryID, "", r.ModuleCallChain),
			"same DATADOG_FINGERPRINT input either way")
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
	ins := releaseInspector(t, root, true)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Empty(t, vulns, "a resource that expands to no instance does not exist")
}
