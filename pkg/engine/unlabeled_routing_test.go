package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// movedFileRule fires once per moved block of a document, reporting the
// block with its file-local list index — the name rules actually report.
// The parser renders a file's repeated moved blocks as a list and a lone one
// as a plain object, so the rule has a branch for each shape.
const movedFileRule = `package datadog

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	is_array(doc.moved)
	some idx
	m := doc.moved[idx]
	m.from

	result := {
		"documentId": doc.id,
		"resourceType": "moved",
		"resourceName": sprintf("%d", [idx]),
		"searchKey": sprintf("moved[%d]", [idx]),
	}
}

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	is_object(doc.moved)
	doc.moved.from

	result := {
		"documentId": doc.id,
		"resourceType": "moved",
		"resourceName": "",
		"searchKey": "moved",
	}
}
`

// Two files of one external module each declare ONE moved block — both files
// report the same bare declaration key for their lone block — routed through
// one call: the module-wide index orders the blocks across files (first
// file's block is .0, second file's .1), so the two routed copies keep distinct addresses and both
// findings survive. With file-local indexing each lone block kept the bare
// address, both copies were addressed module.m.moved and the second finding
// collapsed into the first (K9CODESEC-7158).
func TestInspect_ExternalModuleFileUnlabeledBlocksStayDistinct(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	require.NoError(t, os.MkdirAll(stackDir, 0o755))

	// The external module: two files, one moved block each. Neither file
	// alone has a collision, so only the module-wide index tells them apart.
	firstPath := filepath.Join(cacheDir, "first.tf")
	require.NoError(t, os.WriteFile(firstPath, []byte(`
moved {
  from = aws_a.first
  to   = aws_b.first
}
`), 0o644))
	secondPath := filepath.Join(cacheDir, "second.tf")
	require.NoError(t, os.WriteFile(secondPath, []byte(`
moved {
  from = aws_a.second
  to   = aws_b.second
}
`), 0o644))

	callerPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(callerPath, []byte(`
module "m" {
  source = "../cache"
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, firstPath)...)
	files = append(files, parseTerraform(t, secondPath)...)
	files = append(files, parseTerraform(t, callerPath)...)

	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "moved_rule", Content: movedFileRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "moved-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       tr,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetExternalModulePaths([]string{cacheDir})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 2, "each file's moved block is reported through the call")
	ids := map[string]bool{}
	for i := range vulns {
		require.NotEmpty(t, vulns[i].ResourceID, "each routed copy carries its address")
		ids[vulns[i].ResourceID] = true
	}
	require.Len(t, ids, 2, "the two routed addresses are distinct")
	require.Contains(t, ids, "module.m.moved.0", "first file's block is indexed first")
	require.Contains(t, ids, "module.m.moved.1", "second file's block keeps a distinct index")
	require.EqualValues(t, 0, tr.IdentityGaps, "no finding falls back to the legacy fingerprint")
}
