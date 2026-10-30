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

// movedRule fires once per document with a moved block, reporting the block
// the way rules do: the resource type alone, with the file-local name (empty
// for a lone block in the file).
const movedRule = `package datadog

DatadogPolicy contains result if {
	some i
	m := input.document[i].moved
	m.from

	result := {
		"documentId": input.document[i].id,
		"resourceType": "moved",
		"resourceName": "",
		"searchKey": "moved",
	}
}
`

// Two files of one root each declaring a moved block: both findings resolve
// their own block under the file-local name rules report, carry distinct
// module-wide addresses (moved.0 / moved.1) and so distinct fingerprints, and
// none of them falls back to the legacy fingerprint (zero identity gaps).
func TestInspect_RepeatedUnlabeledBlocksKeepDistinctIdentities(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.tf", "b.tf"} {
		body := "moved {\n  from = aws_a." + name + "\n  to   = aws_b." + name + "\n}\n"
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(body), 0o644))
	}
	files := parseTerraform(t, filepath.Join(root, "a.tf"))
	files = append(files, parseTerraform(t, filepath.Join(root, "b.tf"))...)

	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "moved_rule", Content: movedRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "moved-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       tr,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "one finding per moved block")

	ids := map[string]bool{}
	for i := range vulns {
		require.NotEmpty(t, vulns[i].ResourceID, "each finding carries its Terraform address")
		require.Equal(t, ".", vulns[i].RootModule)
		ids[vulns[i].ResourceID] = true
	}
	idList := make([]string, 0, len(ids))
	for id := range ids {
		idList = append(idList, id)
	}
	require.ElementsMatch(t, []string{"moved.0", "moved.1"}, idList,
		"the two blocks are distinguished by their module-wide index")
	require.EqualValues(t, 0, tr.IdentityGaps, "no finding falls back to the legacy fingerprint")

	// Distinct addresses must mean distinct fingerprints.
	require.NotEqual(t, vulns[0].ResourceID, vulns[1].ResourceID)
}
