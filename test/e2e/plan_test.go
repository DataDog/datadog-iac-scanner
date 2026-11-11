package test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test_E2EPlanRoots checks 3.9: a plan is a root of its own whose companions
// relate to its blocks, and it is never cross-root evidence for a source
// root.
func Test_E2EPlanRoots(t *testing.T) {
	rules := mustAbs(t, filepath.Join("testdata", "terraform_rules"))
	out := t.TempDir()
	runTerraformScanTo(t, filepath.Join("fixtures", "plan"), rules, out, true)

	found := anchoredLines(t, out, "Bucket without enabled versioning companion")
	require.Equal(t, []string{"fixtures/plan/src/main.tf:1", "fixtures/plan/stack/tfplan.json:14"}, found)
}
