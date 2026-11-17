package test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test_E2ECrossRootLiteral checks 3.8: a companion in another source root
// that names a bucket by its literal name relates to it, and one under
// examples/ does not.
func Test_E2ECrossRootLiteral(t *testing.T) {
	rules := mustAbs(t, filepath.Join("testdata", "terraform_rules"))
	out := t.TempDir()
	runTerraformScanTo(t, filepath.Join("fixtures", "cross-root"), rules, out)

	found := anchoredLines(t, out, "Bucket without enabled versioning companion")
	require.Equal(t, []string{"fixtures/cross-root/prod/main.tf:5"}, found)
}
