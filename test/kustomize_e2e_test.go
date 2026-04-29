package test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
	"github.com/stretchr/testify/require"
)

// TestKustomizeEndToEnd verifies representative fixtures build and produce merged YAML.
func TestKustomizeEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	ctx := context.Background()
	repoRoot, err := filepath.Abs(filepath.Join("fixtures", "test_kustomize"))
	require.NoError(t, err)
	fixtures := []string{
		filepath.Join(repoRoot, "canonical", "simple"),
		filepath.Join(repoRoot, "regressions", "namespace_overlay", "overlay"),
	}
	for _, root := range fixtures {
		t.Run(filepath.Base(root), func(t *testing.T) {
			r := kustomize.NewResolver(kustomize.Options{
				RepoRoot:           repoRoot,
				AllowHelmInflation: false,
				HelmIncludeCRDs:    true,
			})
			out, err := r.Resolve(ctx, root)
			require.NoError(t, err)
			require.Empty(t, out.Diagnostics, "%+v", out.Diagnostics)
			require.NotEmpty(t, out.File)
		})
	}
}
