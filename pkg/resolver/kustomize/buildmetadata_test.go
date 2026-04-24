package kustomize

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildMetadataSupplementsNeeded_trueWithoutTransformerAnnotations(t *testing.T) {
	raw := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
buildMetadata:
- originAnnotations
resources: []
`
	need, err := buildMetadataSupplementsNeeded([]byte(raw))
	require.NoError(t, err)
	require.True(t, need)
}

func TestBuildMetadataSupplementsNeeded_falseWhenComplete(t *testing.T) {
	raw := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
buildMetadata:
- originAnnotations
- transformerAnnotations
resources: []
`
	need, err := buildMetadataSupplementsNeeded([]byte(raw))
	require.NoError(t, err)
	require.False(t, need)
}

func TestResolve_doesNotRewriteUserKustomizationWhenMetadataComplete(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata: {}\n"), 0o600))
	kust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
buildMetadata:
- originAnnotations
- transformerAnnotations
resources:
- cm.yaml
`
	path := filepath.Join(dir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(path, []byte(kust), 0o600))
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	r := NewResolver(Options{RepoRoot: dir, AllowHelmInflation: false})
	_, err = r.Resolve(ctx, dir)
	require.NoError(t, err)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after, "scanner must not rewrite the user's kustomization on disk")
}
