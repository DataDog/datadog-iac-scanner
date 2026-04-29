package kustomize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildMetadataStageRelPaths_includesParentDirectoryRefs(t *testing.T) {
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(base, "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  k: v\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`), 0o600))

	rels, err := BuildMetadataStageRelPaths(repo, overlay)
	require.NoError(t, err)
	require.Contains(t, rels, filepath.Join("overlay", "kustomization.yaml"))
	require.Contains(t, rels, filepath.Join("base", "cm.yaml"))
}

func TestWalkLocalKustomizations_visitsNestedBases(t *testing.T) {
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`), 0o600))

	var visited []string
	err := WalkLocalKustomizations(overlay, func(kustPath string, _ []byte) error {
		visited = append(visited, filepath.Clean(kustPath))
		return nil
	})
	require.NoError(t, err)
	require.Contains(t, visited, filepath.Join(overlay, "kustomization.yaml"))
	require.Contains(t, visited, filepath.Join(base, "kustomization.yaml"))
}

func TestBuildMetadataStageRelPaths_includesNestedChildParentRefs(t *testing.T) {
	repo := t.TempDir()
	common := filepath.Join(repo, "common")
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(common, 0o700))
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(common, "shared.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: shared\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../common/shared.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`), 0o600))

	rels, err := BuildMetadataStageRelPaths(repo, overlay)
	require.NoError(t, err)
	require.Contains(t, rels, filepath.Join("base", "kustomization.yaml"))
	require.Contains(t, rels, filepath.Join("common", "shared.yaml"))
}
