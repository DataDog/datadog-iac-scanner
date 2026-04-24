package kustomize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	krusty "sigs.k8s.io/kustomize/api/krusty"
	kustypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

func TestBuildMetadataIncludesTransformerAnnotations_GetTransformationsPopulated(t *testing.T) {
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))

	require.NoError(t, os.WriteFile(filepath.Join(base, "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlay, "patch.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 3
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
patchesStrategicMerge:
- patch.yaml
`), 0o600))

	require.NoError(t, ensureBuildMetadataIfNeeded(overlay))

	opts := krusty.MakeDefaultOptions()
	opts.LoadRestrictions = kustypes.LoadRestrictionsNone
	opts.PluginConfig = kustypes.DisabledPluginConfig()
	opts.PluginConfig.HelmConfig.Enabled = false
	k := krusty.MakeKustomizer(opts)
	rm, err := k.Run(filesys.MakeFsOnDisk(), overlay)
	require.NoError(t, err)

	var anyTrans bool
	for _, res := range rm.Resources() {
		trans, err := res.GetTransformations()
		require.NoError(t, err)
		if len(trans) > 0 {
			anyTrans = true
			break
		}
	}
	require.True(t, anyTrans, "with transformerAnnotations in buildMetadata, GetTransformations should be non-empty for patched resources")
}
