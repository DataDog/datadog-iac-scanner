package kustomize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
	krusty "sigs.k8s.io/kustomize/api/krusty"
	kustypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

func TestOriginFromResource_GeneratorUsesOrgIdNameWithoutHashSuffix(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
configMapGenerator:
- name: my-map
  literals:
  - k=v
`), 0o600))
	require.NoError(t, ensureBuildMetadataIfNeeded(dir))

	opts := krusty.MakeDefaultOptions()
	opts.LoadRestrictions = kustypes.LoadRestrictionsNone
	opts.PluginConfig = kustypes.DisabledPluginConfig()
	opts.PluginConfig.HelmConfig.Enabled = false
	k := krusty.MakeKustomizer(opts)
	rm, err := k.Run(filesys.MakeFsOnDisk(), dir)
	require.NoError(t, err)

	var found bool
	for _, res := range rm.Resources() {
		if res.GetGvk().Kind != "ConfigMap" {
			continue
		}
		origin := OriginFromResource(res, dir)
		if origin == nil || origin.OriginKind != model.KustomizeOriginGenerator {
			continue
		}
		require.Equal(t, "my-map", origin.ResourceName)
		require.NotEqual(t, res.GetName(), origin.ResourceName, "rendered name should include hash suffix while ResourceName stays stable")
		found = true
	}
	require.True(t, found, "expected a generator-origin ConfigMap")
}
