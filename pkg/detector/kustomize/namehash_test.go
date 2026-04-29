package kustomize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestStripKustomizeNameHashSuffix(t *testing.T) {
	require.Equal(t, "my-map", stripKustomizeNameHashSuffix("my-map-h4kk2gt9cm"))
	require.Equal(t, "x", stripKustomizeNameHashSuffix("x"))
}

func TestGeneratorConfigLine_matchesWithHashedLookupName(t *testing.T) {
	// kustomization declares "my-map"; detector may still receive a hashed name from document metadata.
	content := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nconfigMapGenerator:\n- name: my-map\n  literals:\n  - k=v\n"
	dir := t.TempDir()
	p := filepath.Join(dir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	o := &model.KustomizeOrigin{GeneratorConfigFile: p}
	line, gotPath := generatorConfigLine(o, "my-map-h4kk2gt9cm")
	require.Equal(t, p, gotPath)
	require.Equal(t, 4, line)
}
