package kustomize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestGeneratorConfigLine_secondGeneratorBlock(t *testing.T) {
	dir := t.TempDir()
	kust := filepath.Join(dir, "kustomization.yaml")
	content := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
configMapGenerator:
- name: first
  literals:
  - a=b
secretGenerator:
- name: secret-a
  literals:
  - s=t
configMapGenerator:
- name: second
  literals:
  - c=d
`
	require.NoError(t, os.WriteFile(kust, []byte(content), 0o600))
	o := &model.KustomizeOrigin{GeneratorConfigFile: kust}
	line, p := generatorConfigLine(o, "second")
	require.Equal(t, kust, p)
	require.Equal(t, 12, line)
}
