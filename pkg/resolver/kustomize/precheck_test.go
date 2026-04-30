package kustomize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCollectRemoteRefsFromKustomization(t *testing.T) {
	raw := `resources:
- ./local
- https://example.com/base
- git::https://github.com/org/repo.git//kustomize?ref=main
- github.com/org/another-repo//deploy?ref=main
- github.com/org/plain-repo//base
- github.com/Liujingfang1/mysql?ref=test
bases:
- git@github.com:org/repo.git//deploy?ref=main
components:
- ssh://git@example.com/acme/comp.git
patches:
- path: https://example.com/patch.yaml
transformers:
- path: github.com/org/transformers//labeler
generators:
- path: git::https://github.com/org/plugin.git//gen
helmCharts:
- name: foo
  repo: oci://registry.example.com/charts/foo
`
	got, err := CollectRemoteRefsFromKustomization([]byte(raw))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"https://example.com/base",
		"git::https://github.com/org/repo.git//kustomize?ref=main",
		"github.com/org/another-repo//deploy?ref=main",
		"github.com/org/plain-repo//base",
		"github.com/Liujingfang1/mysql?ref=test",
		"git@github.com:org/repo.git//deploy?ref=main",
		"ssh://git@example.com/acme/comp.git",
		"https://example.com/patch.yaml",
		"github.com/org/transformers//labeler",
		"git::https://github.com/org/plugin.git//gen",
	}, got)
}

func TestIsRemoteKustomizeRef(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{".", false},
		{"./local", false},
		{"../base", false},
		{"base", false},
		{"my.dir/file.yaml", false},
		{"/abs/path", false},
		{"server/foo/bar", false},
		{"my-base?ref=foo", false},

		{"https://example.com/base", true},
		{"HTTPS://EXAMPLE.com/base", true},
		{"http://example.com/base", true},
		{"ssh://git@example.com/acme/comp.git", true},
		{"oci://registry.example.com/charts/foo", true},
		{"file:///etc/passwd", true},
		{"git::https://github.com/org/plugin.git//gen", true},
		{"git@github.com:org/repo.git//deploy?ref=main", true},
		{"git@gitlab2.example.com:infra/repo.git?ref=v1", true},
		{"org-12345@github.com:foo/bar", true},
		{"github.com/Liujingfang1/mysql?ref=test", true},
		{"GitHub.com/foo/bar", true},
		{"github.com/foo/bar//sub?ref=v1", true},
		{"example.org/path/to/repo//examples/multibases/dev", true},
		{"https://example.com/path/to/repo.git/sub", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, isRemoteKustomizeRef(tc.in), "input: %q", tc.in)
		})
	}
}

func TestCollectRemoteRefsFromKustomization_HelmChartsAreOwnedByPrepass(t *testing.T) {
	raw := `helmCharts:
- name: chart-a
  repo: oci://registry.example.com/charts/foo
- name: chart-b
  repo: https://charts.example.com
`
	got, err := CollectRemoteRefsFromKustomization([]byte(raw))
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestDetectKRMInlineFunctions(t *testing.T) {
	var doc map[string]interface{}
	require.NoError(t, yaml.Unmarshal([]byte(`generators:
- apiVersion: builtin
  kind: ConfigMapGenerator
  name: x
`), &doc))
	require.True(t, DetectKRMInlineFunctions(doc))

	require.NoError(t, yaml.Unmarshal([]byte(`generators:
- path: ./plugin.yaml
`), &doc))
	require.False(t, DetectKRMInlineFunctions(doc))
}

func TestTransitiveLocalPaths_ReplacementsOnlyCollectsPathFields(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
replacements:
- source:
    kind: ConfigMap
    name: app-config
    fieldPath: data.message
  targets:
  - select:
      kind: Deployment
      name: app
    options:
      delimiter: "."
      index: 1
    fieldPaths:
    - spec.template.spec.containers.0.image
- path: repl.yaml
`), 0o600))
	got, err := TransitiveLocalPaths(dir)
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.Join(dir, "kustomization.yaml"),
		filepath.Join(dir, "repl.yaml"),
	}, got)
}

func TestTransitiveLocalPaths_IncludesUpwardLocalRefsAndEntryFile(t *testing.T) {
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
patches:
- path: ../base/patch.yaml
`), 0o600))

	got, err := TransitiveLocalPaths(overlay)
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.Join(overlay, "kustomization.yaml"),
		filepath.Join(base),
		filepath.Join(base, "patch.yaml"),
	}, got)
}

func TestTransitiveLocalPaths_RecursesIntoNestedLocalKustomizations(t *testing.T) {
	repo := t.TempDir()
	common := filepath.Join(repo, "common")
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(common, 0o700))
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(base, "Kustomization"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../common/shared.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`), 0o600))

	got, err := TransitiveLocalPaths(overlay)
	require.NoError(t, err)
	require.Contains(t, got, filepath.Join(overlay, "kustomization.yml"))
	require.Contains(t, got, filepath.Join(base, "Kustomization"))
	require.Contains(t, got, filepath.Join(common, "shared.yaml"))
}

func TestTransitiveRelativeLocalPaths_IgnoresAbsoluteRefs(t *testing.T) {
	repo := t.TempDir()
	external := t.TempDir()
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- ../shared\n- "+filepath.Join(external, "base")+"\n"), 0o600))

	got, err := TransitiveRelativeLocalPaths(overlay)
	require.NoError(t, err)
	require.Contains(t, got, overlay)
	require.Contains(t, got, filepath.Join(repo, "shared"))
	require.NotContains(t, got, filepath.Join(external, "base"))
}
