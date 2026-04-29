package kustomize

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrepareHelmChartsIfNeeded_ErrMaxStagingBytes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	scratch := t.TempDir()
	charts := filepath.Join(root, "charts", "mini")
	require.NoError(t, os.MkdirAll(filepath.Join(charts, "templates"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "Chart.yaml"), []byte("apiVersion: v2\nname: mini\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "values.yaml"), []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata: {}\n"), 0o600))

	kust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
- name: mini
  releaseName: r
`
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(kust), 0o600))

	_, _, diags, err := PrepareHelmChartsIfNeeded(ctx, root, root, scratch, true, true, 1)
	require.ErrorIs(t, err, ErrMaxStagingBytes)
	require.NotEmpty(t, diags)
}

func TestPrepareHelmChartsIfNeeded_InvalidValuesMerge(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	scratch := t.TempDir()
	charts := filepath.Join(root, "charts", "mini")
	require.NoError(t, os.MkdirAll(filepath.Join(charts, "templates"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "Chart.yaml"), []byte("apiVersion: v2\nname: mini\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "values.yaml"), []byte("{}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"), 0o600))
	kust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
- name: mini
  valuesMerge: banana
`
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(kust), 0o600))
	_, _, diags, err := PrepareHelmChartsIfNeeded(ctx, root, root, scratch, true, true, 0)
	require.NoError(t, err)
	require.NotEmpty(t, diags)
	require.Equal(t, "kustomize-helm-values-invalid", diags[0].QueryID)
}

func TestPrepareHelmChartsIfNeeded_StagesSiblingBaseRefs(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	charts := filepath.Join(overlay, "charts", "mini")
	require.NoError(t, os.MkdirAll(filepath.Join(charts, "templates"), 0o700))
	require.NoError(t, os.MkdirAll(base, 0o700))

	require.NoError(t, os.WriteFile(filepath.Join(charts, "Chart.yaml"), []byte("apiVersion: v2\nname: mini\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "values.yaml"), []byte("{}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-helm\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-base\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- cm.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
helmCharts:
- name: mini
  releaseName: rel
`), 0o600))

	buildRoot, fsRoot, diags, err := PrepareHelmChartsIfNeeded(ctx, repo, overlay, t.TempDir(), true, true, 0)
	require.NoError(t, err)
	require.Empty(t, diags)
	require.NotEqual(t, overlay, buildRoot)
	require.Equal(t, filepath.Dir(buildRoot), fsRoot)

	raw, err := os.ReadFile(filepath.Join(buildRoot, "kustomization.yaml"))
	require.NoError(t, err)
	txt := string(raw)
	require.Contains(t, txt, "../base")
	require.NotContains(t, txt, "helmCharts:")

	stagedBaseFile := filepath.Join(fsRoot, "base", "cm.yaml")
	_, err = os.Stat(stagedBaseFile)
	require.NoError(t, err)

	stagedContent, err := os.ReadFile(filepath.Join(buildRoot, "kustomization.yaml"))
	require.NoError(t, err)
	require.True(t, strings.Contains(string(stagedContent), "../base") || strings.Contains(string(stagedContent), "base"))
}

func TestPrepareHelmChartsIfNeeded_StagesCustomValuesFiles(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	overlay := filepath.Join(repo, "overlay")
	charts := filepath.Join(overlay, "charts", "mini")
	require.NoError(t, os.MkdirAll(filepath.Join(charts, "templates"), 0o700))

	require.NoError(t, os.WriteFile(filepath.Join(charts, "Chart.yaml"), []byte("apiVersion: v2\nname: mini\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "values.yaml"), []byte("service:\n  port: 80\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "templates", "svc.yaml"), []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec:\n  ports:\n  - port: {{ .Values.service.port }}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "custom-values.yaml"), []byte("service:\n  port: 9090\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
- name: mini
  releaseName: rel
  valuesFile: custom-values.yaml
`), 0o600))

	buildRoot, fsRoot, diags, err := PrepareHelmChartsIfNeeded(ctx, repo, overlay, t.TempDir(), true, true, 0)
	require.NoError(t, err)
	require.Empty(t, diags)
	require.Equal(t, filepath.Dir(buildRoot), fsRoot)
	_, err = os.Stat(filepath.Join(buildRoot, "custom-values.yaml"))
	require.NoError(t, err)
}

func TestPrepareHelmChartsIfNeeded_RewritesNestedBaseHelmCharts(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	charts := filepath.Join(base, "charts", "mini")
	require.NoError(t, os.MkdirAll(filepath.Join(charts, "templates"), 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))

	require.NoError(t, os.WriteFile(filepath.Join(charts, "Chart.yaml"), []byte("apiVersion: v2\nname: mini\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "values.yaml"), []byte("{}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: nested\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
- name: mini
  releaseName: rel
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`), 0o600))

	buildRoot, _, diags, err := PrepareHelmChartsIfNeeded(ctx, repo, overlay, t.TempDir(), true, true, 0)
	require.NoError(t, err)
	require.Empty(t, diags)

	stagedBaseKust := filepath.Join(filepath.Dir(buildRoot), "base", "kustomization.yaml")
	raw, err := os.ReadFile(stagedBaseKust)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "helmCharts:")
	require.Contains(t, string(raw), ".iac-scanner-helm-out")
}

func TestPrepareHelmChartsIfNeeded_StripsHelmChartsWhenInflationDisabled(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	charts := filepath.Join(repo, "charts", "mini")
	require.NoError(t, os.MkdirAll(filepath.Join(charts, "templates"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "Chart.yaml"), []byte("apiVersion: v2\nname: mini\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "values.yaml"), []byte("{}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(charts, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: disabled\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "local.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: keep-me\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- local.yaml
helmCharts:
- name: mini
  releaseName: rel
`), 0o600))

	buildRoot, _, diags, err := PrepareHelmChartsIfNeeded(ctx, repo, repo, t.TempDir(), false, true, 0)
	require.NoError(t, err)
	require.NotEmpty(t, diags)
	require.Equal(t, "kustomize-helm-inflation-disabled", diags[0].QueryID)

	raw, err := os.ReadFile(filepath.Join(buildRoot, "kustomization.yaml"))
	require.NoError(t, err)
	require.NotContains(t, string(raw), "helmCharts:")
	require.Contains(t, string(raw), "local.yaml")
}

func TestPrepareHelmChartsIfNeeded_DoesNotPreRejectRemoteRepoWithoutVersion(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(repo, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
- name: mini
  repo: https://example.com/charts
  releaseName: rel
`), 0o600))

	_, _, diags, err := PrepareHelmChartsIfNeeded(ctx, repo, repo, t.TempDir(), true, true, 0)
	require.NoError(t, err)
	for _, d := range diags {
		require.NotEqual(t, "kustomize-helm-remote-chart-invalid", d.QueryID)
	}
}

func TestHelmValueFilesForEntry_RejectsEscape(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "overlay")
	entry := map[string]interface{}{
		"valuesFile": "../../secrets.yaml",
	}
	_, err := helmValueFilesForEntry(root, staging, entry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "escapes the staged repo root")
}

func TestStagedHelmChartPath_RejectsEscape(t *testing.T) {
	stagedRepo := t.TempDir()
	kustDir := filepath.Join(stagedRepo, "overlay")

	cases := []struct {
		name      string
		chartHome string
		chart     string
	}{
		{"chartHome traversal", "../../../etc", "passwd"},
		{"chart name traversal", "charts", "../../../etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := stagedHelmChartPath(stagedRepo, kustDir, tc.chartHome, tc.chart)
			require.Error(t, err)
			require.Contains(t, err.Error(), "escapes the staged repo root")
		})
	}
}

func TestStagedHelmChartPath_AcceptsInRoot(t *testing.T) {
	stagedRepo := t.TempDir()
	kustDir := filepath.Join(stagedRepo, "overlay")
	require.NoError(t, os.MkdirAll(filepath.Join(kustDir, "charts", "mini"), 0o700))

	got, err := stagedHelmChartPath(stagedRepo, kustDir, "charts", "mini")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(kustDir, "charts", "mini"), got)
}

func TestPrepareHelmChartsIfNeeded_RejectsLocalChartEscape(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(repo, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmGlobals:
  chartHome: ../../../etc
helmCharts:
- name: passwd
  releaseName: rel
`), 0o600))

	_, _, diags, err := PrepareHelmChartsIfNeeded(ctx, repo, repo, t.TempDir(), true, true, 0)
	require.NoError(t, err)
	var sawEscape bool
	for _, d := range diags {
		if d.QueryID == "kustomize-helm-chart-escape" {
			sawEscape = true
			require.Contains(t, d.Message, "escapes the staged repo root")
		}
		require.NotEqual(t, "kustomize-helm-render-failed", d.QueryID)
	}
	require.True(t, sawEscape, "%+v", diags)
}
