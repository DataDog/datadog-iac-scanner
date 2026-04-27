package helm

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/cli/values"
)

func testHelmFixtureChartDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "test", "fixtures", "test_helm")
}

func TestRenderChart_invalidChartPath(t *testing.T) {
	ctx := context.Background()
	_, err := RenderChart(ctx, &RenderOptions{
		ChartPath:   "/this/path/does/not/exist/chart",
		IncludeCRDs: true,
	})
	require.Error(t, err)
}

func TestRenderChart_valuesInlineAndSkipTests(t *testing.T) {
	ctx := context.Background()
	chartDir := testHelmFixtureChartDir(t)
	out, err := RenderChart(ctx, &RenderOptions{
		ChartPath:   chartDir,
		IncludeCRDs: true,
		SkipTests:   true,
		ValuesInline: map[string]interface{}{
			"service": map[string]interface{}{
				"port": 9090,
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.Resources)
	var joined strings.Builder
	for _, r := range out.Resources {
		joined.Write(r.Content)
	}
	require.Contains(t, joined.String(), "9090")
}

func TestMergedValuesInlineBytes_UsesAllValuesFilesBeforeInline(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	override := filepath.Join(dir, "override.yaml")
	require.NoError(t, os.WriteFile(base, []byte("service:\n  port: 80\n  type: ClusterIP\n"), 0o600))
	require.NoError(t, os.WriteFile(override, []byte("service:\n  port: 8080\n"), 0o600))

	out, err := mergedValuesInlineBytes(&RenderOptions{
		ChartPath:   dir,
		ValuesFiles: []string{base, override},
		ValuesInline: map[string]interface{}{
			"service": map[string]interface{}{
				"type": "LoadBalancer",
			},
		},
		ValuesMerge: valuesMergeOverride,
	})
	require.NoError(t, err)
	txt := string(out)
	require.Contains(t, txt, "port: 8080")
	require.Contains(t, txt, "type: LoadBalancer")
}

func TestApplyValuesInline_ReplacesWholeValuesFileStack(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	override := filepath.Join(dir, "override.yaml")
	require.NoError(t, os.WriteFile(base, []byte("service:\n  port: 80\n"), 0o600))
	require.NoError(t, os.WriteFile(override, []byte("service:\n  port: 8080\n"), 0o600))

	valueOpts := &values.Options{ValueFiles: []string{base, override}}
	cleanup, err := applyValuesInline(ctx, valueOpts, &RenderOptions{
		ChartPath:   dir,
		ValuesFiles: []string{base, override},
		ValuesInline: map[string]interface{}{
			"service": map[string]interface{}{
				"type": "LoadBalancer",
			},
		},
		ValuesMerge: valuesMergeOverride,
	})
	require.NoError(t, err)
	defer cleanup()
	require.Len(t, valueOpts.ValueFiles, 1)
	require.NotEqual(t, base, valueOpts.ValueFiles[0])
	require.NotEqual(t, override, valueOpts.ValueFiles[0])
}

func TestApplyValuesInline_CleanupRemovesTempFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	require.NoError(t, os.WriteFile(base, []byte("service:\n  port: 80\n"), 0o600))

	valueOpts := &values.Options{ValueFiles: []string{base}}
	cleanup, err := applyValuesInline(ctx, valueOpts, &RenderOptions{
		ChartPath:   dir,
		ValuesFiles: []string{base},
		ValuesInline: map[string]interface{}{
			"service": map[string]interface{}{
				"type": "LoadBalancer",
			},
		},
		ValuesMerge: valuesMergeOverride,
	})
	require.NoError(t, err)
	require.Len(t, valueOpts.ValueFiles, 1)
	tempPath := valueOpts.ValueFiles[0]
	_, statErr := os.Stat(tempPath)
	require.NoError(t, statErr)

	cleanup()

	_, statErr = os.Stat(tempPath)
	require.Error(t, statErr)
	require.True(t, os.IsNotExist(statErr))
}

func TestValuesFilePathForRead_RejectsSymlinkEscape(t *testing.T) {
	chartDir := t.TempDir()
	outsideDir := t.TempDir()
	secret := filepath.Join(outsideDir, "secret.yaml")
	require.NoError(t, os.WriteFile(secret, []byte("password: hunter2\n"), 0o600))

	link := filepath.Join(chartDir, "values.yaml")
	require.NoError(t, os.Symlink(secret, link))

	_, err := valuesFilePathForRead(chartDir, "values.yaml")
	require.Error(t, err, "symlinked values file pointing outside the chart must be rejected")
}

func TestValuesFilePathForRead_AcceptsSymlinkInsideChart(t *testing.T) {
	chartDir := t.TempDir()
	real := filepath.Join(chartDir, "real-values.yaml")
	require.NoError(t, os.WriteFile(real, []byte("service:\n  port: 80\n"), 0o600))
	link := filepath.Join(chartDir, "values.yaml")
	require.NoError(t, os.Symlink(real, link))

	p, err := valuesFilePathForRead(chartDir, "values.yaml")
	require.NoError(t, err)
	require.Equal(t, filepath.Base(real), filepath.Base(p), "symlinked values file inside chart should be accepted and resolved")
}

func TestRenderChart_PreservesExplicitReleaseName(t *testing.T) {
	ctx := context.Background()
	chartDir := testHelmFixtureChartDir(t)
	out, err := RenderChart(ctx, &RenderOptions{
		ChartPath:    chartDir,
		ReleaseName:  "custom-release",
		IncludeCRDs:  true,
		ValuesInline: map[string]interface{}{},
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.Resources)
	var joined strings.Builder
	for _, r := range out.Resources {
		joined.Write(r.Content)
	}
	require.Contains(t, joined.String(), "custom-release")
}
