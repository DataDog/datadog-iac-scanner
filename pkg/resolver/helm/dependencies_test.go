/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

// writeChartDir creates a chart directory with the given Chart.yaml body and
// returns its path.
func writeChartDir(t *testing.T, dir, chartYAML string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte(chartYAML), 0o600))
	return dir
}

// TestAttachMissingDependencies_LoadFailureWarns covers the loadChart failure
// path: a "file://" dependency whose directory has no Chart.yaml cannot be
// loaded, which must be logged at Warn (not fail the scan) and leave the
// dependency unattached.
func TestAttachMissingDependencies_LoadFailureWarns(t *testing.T) {
	root := t.TempDir()
	chartYAML := "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n" +
		"  - name: dep\n    repository: file://./dep\n    version: 1.0.0\n"
	chartDir := writeChartDir(t, filepath.Join(root, "Chart.yaml-path"), chartYAML)

	// The dependency directory exists where file://./dep resolves (under the
	// chart), but holds no Chart.yaml, so the dependency cannot be loaded.
	depDir := filepath.Join(chartDir, "dep")
	require.NoError(t, os.MkdirAll(depDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(depDir, "values.yaml"), []byte("a: 1\n"), 0o600))

	ch, err := loader.LoadDir(chartDir)
	require.NoError(t, err)

	var logBuf strings.Builder
	ctx := zerolog.New(&logBuf).WithContext(context.Background())
	attachMissingDependencies(ctx, vfs.DiskFS{}, nil, ch, chartDir, 0)

	require.Empty(t, ch.Dependencies(), "an unloadable dependency must not be attached")
	require.Contains(t, logBuf.String(), `"level":"warn"`)
	require.Contains(t, logBuf.String(), "helm dependency")
	require.Contains(t, logBuf.String(), "dep")
	require.Contains(t, logBuf.String(), "of chart")
	require.Contains(t, logBuf.String(), "could not be loaded")
	// The failure is the missing Chart.yaml inside the existing directory,
	// not a nonexistent dependency path.
	require.Contains(t, logBuf.String(), "Chart.yaml")
}

// TestAttachMissingDependencies_CycleTerminates covers a two-chart dependency
// cycle over "file://" repositories: the dependency that points back at an
// ancestor is skipped, so the cycle stops after one level instead of unfolding
// to maxDependencyDepth.
func TestAttachMissingDependencies_CycleTerminates(t *testing.T) {
	root := t.TempDir()
	aYAML := "apiVersion: v2\nname: a\nversion: 1.0.0\ndependencies:\n" +
		"  - name: b\n    repository: file://./b\n    version: 1.0.0\n"
	bYAML := "apiVersion: v2\nname: b\nversion: 1.0.0\ndependencies:\n" +
		"  - name: a\n    repository: file://../../a\n    version: 1.0.0\n"
	aDir := writeChartDir(t, filepath.Join(root, "a"), aYAML)
	writeChartDir(t, filepath.Join(root, "a", "b"), bYAML)

	ch, err := loader.LoadDir(aDir)
	require.NoError(t, err)

	type done struct{}
	finished := make(chan done, 1)
	go func() {
		attachMissingDependencies(
			context.Background(), vfs.DiskFS{}, nil, ch, aDir, 0)
		finished <- done{}
	}()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("attachMissingDependencies did not terminate on a dependency cycle")
	}

	require.Equal(t, 2, dependencyTreeHeight(ch, 0), "only a -> b is attached; b -> a closes the cycle")
}

// dependencyTreeHeight returns the number of dependency edges on the longest
// chain below ch, guarding against runaway trees with a hard visit limit.
func dependencyTreeHeight(ch *chart.Chart, limit int) int {
	if limit > 4*maxDependencyDepth {
		return limit
	}
	best := 0
	for _, dep := range ch.Dependencies() {
		if h := dependencyTreeHeight(dep, limit+1); h > best {
			best = h
		}
	}
	return best + 1
}

func TestLoadChart_DropsNonTemplateFiles(t *testing.T) {
	dir := writeChartDir(t, filepath.Join(t.TempDir(), "app"), "apiVersion: v2\nname: app\nversion: 1.0.0\n")
	tpl := filepath.Join(dir, "templates")
	require.NoError(t, os.MkdirAll(tpl, 0o755))
	for name, body := range map[string]string{
		"cm.yaml": "kind: ConfigMap\n", "_helpers.tpl": "{{/* h */}}", "NOTES.txt": "hi", "BUILD.bazel": "filegroup(name = \"x\")",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(tpl, name), []byte(body), 0o600))
	}

	ch, err := loadChart(vfs.DiskFS{}, dir)
	require.NoError(t, err)

	var names []string
	for _, f := range ch.Templates {
		names = append(names, filepath.Base(f.Name))
	}
	require.ElementsMatch(t, []string{"cm.yaml", "_helpers.tpl", "NOTES.txt"}, names)
}
