/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

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
	attachMissingDependencies(ctx, vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{chartDir, depDir}), ch, chartDir, 0)

	require.Empty(t, ch.Dependencies(), "an unloadable dependency must not be attached")
	var entry struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal([]byte(logBuf.String()), &entry))
	require.Equal(t, "warn", entry.Level)
	require.Contains(t, entry.Message, `helm dependency "dep"`)
	// The failure is the missing Chart.yaml, not a nonexistent dependency path.
	require.Contains(t, entry.Message, "Chart.yaml")
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

	index := newChartIndex(vfs.DiskFS{}, []string{aDir, filepath.Join(aDir, "b")})
	attachMissingDependencies(context.Background(), vfs.DiskFS{}, index, ch, aDir, 0)
	require.Equal(t, 2, dependencyTreeHeight(ch, 0), "only a -> b is attached; b -> a closes the cycle")
}

// A "file://" repository may name any directory on the host; only charts of the
// scan are read from it.
func TestAttachMissingDependencies_FileRepositoryOutsideScanIsNotLoaded(t *testing.T) {
	root := t.TempDir()
	outside := writeChartDir(t, filepath.Join(root, "outside"), "apiVersion: v2\nname: outside\nversion: 1.0.0\n")
	tests := map[string]string{
		"absolute": "file://" + filepath.ToSlash(outside),
		"relative": "file://../../outside",
	}
	for name, repository := range tests {
		t.Run(name, func(t *testing.T) {
			appDir := writeChartDir(t, filepath.Join(root, "repo", name), "apiVersion: v2\nname: app\nversion: 1.0.0\n"+
				"dependencies:\n  - name: outside\n    repository: "+repository+"\n    version: 1.0.0\n")
			ch, err := loader.LoadDir(appDir)
			require.NoError(t, err)

			var logBuf strings.Builder
			ctx := zerolog.New(&logBuf).WithContext(context.Background())
			attachMissingDependencies(ctx, vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{appDir}), ch, appDir, 0)
			require.Empty(t, ch.Dependencies())
			require.Contains(t, logBuf.String(), "not a chart of the scan")

			attachMissingDependencies(ctx, vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{appDir, outside}), ch, appDir, 0)
			require.Len(t, ch.Dependencies(), 1, "the same chart is loaded once it is part of the scan")
		})
	}
}

// An in-memory FS reads only what the client pushed, so a "file://" dependency
// it lacks is requested from the client rather than skipped.
func TestAttachMissingDependencies_UnpushedFileRepositoryIsRequested(t *testing.T) {
	memfs := vfs.NewMemFS(map[string][]byte{
		"app/Chart.yaml": []byte("apiVersion: v2\nname: app\nversion: 1.0.0\n" +
			"dependencies:\n  - name: lib\n    repository: file://../lib\n    version: 1.0.0\n"),
	})
	ch, err := loadChart(context.Background(), memfs, "app")
	require.NoError(t, err)
	attachMissingDependencies(context.Background(), memfs, newChartIndex(memfs, []string{"app"}), ch, "app", 0)
	require.Empty(t, ch.Dependencies())
	require.Contains(t, memfs.MissingFiles(), "lib")
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
