/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"encoding/json"
	"fmt"
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
	attachMissingDependencies(ctx, vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{chartDir, depDir}), ch, chartDir)

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
	attachMissingDependencies(context.Background(), vfs.DiskFS{}, index, ch, aDir)
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
			attachMissingDependencies(ctx, vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{appDir}), ch, appDir)
			require.Empty(t, ch.Dependencies())
			require.Contains(t, logBuf.String(), "not a chart of the scan")

			attachMissingDependencies(ctx, vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{appDir, outside}), ch, appDir)
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
	attachMissingDependencies(context.Background(), memfs, newChartIndex(memfs, []string{"app"}), ch, "app")
	require.Empty(t, ch.Dependencies())
	require.Contains(t, memfs.MissingFiles(), "lib")
}

// The client can push only files of the workspace, so a "file://" dependency
// outside it is not requested.
func TestAttachMissingDependencies_FileRepositoryOutsideWorkspaceIsNotRequested(t *testing.T) {
	memfs := vfs.NewMemFS(map[string][]byte{
		"apps/app/Chart.yaml": []byte("apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n" +
			"  - name: keys\n    repository: file:///home/victim/.ssh\n    version: 1.0.0\n" +
			"  - name: etc\n    repository: file://../../../../etc\n    version: 1.0.0\n" +
			"  - name: up\n    repository: file://../..\n    version: 1.0.0\n" +
			"  - name: lib\n    repository: file://../lib\n    version: 1.0.0\n"),
	})
	ch, err := loadChart(context.Background(), memfs, "apps/app")
	require.NoError(t, err)
	attachMissingDependencies(context.Background(), memfs, newChartIndex(memfs, []string{"apps/app"}), ch, "apps/app")
	var requested []string
	for _, p := range memfs.MissingFiles() {
		requested = append(requested, filepath.ToSlash(p))
	}
	require.Equal(t, []string{"apps/lib"}, requested)
}

func TestInsideWorkspace(t *testing.T) {
	for p, want := range map[string]bool{
		"lib": true, "apps/lib": true, "apps/../lib": true, ".": false,
		"..": false, "../lib": false, "apps/../../lib": false, "/etc": false,
	} {
		require.Equal(t, want, insideWorkspace(p), p)
	}
}

// A dependency naming a remote repository is the chart published there: a chart
// of the scan with the same name but another version is not used in its place.
// Without a repository, the scan's chart is the best guess at what the build
// links, whatever its version.
func TestAttachMissingDependencies_IncompatibleVersionOnlyWithoutRepository(t *testing.T) {
	for name, tt := range map[string]struct {
		repository string
		want       int
	}{
		"remote repository": {repository: "https://charts.bitnami.com/bitnami", want: 0},
		"repository alias":  {repository: `"@bitnami"`, want: 0},
		"no repository":     {want: 1},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			repo := ""
			if tt.repository != "" {
				repo = "    repository: " + tt.repository + "\n"
			}
			appDir := writeChartDir(t, filepath.Join(root, "app"), "apiVersion: v2\nname: app\nversion: 1.0.0\n"+
				"dependencies:\n  - name: redis\n    version: ~17.3.0\n"+repo)
			devRedis := writeChartDir(t, filepath.Join(root, "tools", "dev-redis"), "apiVersion: v2\nname: redis\nversion: 0.0.1\n")
			ch, err := loader.LoadDir(appDir)
			require.NoError(t, err)
			attachMissingDependencies(context.Background(), vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{appDir, devRedis}), ch, appDir)
			require.Len(t, ch.Dependencies(), tt.want)
		})
	}
}

// A chart declared under two aliases at different versions renders each from
// the chart of the scan matching its version.
func TestAttachMissingDependencies_AliasesAtDifferentVersions(t *testing.T) {
	root := t.TempDir()
	appDir := writeChartDir(t, filepath.Join(root, "app"), "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n"+
		"  - name: lib\n    alias: c1\n    version: 1.0.0\n"+
		"  - name: lib\n    alias: c2\n    version: 2.0.0\n"+
		"  - name: lib\n    alias: c3\n    version: 2.0.0\n")
	lib1 := writeChartDir(t, filepath.Join(root, "lib1"), "apiVersion: v2\nname: lib\nversion: 1.0.0\n")
	lib2 := writeChartDir(t, filepath.Join(root, "lib2"), "apiVersion: v2\nname: lib\nversion: 2.0.0\n")
	ch, err := loader.LoadDir(appDir)
	require.NoError(t, err)
	attachMissingDependencies(context.Background(), vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, []string{appDir, lib1, lib2}), ch, appDir)
	var versions []string
	for _, dep := range ch.Dependencies() {
		versions = append(versions, dep.Metadata.Version)
	}
	require.ElementsMatch(t, []string{"1.0.0", "2.0.0"}, versions,
		"c3 shares the chart of c2, which Helm copies per alias")
}

// Charts that each depend on every chart after them are reached through
// exponentially many paths; one render attaches a bounded number of them.
func TestAttachMissingDependencies_AttachedChartsAreCapped(t *testing.T) {
	root := t.TempDir()
	const n = 12
	roots := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var deps strings.Builder
		for j := i + 1; j < n; j++ {
			fmt.Fprintf(&deps, "  - name: c%d\n    version: 1.0.0\n", j)
		}
		yaml := fmt.Sprintf("apiVersion: v2\nname: c%d\nversion: 1.0.0\n", i)
		if deps.Len() > 0 {
			yaml += "dependencies:\n" + deps.String()
		}
		roots = append(roots, writeChartDir(t, filepath.Join(root, fmt.Sprintf("c%d", i)), yaml))
	}
	ch, err := loader.LoadDir(roots[0])
	require.NoError(t, err)
	var logBuf strings.Builder
	ctx := zerolog.New(&logBuf).WithContext(context.Background())
	locator := attachMissingDependencies(ctx, vfs.DiskFS{}, newChartIndex(vfs.DiskFS{}, roots), ch, roots[0])
	require.Equal(t, maxAttachedCharts, locator.attached)
	require.Equal(t, 1, strings.Count(logBuf.String(), "attaches more than"))
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
