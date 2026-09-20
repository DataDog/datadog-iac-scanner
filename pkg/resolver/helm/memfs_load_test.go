/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */

package helm

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// chartFilesFromDir reads every regular file under root, keyed by "chart/"
// plus its path relative to root — the shape a pushed analyze request carries.
func chartFilesFromDir(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files["chart/"+filepath.ToSlash(rel)] = data
		return nil
	})
	require.NoError(t, err)
	return files
}

// resolvedByRoot indexes resolved helm files by their path relative to the
// chart root, so disk and in-memory renders of the same chart compare entry
// by entry.
func resolvedByRoot(t *testing.T, resolved model.ResolvedFiles, root string) map[string]model.ResolvedHelm {
	t.Helper()
	normalizedRoot := filepath.ToSlash(filepath.Clean(root))
	out := make(map[string]model.ResolvedHelm, len(resolved.File))
	for _, f := range resolved.File {
		rel, ok := strings.CutPrefix(filepath.ToSlash(f.FileName), normalizedRoot+"/")
		require.True(t, ok, "resolved path %q is not under the chart root %q", f.FileName, root)
		require.NotContains(t, out, rel, "duplicate resolved entry for %q", rel)
		out[rel] = f
	}
	return out
}

// TestResolveParityDiskVersusMemFS renders the richest fixture chart (a
// directory subchart with its own .helmignore and CRDs) once through the real
// filesystem and once through an in-memory FS, and asserts the renders agree
// on every resolved manifest, split id, invocation marker, id map and
// exclusion — the contract server-mode helm support depends on.
func TestResolveParityDiskVersusMemFS(t *testing.T) {
	ctx := context.Background()
	chartPath := helmFixturePath(t, "test_helm_subchart")

	diskResolved, err := (&Resolver{}).Resolve(ctx, chartPath)
	require.NoError(t, err)

	files := chartFilesFromDir(t, chartPath)
	memResolved, err := NewResolver(vfs.NewMemFS(files)).Resolve(ctx, "chart")
	require.NoError(t, err)

	diskEntries := resolvedByRoot(t, diskResolved, chartPath)
	memEntries := resolvedByRoot(t, memResolved, "chart")
	require.Len(t, diskEntries, len(memEntries))

	for rel, diskFile := range diskEntries {
		memFile, ok := memEntries[rel]
		require.True(t, ok, "in-memory render is missing %q", rel)
		require.Equal(t, diskFile.Content, memFile.Content, "rendered content mismatch for %q", rel)
		require.Equal(t, diskFile.OriginalData, memFile.OriginalData, "original template mismatch for %q", rel)
		require.Equal(t, diskFile.SplitID, memFile.SplitID, "split id mismatch for %q", rel)
		require.Equal(t, diskFile.SourceDocumentIndex, memFile.SourceDocumentIndex,
			"source document index mismatch for %q", rel)
		require.Equal(t, diskFile.HelmInvocation, memFile.HelmInvocation,
			"helm invocation mismatch for %q", rel)
		require.Equal(t, diskFile.IDInfo, memFile.IDInfo, "id map mismatch for %q", rel)
		require.Equal(t, diskFile.IsCRD, memFile.IsCRD, "CRD flag mismatch for %q", rel)
	}

	// Exclusions must agree modulo the root prefix.
	require.Len(t, memResolved.Excluded, len(diskResolved.Excluded))
	diskExcluded := make(map[string]struct{}, len(diskResolved.Excluded))
	for _, p := range diskResolved.Excluded {
		rel := strings.TrimPrefix(filepath.ToSlash(p), filepath.ToSlash(chartPath)+"/")
		diskExcluded[rel] = struct{}{}
	}
	for _, p := range memResolved.Excluded {
		rel := strings.TrimPrefix(filepath.ToSlash(p), "chart/")
		require.Contains(t, diskExcluded, rel, "in-memory render excluded an unexpected file %q", rel)
		delete(diskExcluded, rel)
	}
	require.Empty(t, diskExcluded, "in-memory render did not exclude every raw chart file")
}

// TestResolveMemFSPartialChartRendersWithoutSpuriousEscalation asserts the
// walk never probes unpushed subdirectories: a partially pushed chart renders
// and records no missing path. A speculative probe of standard subdirs
// (templates/, crds/) would surface escalation requests for files that
// legitimately do not exist; chart completeness is the IDE's job.
func TestResolveMemFSPartialChartRendersWithoutSpuriousEscalation(t *testing.T) {
	ctx := context.Background()
	chartPath := helmFixturePath(t, "test_helm_subchart")

	// Simulate a push that carried the subchart's Chart.yaml but not its
	// templates.
	files := chartFilesFromDir(t, chartPath)
	for p := range files {
		if strings.HasPrefix(p, "chart/charts/subchart/templates/") {
			delete(files, p)
		}
	}
	memfs := vfs.NewMemFS(files)

	_, err := NewResolver(memfs).Resolve(ctx, "chart")
	require.NoError(t, err, "a chart missing optional files must still render")
	require.Empty(t, memfs.MissingFiles(),
		"the walk must not probe unpushed subdirectories, which would surface as escalation requests")
}

// TestResolvedChartFilePathPushedShape pins that a forward-slash chart root (a
// pushed analyze request) yields forward-slash resolved paths: on Windows,
// filepath.Join would otherwise produce backslashed findings that no longer
// match the pushed path shape.
func TestResolvedChartFilePathPushedShape(t *testing.T) {
	got := resolvedChartFilePath("chart", "templates/deployment.yaml")
	require.Equal(t, "chart/templates/deployment.yaml", got)
}
