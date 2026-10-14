/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// A parent's render stores the rendered template of its dependency. A template
// the parent leaves empty, here disabled by a condition, is stored by no render,
// and its raw text is not YAML, so no copy of it is stored or reported.
// plain.yaml is valid YAML even raw, so only the raw copy being withheld keeps
// it from being stored twice.
func TestPrepareDiskSources_TemplateNoRenderStoredIsNotReported(t *testing.T) {
	files := map[string]string{
		"lib/Chart.yaml": "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
		"lib/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ required \"name is required\" .Values.name }}\n",
		"lib/templates/disabled.yaml": "{{- if .Values.enabled }}\napiVersion: v1\nkind: ConfigMap\n" +
			"metadata:\n  name: off\n{{- end }}\n",
		"lib/templates/plain.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: plain\n",
		"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
			"dependencies:\n- name: lib\n  version: 1.0.0\n  repository: file://../lib\n",
		"app/values.yaml":       "lib:\n  name: web\n",
		"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
	}
	want := map[string]int{
		"app/templates/cm.yaml":    1,
		"lib/templates/cm.yaml":    1,
		"lib/templates/plain.yaml": 1,
	}

	t.Run("disk", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		for rel, body := range files {
			writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
		}
		fsp, err := provider.NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
		require.NoError(t, err)
		services, _ := buildServices(t, ctx, vfs.DiskFS{}, fsp, filepath.Join(dir, "app"), filepath.Join(dir, "lib"))
		disk, ok := DiskSourceProvider(services)
		require.True(t, ok)
		require.NoError(t, PrepareDiskSources(ctx, disk, services, "scan", false, 5, true))
		require.Equal(t, want, templatesStored(t, services, dir))
	})

	t.Run("memory", func(t *testing.T) {
		ctx := context.Background()
		pushed := make(map[string][]byte, len(files))
		for rel, body := range files {
			pushed[rel] = []byte(body)
		}
		memfs := vfs.NewMemFS(pushed)
		mp := provider.NewMemorySourceProvider(memfs, memfs.Paths(), nil, nil)
		services, _ := buildServices(t, ctx, memfs, mp, provider.ChartRoots(memfs.Paths())...)
		memory, ok := MemorySourceProvider(services)
		require.True(t, ok)
		require.NoError(t, PrepareMemorySources(ctx, memory, services, "scan", false, 5, false))
		require.Equal(t, want, templatesStored(t, services, "."))
	})
}

// withoutRaw keeps every raw file that no render stored, and drops the others.
func TestStoredRenderPathsWithoutRaw(t *testing.T) {
	stored := &storedRenderPaths{}
	require.Equal(t, []provider.InventoryFile{{Path: "a.yaml"}},
		stored.withoutRaw([]provider.InventoryFile{{Path: "a.yaml"}}), "nothing stored keeps every file")

	stored.add([]string{filepath.FromSlash("lib/templates/cm.yaml")})
	files := []provider.InventoryFile{
		{Path: "lib/templates/cm.yaml"},
		{Path: "lib/templates/disabled.yaml"},
		{Path: "app/templates/cm.yaml"},
	}
	require.Equal(t, []provider.InventoryFile{
		{Path: "lib/templates/disabled.yaml"},
		{Path: "app/templates/cm.yaml"},
	}, stored.withoutRaw(files))
}

// The sequential and the parallel prepare store the same files, on disk and in memory.
func TestPrepareSequentialMatchesParallel(t *testing.T) {
	files := map[string]string{
		"lib/Chart.yaml":        "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
		"lib/templates/cm.yaml": "name: {{ required \"name is required\" .Values.name }}\n",
		"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
			"dependencies:\n- name: lib\n  version: 1.0.0\n  repository: file://../lib\n",
		"app/values.yaml":       "lib:\n  name: web\n",
		"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
	}
	disk := func(parallel bool) map[string]int {
		ctx := context.Background()
		dir := t.TempDir()
		for rel, body := range files {
			writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
		}
		fsp, err := provider.NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
		require.NoError(t, err)
		services, _ := buildServices(t, ctx, vfs.DiskFS{}, fsp, filepath.Join(dir, "app"), filepath.Join(dir, "lib"))
		src, ok := DiskSourceProvider(services)
		require.True(t, ok)
		require.NoError(t, PrepareDiskSources(ctx, src, services, "scan", false, 5, parallel))
		return templatesStored(t, services, dir)
	}
	memory := func(parallel bool) map[string]int {
		ctx := context.Background()
		pushed := make(map[string][]byte, len(files))
		for rel, body := range files {
			pushed[rel] = []byte(body)
		}
		memfs := vfs.NewMemFS(pushed)
		mp := provider.NewMemorySourceProvider(memfs, memfs.Paths(), nil, nil)
		services, _ := buildServices(t, ctx, memfs, mp, provider.ChartRoots(memfs.Paths())...)
		src, ok := MemorySourceProvider(services)
		require.True(t, ok)
		require.NoError(t, PrepareMemorySources(ctx, src, services, "scan", false, 5, parallel))
		return templatesStored(t, services, ".")
	}
	require.Equal(t, disk(true), disk(false), "disk")
	require.Equal(t, memory(true), memory(false), "memory")
}

// Two scan paths that both hold the same Helm chart store its render once, in
// either order: the rendered copy of lib's template is not listed twice.
func TestPrepareDiskSources_RenderedFileNotDuplicatedAcrossScanPaths(t *testing.T) {
	files := map[string]string{
		"lib/Chart.yaml": "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
		"lib/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ required \"name is required\" .Values.name }}\n",
		"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
			"dependencies:\n- name: lib\n  version: 1.0.0\n  repository: file://../lib\n",
		"app/values.yaml":       "lib:\n  name: web\n",
		"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
	}
	want := map[string]int{"app/templates/cm.yaml": 1, "lib/templates/cm.yaml": 1}

	for _, order := range [][]string{{"app", "lib"}, {"lib", "app"}} {
		t.Run(order[0]+" first", func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			for rel, body := range files {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
			}
			paths := make([]string, 0, len(order))
			for _, p := range order {
				paths = append(paths, filepath.Join(dir, p))
			}
			fsp, err := provider.NewFileSystemSourceProvider(ctx, paths, nil, nil)
			require.NoError(t, err)
			services, _ := buildServices(t, ctx, vfs.DiskFS{}, fsp, paths...)
			src, ok := DiskSourceProvider(services)
			require.True(t, ok)
			require.NoError(t, PrepareDiskSources(ctx, src, services, "scan", false, 5, true))
			require.Equal(t, want, templatesStored(t, services, dir))
		})
	}
}
