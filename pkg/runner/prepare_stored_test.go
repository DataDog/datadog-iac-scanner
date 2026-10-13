/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package runner

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// A parent's render stores the rendered template of its dependency. A template
// the parent leaves empty, here disabled by a condition, is stored by no render,
// and its raw text is not YAML, so no copy of it is stored or reported.
func TestPrepareSharedWalk_TemplateNoRenderStoredIsNotReported(t *testing.T) {
	files := map[string]string{
		"lib/Chart.yaml": "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
		"lib/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ required \"name is required\" .Values.name }}\n",
		"lib/templates/disabled.yaml": "{{- if .Values.enabled }}\napiVersion: v1\nkind: ConfigMap\n" +
			"metadata:\n  name: off\n{{- end }}\n",
		"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
			"dependencies:\n- name: lib\n  version: 1.0.0\n  repository: file://../lib\n",
		"app/values.yaml":       "lib:\n  name: web\n",
		"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
	}
	want := map[string]int{"app/templates/cm.yaml": 1, "lib/templates/cm.yaml": 1}

	t.Run("disk", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		for rel, body := range files {
			writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
		}
		fsp, err := provider.NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
		require.NoError(t, err)
		services, _ := buildServices(t, ctx, vfs.DiskFS{}, fsp, filepath.Join(dir, "app"), filepath.Join(dir, "lib"))
		shared, ok := SharedWalkProvider(services)
		require.True(t, ok)
		require.NoError(t, PrepareSharedWalk(ctx, shared, services, "scan", false, 5, true))
		require.Equal(t, want, templatesStored(t, services, dir))
	})

	t.Run("per service", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		for rel, body := range files {
			writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
		}
		fsp, err := provider.NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
		require.NoError(t, err)
		services, _ := buildServices(t, ctx, vfs.DiskFS{}, fsp, filepath.Join(dir, "app"), filepath.Join(dir, "lib"))
		var wg sync.WaitGroup
		errCh := make(chan error, len(services))
		for _, service := range services {
			wg.Add(1)
			go service.PrepareSources(ctx, "scan", false, 5, &wg, errCh,
				featureflags.NewLocalEvaluatorWithOverrides(nil))
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}
		for _, service := range services {
			if service.Parser.Parsers.GetKind() == model.KindYAML {
				require.Equal(t, want, templatesStored(t, []*Service{service}, dir))
			}
		}
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
		shared, ok := SharedMemoryProvider(services)
		require.True(t, ok)
		require.NoError(t, PrepareMemorySources(ctx, shared, services, "scan", false, 5, false))
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

// The sequential and the parallel shared walk store the same files.
func TestPrepareSharedWalk_SequentialMatchesParallel(t *testing.T) {
	files := map[string]string{
		"lib/Chart.yaml":        "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
		"lib/templates/cm.yaml": "name: {{ required \"name is required\" .Values.name }}\n",
		"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
			"dependencies:\n- name: lib\n  version: 1.0.0\n  repository: file://../lib\n",
		"app/values.yaml":       "lib:\n  name: web\n",
		"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
	}
	stored := func(parallel bool) map[string]int {
		ctx := context.Background()
		dir := t.TempDir()
		for rel, body := range files {
			writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
		}
		fsp, err := provider.NewFileSystemSourceProvider(ctx, []string{dir}, nil, nil)
		require.NoError(t, err)
		services, _ := buildServices(t, ctx, vfs.DiskFS{}, fsp, filepath.Join(dir, "app"), filepath.Join(dir, "lib"))
		shared, ok := SharedWalkProvider(services)
		require.True(t, ok)
		require.NoError(t, PrepareSharedWalk(ctx, shared, services, "scan", false, 5, parallel))
		return templatesStored(t, services, dir)
	}
	require.Equal(t, stored(true), stored(false))
}
