/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package provider

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestMemorySourceProvider_FiltersByExtension(t *testing.T) {
	mem := vfs.NewMemFS(map[string][]byte{
		"infra/main.tf":   []byte("tf-content"),
		"infra/notes.md":  []byte("md-content"),
		"k8s/deploy.yaml": []byte("yaml-content"),
		"Dockerfile":      []byte("FROM scratch"),
	})
	p := NewMemorySourceProvider(mem, mem.Paths(), nil, nil)

	got := collect(t, p, model.Extensions{".tf": {}})
	if len(got) != 1 || got["infra/main.tf"] != "tf-content" {
		t.Errorf("with .tf only, emitted %v, want just infra/main.tf", got)
	}

	gotDocker := collect(t, p, model.Extensions{"Dockerfile": {}})
	if len(gotDocker) != 1 || gotDocker["Dockerfile"] != "FROM scratch" {
		t.Errorf("with Dockerfile only, emitted %v, want just Dockerfile", gotDocker)
	}

	gotMulti := collect(t, p, model.Extensions{".tf": {}, ".yaml": {}})
	if len(gotMulti) != 2 {
		t.Errorf("with .tf+.yaml, emitted %v, want 2 files", gotMulti)
	}
}

func TestMemorySourceProvider_FiltersByPath(t *testing.T) {
	files := map[string][]byte{
		"infra/main.tf": []byte("infra-tf"),
		"src/main.tf":   []byte("src-tf"),
	}
	tfOnly := model.Extensions{".tf": {}}

	t.Run("ignore-paths skips matching files", func(t *testing.T) {
		mem := vfs.NewMemFS(files)
		p := NewMemorySourceProvider(mem, mem.Paths(), []string{"infra/**"}, nil)
		got := collect(t, p, tfOnly)
		if len(got) != 1 || got["src/main.tf"] != "src-tf" {
			t.Errorf("with ignore-paths infra/**, emitted %v, want just src/main.tf", got)
		}
	})

	t.Run("only-paths restricts to matching files", func(t *testing.T) {
		mem := vfs.NewMemFS(files)
		p := NewMemorySourceProvider(mem, mem.Paths(), nil, []string{"infra/**"})
		got := collect(t, p, tfOnly)
		if len(got) != 1 || got["infra/main.tf"] != "infra-tf" {
			t.Errorf("with only-paths infra/**, emitted %v, want just infra/main.tf", got)
		}
	})
}

func TestMemorySourceProvider_GetBasePaths(t *testing.T) {
	p := NewMemorySourceProvider(vfs.NewMemFS(nil), nil, nil, nil)
	if got := p.GetBasePaths(); len(got) != 1 || got[0] != "." {
		t.Errorf("GetBasePaths = %v, want [.]", got)
	}
}

// collect lists the files the shared prepare reads for exts and returns the
// path -> content map.
func collect(t *testing.T, p *MemorySourceProvider, exts model.Extensions) map[string]string {
	t.Helper()
	files, err := p.WalkInventory(context.Background(), exts, utils.PoolOptions{},
		func(context.Context, string) bool { return false })
	require.NoError(t, err)
	got := map[string]string{}
	for _, f := range files {
		b, readErr := p.ReadFile(f.Path)
		require.NoError(t, readErr)
		got[f.Path] = string(b)
	}
	return got
}

func TestMemorySourceProvider_TofuShadowing(t *testing.T) {
	mem := vfs.NewMemFS(map[string][]byte{
		"infra/main.tf":      []byte("tf twin"),
		"infra/main.tofu":    []byte("tofu"),
		"infra/main.tf.json": []byte(`{}`),
		"infra/other.tf":     []byte("other"),
	})
	p := NewMemorySourceProvider(mem, mem.Paths(), nil, nil)
	exts := model.Extensions{".tf": {}, ".tofu": {}, ".tf.json": {}}

	got := collect(t, p, exts)
	if len(got) != 4 {
		t.Fatalf("emitted %d files, want 4 (both twins kept): %v", len(got), got)
	}
	if got["infra/main.tofu"] != "tofu" || got["infra/other.tf"] != "other" || got["infra/main.tf.json"] != "{}" || got["infra/main.tf"] != "tf twin" {
		t.Errorf("unexpected emitted set %v", got)
	}
}

func TestChartRoots(t *testing.T) {
	if got := ChartRoots([]string{"main.tf", "charts/app/values.yaml"}); got != nil {
		t.Errorf("ChartRoots() = %v, want nil without Chart.yaml", got)
	}
	got := ChartRoots([]string{
		"main.tf", "charts/other/Chart.yaml", "charts/app/values.yaml", "charts/app/Chart.yaml", "charts/app/Chart.yaml",
	})
	if want := []string{"charts/app", "charts/other"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ChartRoots() = %v, want %v", got, want)
	}
}

// Pushed charts are rendered under the same path filters as charts on disk.
func TestMemoryWalkInventoryRendersChartsInScope(t *testing.T) {
	pushed := []string{
		"app/Chart.yaml", "app/templates/cm.yaml",
		"lib/Chart.yaml", "lib/templates/cm.yaml",
		"other/Chart.yaml", "other/templates/cm.yaml",
	}
	tests := []struct {
		name         string
		ignore, only []string
		wantRendered []string
	}{
		{name: "no filters", wantRendered: []string{"app", "lib", "other"}},
		{name: "ignored chart", ignore: []string{"lib/**"}, wantRendered: []string{"app", "other"}},
		{name: "ignored Chart.yaml", ignore: []string{"lib/Chart.yaml"}, wantRendered: []string{"app", "other"}},
		{name: "only one chart", only: []string{"app"}, wantRendered: []string{"app"}},
		{name: "only one template", only: []string{"other/templates/cm.yaml"}, wantRendered: []string{"other"}},
		{name: "only a file outside every chart", only: []string{"main.tf"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMemorySourceProvider(nil, pushed, tt.ignore, tt.only)
			var mu sync.Mutex
			var rendered []string
			files, err := m.WalkInventory(context.Background(), model.Extensions{".yaml": {}}, utils.PoolOptions{},
				func(_ context.Context, root string) bool {
					mu.Lock()
					defer mu.Unlock()
					rendered = append(rendered, root)
					return true
				})
			require.NoError(t, err)
			require.ElementsMatch(t, tt.wantRendered, rendered)
			require.Empty(t, files, "the Helm files of a chart rendered or left out are not listed raw")
		})
	}
}

// A request whose platforms read no YAML renders no pushed chart.
func TestMemoryWalkInventoryRendersNoChartWithoutYAMLPlatform(t *testing.T) {
	m := NewMemorySourceProvider(nil, []string{"infra/main.tf", "infra/Chart.yaml", "infra/templates/cm.yaml"}, nil, nil)
	files, err := m.WalkInventory(context.Background(), model.Extensions{".tf": {}}, utils.PoolOptions{},
		func(_ context.Context, root string) bool {
			t.Errorf("chart %s rendered for a Terraform-only request", root)
			return true
		})
	require.NoError(t, err)
	require.Equal(t, []InventoryFile{{Path: "infra/main.tf", Ext: ".tf"}}, files)
}

func TestMemorySourceProvider_DockerfileNames(t *testing.T) {
	files := map[string][]byte{
		"upper/Dockerfile": []byte("FROM alpine\n"),
		"lower/dockerfile": []byte("FROM alpine\n"),
		"api.Dockerfile":   []byte("FROM alpine\n"),
		"Dockerfile.prod":  []byte("ARG TAG=3\nFROM alpine:$TAG\n"),
		"dockerfile.go":    []byte("package dockerfile\n"),
		"dockerfile.tf":    []byte("resource \"aws_s3_bucket\" \"b\" {}\n"),
	}
	mem := vfs.NewMemFS(files)
	p := NewMemorySourceProvider(mem, mem.Paths(), nil, nil)
	got := collect(t, p, model.Extensions{"Dockerfile": {}, ".dockerfile": {}, "possibleDockerfile": {}})
	// Inventory offers unregistered Dockerfile suffixes to the content gate in preparation.
	require.Len(t, got, 5)
	for _, name := range []string{"upper/Dockerfile", "lower/dockerfile", "api.Dockerfile", "Dockerfile.prod", "dockerfile.go"} {
		require.Equal(t, string(files[name]), got[name])
	}
	require.Empty(t, mem.MissingFiles())
}
