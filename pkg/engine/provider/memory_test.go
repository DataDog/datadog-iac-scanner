/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package provider

import (
	"context"
	"io"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

func TestMemorySourceProvider_GetSources_FiltersByExtension(t *testing.T) {
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

func TestMemorySourceProvider_GetSources_FiltersByPath(t *testing.T) {
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

// collect runs GetSources and returns the emitted filename -> content map.
func collect(t *testing.T, p *MemorySourceProvider, exts model.Extensions) map[string]string {
	t.Helper()
	got := map[string]string{}
	sink := func(_ context.Context, filename string, content io.ReadCloser) error {
		b, _ := io.ReadAll(content)
		_ = content.Close()
		got[filename] = string(b)
		return nil
	}
	noopResolver := func(_ context.Context, _ string) ([]string, error) { return nil, nil }
	if err := p.GetSources(context.Background(), exts, sink, noopResolver); err != nil {
		t.Fatalf("GetSources: %v", err)
	}
	return got
}
