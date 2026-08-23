package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/stretchr/testify/require"
)

func TestLoadManifestJSONShape(t *testing.T) {
	dir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	moduleDir := filepath.Join(resolvedDir, "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))

	manifestPath := filepath.Join(resolvedDir, "modules.json")
	manifestData, err := json.Marshal(map[string]any{
		"dir": resolvedDir,
		"modules": map[string]any{
			"terraform-aws-modules/vpc/aws@5.0.0": map[string]any{
				"local_path": moduleDir,
				"version":    "5.0.0",
				"origin":     "registry",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, manifestData, 0o644))

	m, err := LoadManifest(manifestPath)
	require.NoError(t, err)
	require.Equal(t, resolvedDir, m.Dir)

	data, err := json.Marshal(m)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	modules := raw["modules"].(map[string]any)
	entry := modules["terraform-aws-modules/vpc/aws@5.0.0"].(map[string]any)
	require.Equal(t, moduleDir, entry["local_path"])
	require.Equal(t, "5.0.0", entry["version"])
	require.Equal(t, "registry", entry["origin"])
}

func TestPrefetchedResolverUsesManifest(t *testing.T) {
	dir := t.TempDir()
	moduleDir := filepath.Join(dir, "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`resource "x" "y" {}`), 0o644))

	m := &Manifest{
		Dir: dir,
		Modules: map[string]ManifestEntry{
			"terraform-aws-modules/vpc/aws@5.0.0": {LocalPath: moduleDir, Version: "5.0.0"},
		},
	}
	res := NewPrefetchedResolver(m)
	got, err := res.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "5.0.0",
	})
	require.NoError(t, err)
	require.Equal(t, moduleDir, got.LocalPath)
}

func TestLoadManifestPreservesPackageRootForSiblingModules(t *testing.T) {
	dir := t.TempDir()
	packageRoot := filepath.Join(dir, "package")
	selected := filepath.Join(packageRoot, "modules", "selected")
	shared := filepath.Join(packageRoot, "modules", "shared")
	require.NoError(t, os.MkdirAll(selected, 0o755))
	require.NoError(t, os.MkdirAll(shared, 0o755))

	manifestPath := filepath.Join(dir, "modules.json")
	manifestData, err := json.Marshal(Manifest{
		Dir: dir,
		Modules: map[string]ManifestEntry{
			"example/module/aws": {
				LocalPath:   selected,
				PackageRoot: packageRoot,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, manifestData, 0o644))

	manifest, err := LoadManifest(manifestPath)
	require.NoError(t, err)
	resolution, err := NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "example/module/aws",
	})
	require.NoError(t, err)
	require.Equal(t, selected, resolution.LocalPath)
	require.Equal(t, packageRoot, resolution.PackageRoot)
	_, err = ResolvePathWithinRoot(resolution.PackageRoot, shared)
	require.NoError(t, err)
}

func TestLoadManifestRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	packageRoot := filepath.Join(dir, "package")
	require.NoError(t, os.Mkdir(packageRoot, 0o755))
	outside := t.TempDir()
	selected := filepath.Join(packageRoot, "selected")
	require.NoError(t, os.Symlink(outside, selected))

	manifestPath := filepath.Join(dir, "modules.json")
	manifestData, err := json.Marshal(Manifest{
		Dir: dir,
		Modules: map[string]ManifestEntry{
			"example/module/aws": {
				LocalPath:   selected,
				PackageRoot: packageRoot,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, manifestData, 0o644))

	_, err = LoadManifest(manifestPath)
	require.ErrorContains(t, err, "escapes package root")
}
