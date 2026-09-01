package resolver

import (
	"context"
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

	m, err := LoadManifest(t.Context(), manifestPath)
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
	require.Equal(t, "5.0.0", got.ResolvedVersion)
}

func TestLoadManifestV1ResolvesRelativePackageAndVerifiesDigest(t *testing.T) {
	dir := t.TempDir()
	packageRoot := filepath.Join(dir, "modules", "vpc-package")
	moduleDir := filepath.Join(packageRoot, "modules", "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`resource "x" "y" {}`), 0o644))
	digest, err := ComputePackageDigest(t.Context(), packageRoot)
	require.NoError(t, err)

	manifestPath := filepath.Join(dir, "modules.json")
	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules": []map[string]any{{
			"source":            "terraform-aws-modules/vpc/aws",
			"requested_version": "~> 5.0",
			"resolved_version":  "5.4.0",
			"source_type":       "registry",
			"package_root":      "vpc-package",
			"local_path":        "vpc-package/modules/vpc",
			"content_digest":    digest,
			"status":            "resolved",
			"declarations": []map[string]any{{
				"filename":    "infra/main.tf",
				"line_start":  12,
				"line_end":    18,
				"module_name": "vpc",
			}},
		}},
	})

	manifest, err := LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	resolution, err := NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "~> 5.0",
	})
	require.NoError(t, err)
	require.Equal(t, moduleDir, resolution.LocalPath)
	require.Equal(t, packageRoot, resolution.PackageRoot)
	require.Equal(t, "5.4.0", resolution.ResolvedVersion)
}

func TestLoadManifestV1PreservesUnresolvedStatus(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "modules.json")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "modules"), 0o755))
	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules": []map[string]any{{
			"source":      "example.invalid/module",
			"source_type": "git",
			"status":      "unresolved",
			"failure":     "credentials_unavailable",
			"declarations": []map[string]any{{
				"filename":    "main.tf",
				"line_start":  1,
				"line_end":    3,
				"module_name": "example",
			}},
		}},
	})

	manifest, err := LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	_, err = NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "example.invalid/module",
	})
	require.ErrorContains(t, err, "credentials_unavailable")
}

func TestPrefetchedResolverChoosesMostSpecificDeclaration(t *testing.T) {
	dir := t.TempDir()
	packageRoot := filepath.Join(dir, "modules", "package")
	rootSelection := filepath.Join(packageRoot, "root")
	nestedSelection := filepath.Join(packageRoot, "nested")
	require.NoError(t, os.MkdirAll(rootSelection, 0o755))
	require.NoError(t, os.MkdirAll(nestedSelection, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootSelection, "main.tf"), []byte("root"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(nestedSelection, "main.tf"), []byte("nested"), 0o644))
	digest, err := ComputePackageDigest(t.Context(), packageRoot)
	require.NoError(t, err)

	source := "registry.example.com/acme/shared/aws"
	manifestPath := filepath.Join(dir, "modules.json")
	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules": []map[string]any{
			{
				"source":         source,
				"package_root":   "package",
				"local_path":     "package/root",
				"content_digest": digest,
				"status":         ManifestStatusResolved,
				"declarations": []map[string]any{{
					"filename":    "main.tf",
					"line_start":  1,
					"line_end":    3,
					"module_name": "shared",
				}},
			},
			{
				"source":         source,
				"package_root":   "package",
				"local_path":     "package/nested",
				"content_digest": digest,
				"status":         ManifestStatusResolved,
				"declarations": []map[string]any{{
					"filename":    "parent/main.tf",
					"line_start":  1,
					"line_end":    3,
					"module_name": "shared",
				}},
			},
		},
	})

	manifest, err := LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	prefetched := NewPrefetchedResolver(manifest)
	rootResult, err := prefetched.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: source, Name: "shared", FileName: "/repo/main.tf", DefLine: 1,
	})
	require.NoError(t, err)
	require.Equal(t, rootSelection, rootResult.LocalPath)
	nestedResult, err := prefetched.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: source, Name: "shared", FileName: "/repo/parent/main.tf", DefLine: 1,
	})
	require.NoError(t, err)
	require.Equal(t, nestedSelection, nestedResult.LocalPath)
}

func TestLoadManifestV1RejectsDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	moduleDir := filepath.Join(dir, "modules", "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte("content"), 0o644))
	manifestPath := filepath.Join(dir, "modules.json")
	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules": []map[string]any{{
			"source":         "example/module/aws",
			"local_path":     "vpc",
			"content_digest": "sha256:invalid",
			"status":         "resolved",
			"declarations": []map[string]any{{
				"filename":    "main.tf",
				"line_start":  1,
				"line_end":    3,
				"module_name": "vpc",
			}},
		}},
	})

	_, err := LoadManifest(t.Context(), manifestPath)
	require.ErrorContains(t, err, "content_digest mismatch")
}

func TestLoadManifestV1RejectsLocalPathOutsidePackageRoot(t *testing.T) {
	dir := t.TempDir()
	packageRoot := filepath.Join(dir, "modules", "package")
	selected := filepath.Join(dir, "modules", "selected")
	require.NoError(t, os.MkdirAll(packageRoot, 0o755))
	require.NoError(t, os.MkdirAll(selected, 0o755))
	manifestPath := filepath.Join(dir, "modules.json")
	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules": []map[string]any{{
			"source":         "example/module/aws",
			"package_root":   "package",
			"local_path":     "selected",
			"content_digest": "sha256:unused",
			"status":         "resolved",
			"declarations": []map[string]any{{
				"filename":    "main.tf",
				"line_start":  1,
				"line_end":    3,
				"module_name": "example",
			}},
		}},
	})

	_, err := LoadManifest(t.Context(), manifestPath)
	require.ErrorContains(t, err, "escapes package root")
}

func writeManifestJSON(t *testing.T, path string, manifest any) {
	t.Helper()
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
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

	manifest, err := LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	resolution, err := NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "example/module/aws",
	})
	require.NoError(t, err)
	require.Equal(t, selected, resolution.LocalPath)
	require.Equal(t, packageRoot, resolution.PackageRoot)
	_, err = ResolvePathWithinRoot(t.Context(), resolution.PackageRoot, shared)
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

	_, err = LoadManifest(t.Context(), manifestPath)
	require.ErrorContains(t, err, "escapes package root")
}

func TestLoadManifestRespectsCancelledContext(t *testing.T) {
	dir := t.TempDir()
	packageRoot := filepath.Join(dir, "modules", "vpc-package")
	moduleDir := filepath.Join(packageRoot, "modules", "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`resource "x" "y" {}`), 0o644))
	digest, err := ComputePackageDigest(t.Context(), packageRoot)
	require.NoError(t, err)

	manifestPath := filepath.Join(dir, "modules.json")
	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules": []map[string]any{{
			"source":         "terraform-aws-modules/vpc/aws",
			"package_root":   "vpc-package",
			"local_path":     "vpc-package/modules/vpc",
			"content_digest": digest,
			"status":         "resolved",
			"declarations": []map[string]any{{
				"filename":    "infra/main.tf",
				"line_start":  12,
				"line_end":    18,
				"module_name": "vpc",
			}},
		}},
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = LoadManifest(ctx, manifestPath)
	require.ErrorIs(t, err, context.Canceled)
}
