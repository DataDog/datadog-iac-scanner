package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	measured, err := MeasurePackage(t.Context(), packageRoot, ResourceLimits{})
	require.NoError(t, err)
	require.NotNil(t, resolution.Usage, "usage counted during digest verification spares admission a walk")
	require.Equal(t, measured, *resolution.Usage)
}

// TestLoadManifestV1PreservesUnresolvedStatus checks that an entry recorded as
// unresolved stays final, with the code and detail the manifest recorded. A
// manifest without the fields, or with a code this version does not know, gets
// the code its reason classifies to. The detail is redacted again on read.
func TestLoadManifestV1PreservesUnresolvedStatus(t *testing.T) {
	const secret = "SECRETXYZ987"
	tests := []struct {
		name       string
		failure    map[string]any
		wantReason string
		wantCode   string
		wantDetail string
	}{
		{
			name:       "fields written by a current preparation",
			failure:    map[string]any{"failure": "fetch failed", "failure_code": "network", "failure_detail": "dial tcp: no such host"},
			wantReason: "fetch failed", wantCode: "network", wantDetail: "dial tcp: no such host",
		},
		{
			name:       "manifest written before the fields existed",
			failure:    map[string]any{"failure": "versions endpoint returned HTTP 502"},
			wantReason: "versions endpoint returned HTTP 502", wantCode: "http_5xx", wantDetail: "",
		},
		{
			name:       "well-formed code from a resolver outside the scanner is kept",
			failure:    map[string]any{"failure": "fetch failed", "failure_code": "request_limit_exceeded"},
			wantReason: "fetch failed", wantCode: "request_limit_exceeded", wantDetail: "",
		},
		{
			name:       "malformed code is dropped",
			failure:    map[string]any{"failure": "fetch failed", "failure_code": "Bad Code!"},
			wantReason: "fetch failed", wantCode: "unknown", wantDetail: "",
		},
		{
			name:       "overlong code is dropped",
			failure:    map[string]any{"failure": "fetch failed", "failure_code": strings.Repeat("a", 200)},
			wantReason: "fetch failed", wantCode: "unknown", wantDetail: "",
		},
		{
			name: "credentials in the detail are redacted on read",
			failure: map[string]any{
				"failure": "fetch failed", "failure_code": "network",
				"failure_detail": "error downloading 'https://user:" + secret + "@modules.example/acme/vpc': no such host",
			},
			wantReason: "fetch failed", wantCode: "network",
			wantDetail: "error downloading 'https://modules.example/acme/vpc': no such host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			manifestPath := filepath.Join(dir, "modules.json")
			require.NoError(t, os.Mkdir(filepath.Join(dir, "modules"), 0o755))
			module := map[string]any{
				"source":      "example.invalid/module",
				"source_type": "git",
				"status":      "unresolved",
				"declarations": []map[string]any{{
					"filename":    "main.tf",
					"line_start":  1,
					"line_end":    3,
					"module_name": "example",
				}},
			}
			for k, v := range tt.failure {
				module[k] = v
			}
			writeManifestJSON(t, manifestPath, map[string]any{
				"schema_version": ManifestSchemaVersion,
				"root":           "modules",
				"modules":        []map[string]any{module},
			})

			manifest, err := LoadManifest(t.Context(), manifestPath)
			require.NoError(t, err)
			_, err = NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
				Source: "example.invalid/module",
			})
			var unresolved *tfmodules.UnresolvedError
			require.ErrorAs(t, err, &unresolved)
			require.False(t, unresolved.NotApplicable, "a recorded failure is final")
			require.Equal(t, tt.wantReason, unresolved.Reason)
			require.Equal(t, tt.wantCode, ClassifyFailure(err))
			require.Equal(t, tt.wantDetail, unresolved.Detail)
			require.NotContains(t, unresolved.Detail, secret)
		})
	}
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

func TestLoadManifestV1ReportsEachEntryAgainstSharedPackageDigest(t *testing.T) {
	dir := t.TempDir()
	packageRoot := filepath.Join(dir, "modules", "network")
	for _, name := range []string{"vpc", "subnet"} {
		require.NoError(t, os.MkdirAll(filepath.Join(packageRoot, name), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(packageRoot, name, "main.tf"), []byte(name), 0o644))
	}
	digest, err := ComputePackageDigest(t.Context(), packageRoot)
	require.NoError(t, err)
	entry := func(name, contentDigest string) map[string]any {
		return map[string]any{
			"source":         "example/" + name + "/aws",
			"package_root":   "network",
			"local_path":     "network/" + name,
			"content_digest": contentDigest,
			"status":         "resolved",
			"declarations": []map[string]any{{
				"filename": "main.tf", "line_start": 1, "line_end": 3, "module_name": name,
			}},
		}
	}
	manifestPath := filepath.Join(dir, "modules.json")
	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules":        []map[string]any{entry("vpc", digest), entry("subnet", digest)},
	})
	manifest, err := LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	require.Len(t, manifest.Entries, 2)

	writeManifestJSON(t, manifestPath, map[string]any{
		"schema_version": ManifestSchemaVersion,
		"root":           "modules",
		"modules":        []map[string]any{entry("vpc", digest), entry("subnet", "sha256:stale")},
	})
	_, err = LoadManifest(t.Context(), manifestPath)
	require.ErrorContains(t, err, "modules[1]: content_digest mismatch")
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

func TestManifestModuleRejectionLeavesTheOtherEntries(t *testing.T) {
	declaration := ManifestDeclaration{
		Filename:   "main.tf",
		LineStart:  1,
		LineEnd:    4,
		ModuleName: "vpc",
	}
	good := ManifestModule{
		Source:       "git::https://example.com/acme/vpc.git",
		Status:       ManifestStatusUnresolved,
		Failure:      "fixture has no package",
		Declarations: []ManifestDeclaration{declaration},
	}
	require.Empty(t, ManifestModuleRejection(&good, nil))

	emptySource := good
	emptySource.Source = "  "
	require.Equal(t, "source is required", ManifestModuleRejection(&emptySource, nil))

	accepted := NewManifestEntryIndex()
	accepted.Add(&good)

	duplicate := good
	require.Contains(t, ManifestModuleRejection(&duplicate, accepted), "duplicate module declaration")

	otherDeclaration := declaration
	otherDeclaration.Filename = "other.tf"
	resolved := ManifestModule{
		Source:        good.Source,
		Status:        ManifestStatusResolved,
		LocalPath:     "pkg",
		PackageRoot:   "pkg",
		ContentDigest: "sha256:abc",
		Declarations:  []ManifestDeclaration{otherDeclaration},
	}
	require.Empty(t, ManifestModuleRejection(&resolved, accepted))
	resolved.ContentDigest = ""
	require.Equal(t, "content_digest is required for a resolved module", ManifestModuleRejection(&resolved, nil))
}

// TestManifestEntryIndexScalesWithMatchingKeysNotTotalEntries indexes many
// distinct sources, the way buildManifestModules does, and checks that a
// duplicate is still caught by source and declaration rather than by scanning
// every previously accepted entry.
func TestManifestEntryIndexScalesWithMatchingKeysNotTotalEntries(t *testing.T) {
	index := NewManifestEntryIndex()
	const distinctSources = 5000
	for i := range distinctSources {
		module := ManifestModule{
			Source:  fmt.Sprintf("git::https://example.com/acme/mod-%d.git", i),
			Status:  ManifestStatusUnresolved,
			Failure: "fixture has no package",
			Declarations: []ManifestDeclaration{{
				Filename: "main.tf", LineStart: 1, LineEnd: 4, ModuleName: fmt.Sprintf("m%d", i),
			}},
		}
		require.Empty(t, ManifestModuleRejection(&module, index), "entry %d", i)
		index.Add(&module)
	}

	declaration := ManifestDeclaration{Filename: "shared.tf", LineStart: 1, LineEnd: 4, ModuleName: "shared"}
	first := ManifestModule{
		Source: "git::https://example.com/acme/shared.git", Status: ManifestStatusUnresolved,
		Failure: "fixture has no package", Declarations: []ManifestDeclaration{declaration},
	}
	require.Empty(t, ManifestModuleRejection(&first, index))
	index.Add(&first)

	// Same source and declaration: a real duplicate, caught against the one
	// bucket it belongs to.
	duplicate := first
	require.Contains(t, ManifestModuleRejection(&duplicate, index), "duplicate module declaration")

	// Same source, a different declaration: not a duplicate.
	otherDeclaration := declaration
	otherDeclaration.ModuleName = "shared2"
	distinctDeclaration := first
	distinctDeclaration.Declarations = []ManifestDeclaration{otherDeclaration}
	require.Empty(t, ManifestModuleRejection(&distinctDeclaration, index))
}
