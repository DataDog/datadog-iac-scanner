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
		"version": 2,
		"dir":     resolvedDir,
		"modules": map[string]any{
			"terraform-aws-modules/vpc/aws@5.0.0": map[string]any{
				"local_path":        moduleDir,
				"version":           "5.0.0",
				"origin":            "registry",
				"requested_version": "~> 5.0",
				"resolved_version":  "5.0.0",
				"canonical_source":  "registry.terraform.io/terraform-aws-modules/vpc/aws",
				"content_digest":    "sha256:abc",
				"provenance":        "prefetched",
				"outcome":           "resolved",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, manifestData, 0o644))

	m, err := LoadManifest(manifestPath)
	require.NoError(t, err)
	require.Equal(t, resolvedDir, m.Dir)
	require.Equal(t, 2, m.Version)

	data, err := json.Marshal(m)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	modules := raw["modules"].(map[string]any)
	entry := modules["terraform-aws-modules/vpc/aws@5.0.0"].(map[string]any)
	require.Equal(t, moduleDir, entry["local_path"])
	require.Equal(t, "5.0.0", entry["version"])
	require.Equal(t, "registry", entry["origin"])
	require.Equal(t, "~> 5.0", entry["requested_version"])
	require.Equal(t, "5.0.0", entry["resolved_version"])
	require.Equal(t, "sha256:abc", entry["content_digest"])
}

func TestLoadManifestAcceptsV1Fields(t *testing.T) {
	moduleDir := t.TempDir()
	manifestPath := filepath.Join(t.TempDir(), "modules.json")
	data, err := json.Marshal(map[string]any{
		"version": 1,
		"modules": map[string]any{
			"terraform-aws-modules/vpc/aws@5.0.0": map[string]any{
				"local_path": moduleDir,
				"version":    "5.0.0",
				"origin":     "registry",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))

	manifest, err := LoadManifest(manifestPath)

	require.NoError(t, err)
	require.Equal(t, 1, manifest.Version)
	require.Equal(t, "5.0.0", manifest.Modules["terraform-aws-modules/vpc/aws@5.0.0"].Version)
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

func TestPrefetchedResolverValidatesResolvedVersionAgainstConstraint(t *testing.T) {
	dir := t.TempDir()
	moduleDir := filepath.Join(dir, "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	resolver := NewPrefetchedResolver(&Manifest{
		Dir: dir,
		Modules: map[string]ManifestEntry{
			"terraform-aws-modules/vpc/aws@~> 5.0": {
				LocalPath: moduleDir,
				Version:   "5.1.2",
			},
		},
	})

	_, err := resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "~> 5.0",
	})
	require.NoError(t, err)

	resolver.manifest.Modules["terraform-aws-modules/vpc/aws@~> 6.0"] = ManifestEntry{
		LocalPath: moduleDir,
		Version:   "5.1.2",
	}
	_, err = resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "~> 6.0",
	})
	require.Error(t, err)
}

func TestPrefetchedResolverReturnsResolutionMetadata(t *testing.T) {
	moduleDir := t.TempDir()
	resolver := NewPrefetchedResolver(&Manifest{
		SchemaVersion: 2,
		Modules: map[string]ManifestEntry{
			"legacy-key": {
				LocalPath:        moduleDir,
				Version:          "5.1.2",
				RequestedVersion: "~> 5.0",
				ResolvedVersion:  "5.1.2",
				CanonicalSource:  "registry.terraform.io/terraform-aws-modules/vpc/aws",
				ContentDigest:    "sha256:abc",
				Provenance:       "hosted-cache",
				Outcome:          "resolved",
			},
		},
	})

	got, err := resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source:  "registry.terraform.io/terraform-aws-modules/vpc/aws",
		Version: "~> 5.0",
	})

	require.NoError(t, err)
	require.Equal(t, "5.1.2", got.ResolvedVersion)
	require.Equal(t, "~> 5.0", got.RequestedVersion)
	require.Equal(t, "sha256:abc", got.ContentDigest)
	require.Equal(t, "hosted-cache", got.Provenance)
	require.Equal(t, "resolved", got.Outcome)
}

func TestPrefetchedResolverRejectsManifestRequestedVersionMismatch(t *testing.T) {
	resolver := NewPrefetchedResolver(&Manifest{
		Modules: map[string]ManifestEntry{
			"terraform-aws-modules/vpc/aws": {
				LocalPath:        t.TempDir(),
				Version:          "5.1.2",
				RequestedVersion: "~> 5.0",
			},
		},
	})

	_, err := resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "~> 6.0",
	})

	require.ErrorContains(t, err, "does not match manifest request")
}

func TestPrefetchedResolverSelectsCallerSpecificEntry(t *testing.T) {
	source := "terraform-aws-modules/vpc/aws"
	version := "~> 5.0"
	first := &tfmodules.ParsedModule{
		Name: "vpc", Source: source, Version: version, FileName: "/checkout/stacks/first/main.tf", DefLine: 3,
	}
	second := &tfmodules.ParsedModule{
		Name: "vpc", Source: source, Version: version, FileName: "/checkout/stacks/second/main.tf", DefLine: 3,
	}
	firstPath, secondPath := t.TempDir(), t.TempDir()
	resolver := NewPrefetchedResolver(&Manifest{
		Modules: map[string]ManifestEntry{
			manifestModuleKey(source, version): {
				LocalPath: firstPath, Source: source, Version: "5.1.0",
			},
			"first": {
				LocalPath: firstPath, Source: source, Name: first.Name,
				CallerPath: "stacks/first/main.tf",
				CallID:     tfmodules.ModuleCallID("stacks/first/main.tf", first),
				Version:    "5.1.0",
			},
			"second": {
				LocalPath: secondPath, Source: source, Name: second.Name,
				CallerPath: "stacks/second/main.tf",
				CallID:     tfmodules.ModuleCallID("stacks/second/main.tf", second),
				Version:    "5.2.0",
			},
		},
	})

	firstResolution, err := resolver.Resolve(t.Context(), first)
	require.NoError(t, err)
	secondResolution, err := resolver.Resolve(t.Context(), second)
	require.NoError(t, err)
	require.Equal(t, firstPath, firstResolution.LocalPath)
	require.Equal(t, secondPath, secondResolution.LocalPath)

	_, err = resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Name: "vpc", Source: source, Version: version, FileName: "/checkout/stacks/third/main.tf", DefLine: 3,
	})
	require.ErrorContains(t, err, "not found in manifest")
}

func TestPrefetchedResolverLeavesLegacyCanonicalSourceUnset(t *testing.T) {
	resolver := NewPrefetchedResolver(&Manifest{
		Modules: map[string]ManifestEntry{
			"terraform-aws-modules/vpc/aws@5.0.0": {
				LocalPath: t.TempDir(),
				Version:   "5.0.0",
			},
		},
	})

	resolution, err := resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "terraform-aws-modules/vpc/aws", Version: "5.0.0",
	})

	require.NoError(t, err)
	require.Empty(t, resolution.CanonicalSource)
}

func TestLoadManifestAcceptsSymlinkedRoot(t *testing.T) {
	realRoot := t.TempDir()
	linkRoot := filepath.Join(t.TempDir(), "modules")
	require.NoError(t, os.Symlink(realRoot, linkRoot))
	moduleDir := filepath.Join(linkRoot, "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	manifestPath := filepath.Join(realRoot, "modules.json")
	data, err := json.Marshal(Manifest{
		Dir: linkRoot,
		Modules: map[string]ManifestEntry{
			"module": {LocalPath: moduleDir},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))

	_, err = LoadManifest(manifestPath)
	require.NoError(t, err)
}

func TestLoadManifestAcceptsCompleteDiscoverySnapshot(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	moduleFile := filepath.Join(moduleDir, "main.tf")
	require.NoError(t, os.WriteFile(moduleFile, []byte(`resource "x" "y" {}`), 0o644))
	manifest := completeDiscoveryManifest(root, moduleDir, moduleFile)
	manifest.Discovery.Calls = append(manifest.Discovery.Calls, ManifestDiscoveryCall{
		CallID: "a", CallerPath: "child/main.tf", Name: "child", Source: "./child",
	})
	manifest.Discovery.ScanPaths = []string{moduleFile}

	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestPath := filepath.Join(root, "modules.json")
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))
	loaded, err := LoadManifest(manifestPath)

	require.NoError(t, err)
	require.True(t, loaded.HasCompleteDiscovery())
	require.Equal(t, []string{"a", "root"}, []string{
		loaded.Discovery.Calls[0].CallID,
		loaded.Discovery.Calls[1].CallID,
	})
}

func TestCompleteDiscoveryValidationRejectsBrokenGraphs(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	moduleFile := filepath.Join(moduleDir, "main.tf")
	require.NoError(t, os.WriteFile(moduleFile, nil, 0o644))

	tests := []struct {
		name   string
		mutate func(*Manifest)
		match  string
	}{
		{
			name: "missing parent",
			mutate: func(manifest *Manifest) {
				manifest.Discovery.Calls[0].ParentCallID = "missing"
			},
			match: "references missing parent",
		},
		{
			name: "cycle",
			mutate: func(manifest *Manifest) {
				manifest.Discovery.Calls = append(manifest.Discovery.Calls, ManifestDiscoveryCall{
					CallID:       "child",
					ParentCallID: "root",
					CallerPath:   "vpc/main.tf",
					Name:         "child",
					Source:       "./child",
				})
				manifest.Discovery.Calls[0].ParentCallID = "child"
			},
			match: "contain a cycle",
		},
		{
			name: "missing mapping call",
			mutate: func(manifest *Manifest) {
				manifest.Discovery.ModuleMappings[0].CallID = "missing"
			},
			match: "references missing call",
		},
		{
			name: "unmapped scan path",
			mutate: func(manifest *Manifest) {
				manifest.Discovery.SourceMappings = nil
			},
			match: "has no source_mapping",
		},
		{
			name: "path escape",
			mutate: func(manifest *Manifest) {
				outside := filepath.Join(t.TempDir(), "outside.tf")
				require.NoError(t, os.WriteFile(outside, nil, 0o644))
				manifest.Discovery.ScanPaths = []string{outside}
			},
			match: "not confined",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := completeDiscoveryManifest(root, moduleDir, moduleFile)
			tt.mutate(manifest)
			require.ErrorContains(t, manifest.validate(), tt.match)
		})
	}
}

func TestCompleteDiscoveryRequiresSchemaVersionThree(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	moduleFile := filepath.Join(moduleDir, "main.tf")
	require.NoError(t, os.WriteFile(moduleFile, nil, 0o644))
	manifest := completeDiscoveryManifest(root, moduleDir, moduleFile)
	manifest.SchemaVersion = 2

	require.ErrorContains(t, manifest.validate(), "requires schema_version 3")
}

func completeDiscoveryManifest(root, moduleDir, moduleFile string) *Manifest {
	return &Manifest{
		SchemaVersion: 3,
		Dir:           root,
		Modules:       map[string]ManifestEntry{},
		Discovery: &ManifestDiscovery{
			Complete: true,
			Calls: []ManifestDiscoveryCall{{
				CallID:           "root",
				CallerPath:       "main.tf",
				Name:             "vpc",
				Source:           "terraform-aws-modules/vpc/aws",
				RequestedVersion: "~> 5.0",
			}},
			ScanPaths: []string{moduleFile},
			SourceMappings: map[string]string{
				moduleDir: "registry.terraform.io/terraform-aws-modules/vpc/aws@5.1.2",
			},
			ModuleMappings: []ManifestModuleMapping{{
				CallID:          "root",
				LocalPath:       moduleDir,
				ResolvedVersion: "5.1.2",
				CanonicalSource: "registry.terraform.io/terraform-aws-modules/vpc/aws@5.1.2",
				Outcome:         "resolved",
			}},
		},
	}
}
