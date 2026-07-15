package modulegraph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

type stubResolver struct {
	resolution resolver.Resolution
	resolve    func(*tfmodules.ParsedModule) (resolver.Resolution, error)
}

func (r stubResolver) Resolve(
	_ context.Context, module *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	if r.resolve != nil {
		return r.resolve(module)
	}
	return r.resolution, nil
}

func TestResolveAssemblesModuleMetadataAndPaths(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath: moduleDir,
		}},
		MaxDepth: 2,
	})

	require.Equal(t, []string{filepath.Join(moduleDir, "main.tf")}, result.ScanPaths)
	require.Equal(t, map[string]string{
		moduleDir: "git::https://github.com/acme/network//modules/vpc?ref=v1@1.2.3",
	}, result.SourceMappings)
	require.Equal(t, []ResolvedModule{{
		CallerRoot:       root,
		Source:           "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1",
		Version:          "1.2.3",
		RequestedVersion: "1.2.3",
		Name:             "network",
		LocalPath:        moduleDir,
		CanonicalSource:  "git::https://github.com/acme/network//modules/vpc?ref=v1@1.2.3",
	}}, result.Modules)
}

func TestResolveReportsUnresolvedModulesWhenRequired(t *testing.T) {
	root, _ := writeModuleGraphFixture(t)
	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolve: func(*tfmodules.ParsedModule) (resolver.Resolution, error) {
			return resolver.Resolution{}, errors.New("missing hosted artifact")
		}},
		MaxDepth:         2,
		FailOnUnresolved: true,
	})

	require.ErrorContains(t, result.Error, "missing hosted artifact")
}

func TestResolvePreservesConcreteResolutionMetadata(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)
	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath:        moduleDir,
			RequestedVersion: "1.2.3",
			ResolvedVersion:  "1.2.4",
			CanonicalSource:  "https://example.com/acme/network@1.2.4",
			ContentDigest:    "sha256:abc",
			Provenance:       "prefetched",
			Outcome:          "resolved",
		}},
		MaxDepth: 2,
	})

	require.Len(t, result.Modules, 1)
	module := result.Modules[0]
	require.Equal(t, "1.2.4", module.Version)
	require.Equal(t, "1.2.3", module.RequestedVersion)
	require.Equal(t, "1.2.4", module.ResolvedVersion)
	require.Equal(t, "https://example.com/acme/network@1.2.4", module.CanonicalSource)
	require.Equal(t, "sha256:abc", module.ContentDigest)
	require.Equal(t, "prefetched", module.Provenance)
	require.Equal(t, "resolved", module.Outcome)
	require.Equal(t, module.CanonicalSource, result.SourceMappings[moduleDir])
}

func TestResolveCleanupIsIdempotent(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)
	var cleanupCalls atomic.Int32

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath: moduleDir,
			Cleanup: func() {
				cleanupCalls.Add(1)
			},
		}},
		MaxDepth: 2,
	})

	result.Cleanup()
	result.Cleanup()
	require.Equal(t, int32(1), cleanupCalls.Load())
}

func TestResolveTraversesLocalModuleToRemoteModule(t *testing.T) {
	root, wrapperDir, remoteDir := writeNestedModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths: []string{root},
		DiscoveryPaths: []string{
			filepath.Join(root, "main.tf"),
			filepath.Join(wrapperDir, "main.tf"),
		},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath: remoteDir,
		}},
		MaxDepth: 3,
	})

	require.Equal(t, []string{filepath.Join(remoteDir, "main.tf")}, result.ScanPaths)
	require.Len(t, result.Modules, 1)
	require.Equal(t, "registry.example.com/acme/network/aws", result.Modules[0].Source)
	require.Equal(t, wrapperDir, result.Modules[0].CallerRoot)
}

func TestResolveRestrictsRepositoryCallsToDiscoveryPaths(t *testing.T) {
	root := t.TempDir()
	allowedDir := filepath.Join(root, "allowed")
	excludedDir := filepath.Join(root, "excluded")
	require.NoError(t, os.MkdirAll(allowedDir, 0o755))
	require.NoError(t, os.MkdirAll(excludedDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(allowedDir, "main.tf"), []byte(`resource "x" "allowed" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(excludedDir, "main.tf"), []byte(`resource "x" "excluded" {}`), 0o644))
	allowedFile := filepath.Join(root, "main.tf")
	excludedFile := filepath.Join(root, "experimental.tf")
	require.NoError(t, os.WriteFile(allowedFile, []byte(`module "allowed" { source = "allowed" }`), 0o644))
	require.NoError(t, os.WriteFile(excludedFile, []byte(`module "excluded" { source = "excluded" }`), 0o644))

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{allowedFile},
		Resolver: stubResolver{resolve: func(module *tfmodules.ParsedModule) (resolver.Resolution, error) {
			if module.Source == "allowed" {
				return resolver.Resolution{LocalPath: allowedDir}, nil
			}
			return resolver.Resolution{LocalPath: excludedDir}, nil
		}},
		MaxDepth: 1,
	})

	require.Equal(t, []string{filepath.Join(allowedDir, "main.tf")}, result.ScanPaths)
}

func TestResolveSkipsFilteredLocalModuleTrees(t *testing.T) {
	root := t.TempDir()
	wrapperDir := filepath.Join(root, "modules", "wrapper")
	remoteDir := filepath.Join(root, "remote")
	require.NoError(t, os.MkdirAll(wrapperDir, 0o755))
	require.NoError(t, os.MkdirAll(remoteDir, 0o755))
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`module "wrapper" { source = "./modules/wrapper" }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(wrapperDir, "main.tf"), []byte(`module "remote" { source = "remote" }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(remoteDir, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{rootFile},
		Resolver:       stubResolver{resolution: resolver.Resolution{LocalPath: remoteDir}},
		MaxDepth:       2,
	})

	require.Empty(t, result.ScanPaths)
}

func TestResolveDeduplicatesEquivalentGitCalls(t *testing.T) {
	root := t.TempDir()
	remoteDir := filepath.Join(root, "remote")
	require.NoError(t, os.MkdirAll(remoteDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(remoteDir, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`
module "a" { source = "git::https://example.com/mod.git?ref=main" }
module "b" { source = "git::https://example.com/mod.git?ref=main" }
`), 0o644))
	var calls atomic.Int32

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{rootFile},
		DiscoveryPaths: []string{rootFile},
		Resolver: stubResolver{resolve: func(*tfmodules.ParsedModule) (resolver.Resolution, error) {
			calls.Add(1)
			return resolver.Resolution{LocalPath: remoteDir}, nil
		}},
		MaxDepth: 1,
	})

	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, []string{filepath.Join(remoteDir, "main.tf")}, result.ScanPaths)
	require.Len(t, result.Modules, 2)
}

func TestResolveKeepsHostedCallsDistinct(t *testing.T) {
	root := t.TempDir()
	remoteA, remoteB := filepath.Join(root, "remote-a"), filepath.Join(root, "remote-b")
	for _, dir := range []string{remoteA, remoteB} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))
	}
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`
module "a" { source = "git::https://example.com/mod.git?ref=main" }
module "b" { source = "git::https://example.com/mod.git?ref=main" }
`), 0o644))

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{rootFile},
		DiscoveryPaths: []string{rootFile},
		Resolver: stubResolver{resolve: func(module *tfmodules.ParsedModule) (resolver.Resolution, error) {
			if module.Name == "a" {
				return resolver.Resolution{LocalPath: remoteA}, nil
			}
			return resolver.Resolution{LocalPath: remoteB}, nil
		}},
		MaxDepth:             1,
		CallScopedResolution: true,
	})

	require.ElementsMatch(t, []string{
		filepath.Join(remoteA, "main.tf"),
		filepath.Join(remoteB, "main.tf"),
	}, result.ScanPaths)
}

func TestResolveKeepsUnversionedRegistryCallsDistinctByName(t *testing.T) {
	root := t.TempDir()
	remoteA := filepath.Join(root, "remote-a")
	remoteB := filepath.Join(root, "remote-b")
	for _, dir := range []string{remoteA, remoteB} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))
	}
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`
module "a" { source = "same/source/aws" }
module "b" { source = "same/source/aws" }
`), 0o644))

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{rootFile},
		DiscoveryPaths: []string{rootFile},
		Resolver: stubResolver{resolve: func(module *tfmodules.ParsedModule) (resolver.Resolution, error) {
			if module.Name == "a" {
				return resolver.Resolution{LocalPath: remoteA}, nil
			}
			return resolver.Resolution{LocalPath: remoteB}, nil
		}},
		MaxDepth: 1,
	})

	require.ElementsMatch(t, []string{
		filepath.Join(remoteA, "main.tf"),
		filepath.Join(remoteB, "main.tf"),
	}, result.ScanPaths)
	require.Len(t, result.Modules, 2)
}

func TestResolveCountsLocalHopsTowardDepth(t *testing.T) {
	root, wrapperDir, remoteDir := writeNestedModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths: []string{root},
		DiscoveryPaths: []string{
			filepath.Join(root, "main.tf"),
			filepath.Join(wrapperDir, "main.tf"),
		},
		Resolver: stubResolver{resolution: resolver.Resolution{LocalPath: remoteDir}},
		MaxDepth: 1,
	})

	require.Empty(t, result.ScanPaths)
}

func TestFromManifestDiscoveryUsesExactSnapshotWithoutResolving(t *testing.T) {
	repositoryRoot := t.TempDir()
	moduleRoot := filepath.Join(t.TempDir(), "modules", "vpc")
	moduleFile := filepath.Join(moduleRoot, "main.tf")
	discovery := &resolver.ManifestDiscovery{
		Complete:  true,
		ScanPaths: []string{moduleFile},
		Calls: []resolver.ManifestDiscoveryCall{{
			CallID:           "vpc-call",
			CallerPath:       "stacks/network/main.tf",
			Name:             "vpc",
			Source:           "terraform-aws-modules/vpc/aws",
			RequestedVersion: "~> 5.0",
		}},
		SourceMappings: map[string]string{
			moduleRoot: "registry.terraform.io/terraform-aws-modules/vpc/aws@5.1.2",
		},
		ModuleMappings: []resolver.ManifestModuleMapping{{
			CallID:          "vpc-call",
			LocalPath:       moduleRoot,
			ResolvedVersion: "5.1.2",
			CanonicalSource: "registry.terraform.io/terraform-aws-modules/vpc/aws@5.1.2",
			ContentDigest:   "sha256:abc",
			Provenance:      "prefetched",
			Outcome:         "resolved",
		}},
	}

	result := FromManifestDiscovery(discovery, repositoryRoot, 1)

	require.NoError(t, result.Error)
	require.Equal(t, []string{moduleFile}, result.ScanPaths)
	require.Equal(t, discovery.SourceMappings, result.SourceMappings)
	require.Equal(t, []ResolvedModule{{
		CallerRoot:       filepath.Join(repositoryRoot, "stacks", "network"),
		Source:           "terraform-aws-modules/vpc/aws",
		Version:          "5.1.2",
		RequestedVersion: "~> 5.0",
		ResolvedVersion:  "5.1.2",
		Name:             "vpc",
		LocalPath:        moduleRoot,
		CanonicalSource:  "registry.terraform.io/terraform-aws-modules/vpc/aws@5.1.2",
		ContentDigest:    "sha256:abc",
		Provenance:       "prefetched",
		Outcome:          "resolved",
	}}, result.Modules)
}

func TestFromManifestDiscoveryHonorsPositiveDepth(t *testing.T) {
	root := t.TempDir()
	parentRoot := filepath.Join(root, "parent")
	childRoot := filepath.Join(root, "child")
	require.NoError(t, os.MkdirAll(parentRoot, 0o755))
	require.NoError(t, os.MkdirAll(childRoot, 0o755))
	parentFile := filepath.Join(parentRoot, "main.tf")
	childFile := filepath.Join(childRoot, "main.tf")
	require.NoError(t, os.WriteFile(parentFile, nil, 0o644))
	require.NoError(t, os.WriteFile(childFile, nil, 0o644))
	discovery := &resolver.ManifestDiscovery{
		Complete:  true,
		ScanPaths: []string{childFile, parentFile},
		Calls: []resolver.ManifestDiscoveryCall{
			{CallID: "parent", CallerPath: "main.tf", Name: "parent", Source: "parent"},
			{
				CallID: "child", ParentCallID: "parent", CallerPath: filepath.Join(parentRoot, "main.tf"),
				Name: "child", Source: "child",
			},
		},
		SourceMappings: map[string]string{parentRoot: "canonical-parent", childRoot: "canonical-child"},
		ModuleMappings: []resolver.ManifestModuleMapping{
			{CallID: "parent", LocalPath: parentRoot, Outcome: "resolved"},
			{CallID: "child", LocalPath: childRoot, Outcome: "resolved"},
		},
	}

	result := FromManifestDiscovery(discovery, root, 1)

	require.Equal(t, []string{parentFile}, result.ScanPaths)
	require.Equal(t, map[string]string{parentRoot: "canonical-parent"}, result.SourceMappings)
	require.Len(t, result.Modules, 1)
	require.Equal(t, "parent", result.Modules[0].Name)
}

func TestCanonicalGitModuleSource(t *testing.T) {
	require.Equal(
		t,
		"git::https://github.com/org/repo//sub?ref=v1",
		canonicalGitModuleSource(" git::https://github.com/org/repo.git//sub?ref=v1 "),
	)
	require.Equal(
		t,
		canonicalModuleURL("git::https://github.com/org/repo.git//sub", "v1.2.3"),
		canonicalModuleURL("git::https://github.com/org/repo//sub", "v1.2.3"),
	)
	require.Equal(
		t,
		remoteResolveIdentity(&tfmodules.ParsedModule{
			Source: "git::https://github.com/org/repo.git//sub?ref=v1",
		}, false),
		remoteResolveIdentity(&tfmodules.ParsedModule{
			Source: "git::ssh://git@github.com/org/repo//sub?ref=v1",
		}, false),
	)
}

func writeModuleGraphFixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	moduleDir := filepath.Join(base, "module")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "network" {
  source  = "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1"
  version = "1.2.3"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`
resource "aws_vpc" "this" {}
`), 0o644))
	return root, moduleDir
}

func writeNestedModuleGraphFixture(t *testing.T) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	wrapperDir := filepath.Join(root, "modules", "wrapper")
	remoteDir := filepath.Join(base, "remote")
	require.NoError(t, os.MkdirAll(wrapperDir, 0o755))
	require.NoError(t, os.MkdirAll(remoteDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "wrapper" {
  source = "./modules/wrapper"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(wrapperDir, "main.tf"), []byte(`
module "network" {
  source  = "registry.example.com/acme/network/aws"
  version = "1.2.3"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(remoteDir, "main.tf"), []byte(`
resource "aws_vpc" "this" {}
`), 0o644))
	return root, wrapperDir, remoteDir
}
