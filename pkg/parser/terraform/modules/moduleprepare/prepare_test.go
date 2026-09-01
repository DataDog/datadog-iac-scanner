package moduleprepare

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

func TestPrepareBuildsRecursiveArtifactWithInjectedPrivateResolver(t *testing.T) {
	root := t.TempDir()
	parentSource := "git::https://git.example/acme/parent.git?ref=v1.0.0"
	childSource := "git::https://git.example/acme/child.git?ref=v2.0.0"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "parent" {
  source = "`+parentSource+`"
}
`)

	sourceRoot := t.TempDir()
	parentPackage := filepath.Join(sourceRoot, "parent")
	childPackage := filepath.Join(sourceRoot, "child")
	writeFile(t, filepath.Join(parentPackage, "main.tf"), `
module "child" {
  source = "`+childSource+`"
}
resource "aws_vpc" "parent" {}
`)
	writeFile(t, filepath.Join(childPackage, "main.tf"), `resource "aws_subnet" "child" {}`)

	privateResolver := &fixtureResolver{packages: map[string]string{
		parentSource: parentPackage,
		childSource:  childPackage,
	}}
	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot:      root,
		ArtifactDir:         artifactDir,
		AdditionalResolvers: []resolver.Resolver{privateResolver},
		HostAllowlist:       []string{"git.example"},
		CacheDir:            filepath.Join(t.TempDir(), "cache"),
	})
	require.NoError(t, err)
	require.False(t, result.TimedOut)
	require.Empty(t, result.Failures)
	require.Len(t, result.Modules, 2)
	require.Equal(t, 2, privateResolver.cleanupCount())

	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	parentResolution, err := resolver.NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: parentSource,
	})
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(parentResolution.LocalPath, "main.tf"))
	childResolution, err := resolver.NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: childSource,
	})
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(childResolution.LocalPath, "main.tf"))
	var childEntry resolver.ManifestModule
	for _, entry := range manifest.Entries {
		if entry.Source == childSource {
			childEntry = entry
		}
	}
	require.Contains(t, childEntry.Declarations[0].Filename, filepath.Base(parentResolution.PackageRoot))
}

func TestPrepareKeepsUnresolvedModulesWithoutDroppingResolvedModules(t *testing.T) {
	root := t.TempDir()
	goodSource := "git::https://git.example/acme/good.git?ref=v1"
	badSource := "git::https://git.example/acme/missing.git?ref=v1"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "good" {
  source = "`+goodSource+`"
}
module "missing" {
  source = "`+badSource+`"
}
`)
	goodPackage := filepath.Join(t.TempDir(), "good")
	writeFile(t, filepath.Join(goodPackage, "main.tf"), `resource "aws_vpc" "good" {}`)

	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		DiscoveryPaths: []string{"main.tf"},
		Resolver: &fixtureResolver{
			packages: map[string]string{goodSource: goodPackage},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.Failures, 1)
	require.Len(t, result.Modules, 2)

	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	prefetched := resolver.NewPrefetchedResolver(manifest)
	_, err = prefetched.Resolve(t.Context(), &tfmodules.ParsedModule{Source: goodSource})
	require.NoError(t, err)
	_, err = prefetched.Resolve(t.Context(), &tfmodules.ParsedModule{Source: badSource})
	require.ErrorContains(t, err, "fixture has no package")

	var resolved, unresolved int
	for _, entry := range manifest.Entries {
		switch entry.Status {
		case "resolved":
			resolved++
		case "unresolved":
			unresolved++
		}
	}
	require.Equal(t, 1, resolved)
	require.Equal(t, 1, unresolved)
}

func TestPrepareArtifactManifestRejectsTamperedPackage(t *testing.T) {
	root := t.TempDir()
	source := "git::https://git.example/acme/module.git?ref=v1"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "example" {
  source = "`+source+`"
}
`)
	modulePackage := filepath.Join(t.TempDir(), "module")
	writeFile(t, filepath.Join(modulePackage, "main.tf"), `resource "aws_vpc" "example" {}`)
	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		Resolver: &fixtureResolver{
			packages: map[string]string{source: modulePackage},
		},
	})
	require.NoError(t, err)

	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	require.Len(t, manifest.Entries, 1)
	resolution, err := resolver.NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: source,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(resolution.LocalPath, "main.tf"),
		[]byte(`resource "aws_vpc" "tampered" {}`),
		0o644,
	))
	_, err = resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.ErrorContains(t, err, "content_digest mismatch")
}

func TestPreparePreservesSelectedSubdirectoryWithinPackage(t *testing.T) {
	root := t.TempDir()
	source := "git::https://git.example/acme/network.git//modules/vpc?ref=v1"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "vpc" {
  source = "`+source+`"
}
`)
	modulePackage := filepath.Join(t.TempDir(), "network")
	selected := filepath.Join(modulePackage, "modules", "vpc")
	writeFile(t, filepath.Join(selected, "main.tf"), `resource "aws_vpc" "example" {}`)
	writeFile(t, filepath.Join(modulePackage, "modules", "shared", "variables.tf"), `variable "name" {}`)

	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		Resolver: &fixtureResolver{
			packages: map[string]string{source: modulePackage},
			selected: map[string]string{source: selected},
		},
	})
	require.NoError(t, err)
	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	resolution, err := resolver.NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: source,
	})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(resolution.PackageRoot, "modules", "vpc"), resolution.LocalPath)
	require.FileExists(t, filepath.Join(resolution.PackageRoot, "modules", "shared", "variables.tf"))
}

func TestPreparePreservesDistinctUnversionedRegistryCalls(t *testing.T) {
	root := t.TempDir()
	source := "registry.example.com/acme/network/aws"
	for _, name := range []string{"first", "second"} {
		writeFile(t, filepath.Join(root, name, "main.tf"), `
module "`+name+`" {
  source = "`+source+`"
}
`)
		writeFile(t, filepath.Join(root, name, ".terraform", "modules", "modules.json"), `{}`)
	}
	firstPackage := filepath.Join(t.TempDir(), "first")
	secondPackage := filepath.Join(t.TempDir(), "second")
	writeFile(t, filepath.Join(firstPackage, "main.tf"), `resource "aws_vpc" "first" {}`)
	writeFile(t, filepath.Join(secondPackage, "main.tf"), `resource "aws_vpc" "second" {}`)

	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		Resolver: &fixtureResolver{byName: map[string]string{
			"first":  firstPackage,
			"second": secondPackage,
		}},
	})
	require.NoError(t, err)
	require.Len(t, result.Modules, 2)

	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	for _, name := range []string{"first", "second"} {
		resolution, resolveErr := resolver.NewPrefetchedResolver(manifest).Resolve(
			t.Context(),
			&tfmodules.ParsedModule{
				Source:   source,
				Name:     name,
				FileName: filepath.Join(root, name, "main.tf"),
				DefLine:  2,
			},
		)
		require.NoError(t, resolveErr)
		content, readErr := os.ReadFile(filepath.Join(resolution.LocalPath, "main.tf"))
		require.NoError(t, readErr)
		require.Contains(t, string(content), `"`+name+`"`)
	}
}

func TestPrepareRedactsSourceCredentialsWithoutBreakingLookup(t *testing.T) {
	root := t.TempDir()
	source := "git::https://user:token@git.example/acme/module.git?ref=v1"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "example" {
  source = "`+source+`"
}
`)
	modulePackage := filepath.Join(t.TempDir(), "module")
	writeFile(t, filepath.Join(modulePackage, "main.tf"), `resource "aws_vpc" "example" {}`)
	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		Resolver: &fixtureResolver{
			packages: map[string]string{source: modulePackage},
		},
	})
	require.NoError(t, err)

	data, err := os.ReadFile(result.ManifestPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "user:token")
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	_, err = resolver.NewPrefetchedResolver(manifest).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: source,
	})
	require.NoError(t, err)
}

func TestPreparePublishesPartialManifestOnResolutionTimeout(t *testing.T) {
	root := t.TempDir()
	source := "git::https://git.example/acme/slow.git?ref=v1"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "slow" {
  source = "`+source+`"
}
`)
	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot:    root,
		ArtifactDir:       artifactDir,
		Resolver:          blockingResolver{},
		ResolutionTimeout: 10 * time.Millisecond,
	})
	require.NoError(t, err)
	require.True(t, result.TimedOut)
	require.Len(t, result.Failures, 1)

	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	require.Len(t, manifest.Entries, 1)
	require.Equal(t, "unresolved", manifest.Entries[0].Status)
	require.Contains(t, manifest.Entries[0].Failure, context.DeadlineExceeded.Error())
}

func TestPrepareRecordsModulesRemovedByAdmission(t *testing.T) {
	root := t.TempDir()
	parentSource := "registry.example.com/acme/parent/aws"
	childSource := "git::https://user:token@git.example/acme/child.git?ref=v1"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "parent" {
  source = "`+parentSource+`"
}
`)
	parentPackage := filepath.Join(t.TempDir(), "parent")
	childPackage := filepath.Join(t.TempDir(), "child")
	writeFile(t, filepath.Join(parentPackage, "main.tf"), `
module "child" {
  source = "`+childSource+`"
}
resource "aws_vpc" "parent" {}
`)
	writeFile(t, filepath.Join(childPackage, "main.tf"), `resource "aws_subnet" "child" {}`)
	parentUsage, err := resolver.MeasurePackage(t.Context(), parentPackage, resolver.ResourceLimits{})
	require.NoError(t, err)

	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		Resolver: &fixtureResolver{packages: map[string]string{
			parentSource: parentPackage,
			childSource:  childPackage,
		}},
		ResourceLimits: resolver.ResourceLimits{
			MaxTotalBytes: parentUsage.Bytes,
		},
	})
	require.NoError(t, err)
	require.Len(t, result.BudgetEvents, 1)
	require.NotContains(t, result.BudgetEvents[0].Source, "user:token")

	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	require.Len(t, manifest.Entries, 2)
	var unresolved int
	for _, entry := range manifest.Entries {
		if entry.Status == resolver.ManifestStatusUnresolved {
			unresolved++
			require.Contains(t, entry.Failure, "pre-parse admission")
		}
	}
	require.Equal(t, 1, unresolved)
}

func TestPrepareMaxDepthZeroDisablesTraversal(t *testing.T) {
	root := t.TempDir()
	source := "git::https://git.example/acme/module.git?ref=v1"
	writeFile(t, filepath.Join(root, "main.tf"), `
module "example" {
  source = "`+source+`"
}
`)
	modulePackage := filepath.Join(t.TempDir(), "module")
	writeFile(t, filepath.Join(modulePackage, "main.tf"), `resource "aws_vpc" "example" {}`)
	resolverCalled := false
	depth := 0
	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		MaxDepth:       &depth,
		Resolver: &fixtureResolver{
			packages: map[string]string{source: modulePackage},
			onResolve: func() {
				resolverCalled = true
			},
		},
	})
	require.NoError(t, err)
	require.False(t, resolverCalled)
	require.Empty(t, result.Modules)
	require.Empty(t, result.Failures)
}

func TestPrepareWritesValidEmptyManifest(t *testing.T) {
	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: t.TempDir(),
		ArtifactDir:    artifactDir,
		Resolver:       &fixtureResolver{},
	})
	require.NoError(t, err)
	manifest, err := resolver.LoadManifest(t.Context(), result.ManifestPath)
	require.NoError(t, err)
	require.Empty(t, manifest.Entries)
}

func TestPrepareIgnoresTerraformCacheDirectoriesDuringDiscovery(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".terraform", "modules", "cached", "main.tf"), `
module "cached" {
  source = "git::https://git.example/acme/cached.git?ref=v1"
}
`)
	cacheDir := filepath.Join(root, "worker-cache")
	writeFile(t, filepath.Join(cacheDir, "modules", "cached", "main.tf"), `
module "worker_cached" {
  source = "git::https://git.example/acme/worker-cached.git?ref=v1"
}
`)
	artifactDir := filepath.Join(t.TempDir(), "prepared")
	result, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		CacheDir:       cacheDir,
		Resolver:       &fixtureResolver{},
	})
	require.NoError(t, err)
	require.Empty(t, result.Modules)
}

func TestPrepareDoesNotReplaceExistingArtifact(t *testing.T) {
	root := t.TempDir()
	artifactDir := t.TempDir()
	sentinel := filepath.Join(artifactDir, "sentinel")
	writeFile(t, sentinel, "keep")

	_, err := Prepare(t.Context(), &Config{
		RepositoryRoot: root,
		ArtifactDir:    artifactDir,
		Resolver:       &fixtureResolver{},
	})
	require.ErrorContains(t, err, "already exists")
	require.FileExists(t, sentinel)
}

func TestPublishArtifactDoesNotReplaceDestination(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "first")
	second := filepath.Join(parent, "second")
	destination := filepath.Join(parent, "published")
	writeFile(t, filepath.Join(first, "marker"), "first")
	writeFile(t, filepath.Join(second, "marker"), "second")

	require.NoError(t, publishArtifact(first, destination))
	require.Error(t, publishArtifact(second, destination))
	content, err := os.ReadFile(filepath.Join(destination, "marker"))
	require.NoError(t, err)
	require.Equal(t, "first", string(content))
}

type fixtureResolver struct {
	packages  map[string]string
	selected  map[string]string
	byName    map[string]string
	onResolve func()
	mu        sync.Mutex
	cleanups  int
}

func (r *fixtureResolver) Resolve(_ context.Context, module *tfmodules.ParsedModule) (resolver.Resolution, error) {
	if r.onResolve != nil {
		r.onResolve()
	}
	root, ok := r.packages[module.Source]
	if named := r.byName[module.Name]; named != "" {
		root, ok = named, true
	}
	if !ok {
		return resolver.Resolution{}, &tfmodules.UnresolvedError{Reason: "fixture has no package"}
	}
	localPath := root
	if selected := r.selected[module.Source]; selected != "" {
		localPath = selected
	}
	return resolver.Resolution{
		LocalPath:   localPath,
		PackageRoot: root,
		ResolvedRef: "fixture-ref",
		Cleanup: func() {
			r.mu.Lock()
			r.cleanups++
			r.mu.Unlock()
		},
	}, nil
}

func (r *fixtureResolver) cleanupCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cleanups
}

type blockingResolver struct{}

func (blockingResolver) Resolve(ctx context.Context, _ *tfmodules.ParsedModule) (resolver.Resolution, error) {
	<-ctx.Done()
	return resolver.Resolution{}, ctx.Err()
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}
