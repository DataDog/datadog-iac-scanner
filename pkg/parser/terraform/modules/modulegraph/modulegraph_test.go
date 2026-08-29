package modulegraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

func BenchmarkShedToTotalLimit1000Modules(b *testing.B) {
	const count = 1000
	budget := resolver.NewResourceBudget(resolver.ResourceLimits{MaxTotalBytes: count / 2})
	modules := make([]ResolvedModule, 0, count)
	paths := make([]string, 0, count)
	for i := 0; i < count; i++ {
		root := filepath.Join("packages", fmt.Sprintf("%04d", i))
		parent := ""
		depth := i%benchmarkDepth + 1
		if depth > 1 {
			parent = filepath.Join("packages", fmt.Sprintf("%04d", i-1))
		}
		require.NoError(b, budget.AdmitPackage(root, resolver.PackageUsage{Bytes: 1, Files: 1}))
		modules = append(modules, ResolvedModule{
			Source:            fmt.Sprintf("example.com/acme/module-%04d/aws", i),
			CanonicalSource:   fmt.Sprintf("example.com/acme/module-%04d/aws", i),
			PackageRoot:       root,
			ParentPackageRoot: parent,
			Depth:             depth,
		})
		paths = append(paths, filepath.Join(root, "main.tf"))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		snapshot := walkerSnapshot{
			paths:          paths,
			modules:        modules,
			sourceMappings: make(map[string]string),
		}
		shedToTotalLimit(&snapshot, budget, count/2, true)
		if len(snapshot.modules) != count/2 {
			b.Fatalf("admitted %d modules", len(snapshot.modules))
		}
	}
}

const benchmarkDepth = 8

type stubResolver struct {
	resolution resolver.Resolution
}

func (r stubResolver) Resolve(
	_ context.Context, _ *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	return r.resolution, nil
}

type mapResolver struct {
	bySource map[string]resolver.Resolution
}

func (r mapResolver) Resolve(
	_ context.Context, mod *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	res, ok := r.bySource[mod.Source]
	if !ok {
		return resolver.Resolution{}, &tfmodules.UnresolvedError{Reason: "unknown source " + mod.Source}
	}
	return res, nil
}

type errorResolver struct {
	err error
}

func (r errorResolver) Resolve(
	_ context.Context, _ *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	return resolver.Resolution{}, r.err
}

type contextBlockingResolver struct{}

func (contextBlockingResolver) Resolve(
	ctx context.Context, _ *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	<-ctx.Done()
	return resolver.Resolution{}, ctx.Err()
}

type trackingResolver struct {
	mu       sync.Mutex
	bySource map[string]resolver.Resolution
	calls    map[string]int
}

func (r *trackingResolver) Resolve(
	_ context.Context, mod *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[mod.Source]++
	res, ok := r.bySource[mod.Source]
	if !ok {
		return resolver.Resolution{}, &tfmodules.UnresolvedError{Reason: "unknown source " + mod.Source}
	}
	return res, nil
}

func (r *trackingResolver) callCount(source string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[source]
}

type acquisitionTrackingResolver struct {
	bySource     map[string]resolver.Resolution
	release      chan struct{}
	releaseOnce  sync.Once
	entered      atomic.Int64
	activeBytes  atomic.Int64
	maximumBytes atomic.Int64
}

func (r *acquisitionTrackingResolver) Resolve(
	ctx context.Context, mod *tfmodules.ParsedModule,
) (resolver.Resolution, error) {
	res, ok := r.bySource[mod.Source]
	if !ok {
		return resolver.Resolution{}, &tfmodules.UnresolvedError{Reason: "unknown source " + mod.Source}
	}
	reserved := resolver.ResourceBudgetFromContext(ctx).Limits().MaxPackageBytes
	active := r.activeBytes.Add(reserved)
	defer r.activeBytes.Add(-reserved)
	for {
		maximum := r.maximumBytes.Load()
		if active <= maximum || r.maximumBytes.CompareAndSwap(maximum, active) {
			break
		}
	}
	if r.entered.Add(1) == 2 {
		r.releaseOnce.Do(func() { close(r.release) })
	}
	select {
	case <-ctx.Done():
		return resolver.Resolution{}, ctx.Err()
	case <-r.release:
		return res, nil
	}
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
		moduleDir: "git::https://github.com/acme/network//modules/vpc?ref=v1",
	}, result.SourceMappings)
	require.Equal(t, []ResolvedModule{{
		CallerRoot:      root,
		CallerFile:      filepath.Join(root, "main.tf"),
		CallerLine:      2,
		CallerEndLine:   5,
		Source:          "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1",
		Version:         "1.2.3",
		Name:            "network",
		LocalPath:       moduleDir,
		PackageRoot:     moduleDir,
		Depth:           1,
		CanonicalSource: "git::https://github.com/acme/network//modules/vpc?ref=v1",
	}}, result.Modules)
}

func TestResolveThreadsRegistryIdentity(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	moduleDir := filepath.Join(base, "module")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "bucket" {
  source  = "cloud-inventory/bucket/aws"
  version = "~> 9.0"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`
resource "aws_s3_bucket" "this" {}
`), 0o644))

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath:       moduleDir,
			ResolvedVersion: "9.1.0",
		}},
		MaxDepth: 2,
	})

	require.Equal(t, map[string]string{
		moduleDir: "registry.terraform.io/cloud-inventory/bucket/aws@9.1.0",
	}, result.SourceMappings)
	require.Equal(t, []ResolvedModule{{
		CallerRoot:      root,
		CallerFile:      filepath.Join(root, "main.tf"),
		CallerLine:      2,
		CallerEndLine:   5,
		Source:          "cloud-inventory/bucket/aws",
		Version:         "~> 9.0",
		ResolvedVersion: "9.1.0",
		Name:            "bucket",
		LocalPath:       moduleDir,
		PackageRoot:     moduleDir,
		Depth:           1,
		CanonicalSource: "registry.terraform.io/cloud-inventory/bucket/aws@9.1.0",
	}}, result.Modules)
}

func TestCanonicalModuleURL(t *testing.T) {
	tests := []struct {
		source  string
		version string
		want    string
	}{
		{
			source:  "cloud-inventory/bucket/aws",
			version: "9.1.0",
			want:    "registry.terraform.io/cloud-inventory/bucket/aws@9.1.0",
		},
		{
			source:  "cloud-inventory/bucket/aws",
			version: "~> 9.0",
			want:    "registry.terraform.io/cloud-inventory/bucket/aws",
		},
		{
			source:  "registry.example.com:8443/ns/name/aws//modules/child",
			version: "1.2.3",
			want:    "registry.example.com:8443/ns/name/aws//modules/child@1.2.3",
		},
		{
			source:  "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1",
			version: "1.2.3",
			want:    "git::https://github.com/acme/network//modules/vpc?ref=v1",
		},
	}
	for _, tt := range tests {
		if got := canonicalModuleURL(tt.source, tt.version); got != tt.want {
			t.Errorf("canonicalModuleURL(%q, %q) = %q, want %q", tt.source, tt.version, got, tt.want)
		}
	}
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

func TestResolveRejectsOversizedPackageAndReportsBudget(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)
	var cleanupCalls atomic.Int32

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath:   moduleDir,
			PackageRoot: moduleDir,
			Cleanup: func() {
				cleanupCalls.Add(1)
			},
		}},
		MaxDepth: 2,
		ResourceLimits: resolver.ResourceLimits{
			MaxPackageBytes: 1,
		},
	})

	require.Empty(t, result.ScanPaths)
	require.Empty(t, result.Modules)
	require.Equal(t, int32(1), cleanupCalls.Load())
	require.Len(t, result.BudgetEvents, 1)
	event := result.BudgetEvents[0]
	require.Equal(t, "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1", event.Source)
	require.Equal(t, "stream", event.Gate)
	require.Equal(t, "package_bytes", event.Limit)
	require.Equal(t, int64(1), event.Maximum)
	require.Greater(t, event.Measured, int64(1))
}

func TestResolveAdmitsOnDiskPackageDespitePerFileLimit(t *testing.T) {
	root, moduleDir := writeModuleGraphFixture(t)

	result := Resolve(context.Background(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath:   moduleDir,
			PackageRoot: moduleDir,
		}},
		MaxDepth: 2,
		ResourceLimits: resolver.ResourceLimits{
			MaxFileBytes: 1,
		},
	})

	require.NotEmpty(t, result.ScanPaths)
	require.Len(t, result.Modules, 1)
	require.Empty(t, result.BudgetEvents)
}

func TestResolveReportsStreamingBudgetFailure(t *testing.T) {
	root, _ := writeModuleGraphFixture(t)

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: errorResolver{err: &resolver.BudgetExceededError{
			Gate:     "stream",
			Limit:    "package_bytes",
			Maximum:  10,
			Measured: 11,
		}},
		MaxDepth: 2,
	})

	require.Equal(t, []BudgetEvent{{
		Source:   "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1",
		Gate:     "stream",
		Limit:    "package_bytes",
		Maximum:  10,
		Measured: 11,
	}}, result.BudgetEvents)
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

func TestResolveShedsTransitiveSubtreeBeforeDirectModule(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	root := filepath.Join(base, "root")
	direct := filepath.Join(base, "direct")
	transitive := filepath.Join(base, "transitive")
	for _, dir := range []string{root, direct, transitive} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "direct" {
  source = "example.com/acme/direct/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(direct, "main.tf"), []byte(`
resource "aws_vpc" "direct" {}
module "transitive" {
  source = "example.com/acme/transitive/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(transitive, "main.tf"), []byte(`
resource "aws_vpc" "transitive" {}
`), 0o600))
	directUsage, err := resolver.MeasurePackage(t.Context(), direct, resolver.ResourceLimits{})
	require.NoError(t, err)

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: mapResolver{bySource: map[string]resolver.Resolution{
			"example.com/acme/direct/aws": {
				LocalPath: direct,
			},
			"example.com/acme/transitive/aws": {
				LocalPath: transitive,
			},
		}},
		MaxDepth: 3,
		ResourceLimits: resolver.ResourceLimits{
			MaxTotalBytes: directUsage.Bytes,
		},
	})

	require.Len(t, result.Modules, 1)
	require.Equal(t, "example.com/acme/direct/aws", result.Modules[0].Source)
	require.Equal(t, []string{filepath.Join(direct, "main.tf")}, result.ScanPaths)
	require.Len(t, result.BudgetEvents, 1)
	require.Equal(t, "example.com/acme/transitive/aws", result.BudgetEvents[0].Source)
	require.Equal(t, "pre_parse_admission", result.BudgetEvents[0].Gate)
	require.Equal(t, 1, result.BudgetEvents[0].SheddingRank)
}

func TestResolveDoesNotTraverseDescendantsOfShedPackage(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	root := filepath.Join(base, "root")
	small := filepath.Join(base, "small")
	large := filepath.Join(base, "large")
	child := filepath.Join(base, "child")
	for _, dir := range []string{root, small, large, child} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "small" {
  source = "example.com/acme/small/aws"
}
module "large" {
  source = "example.com/acme/large/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(small, "main.tf"),
		[]byte(`resource "aws_vpc" "small" {}`),
		0o600,
	))
	require.NoError(t, os.WriteFile(filepath.Join(large, "main.tf"), []byte(`
resource "aws_vpc" "large" {
  tags = { padding = "make this package larger than the admitted sibling" }
}
module "child" {
  source = "example.com/acme/child/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(child, "main.tf"),
		[]byte(`resource "aws_vpc" "child" {}`),
		0o600,
	))
	smallUsage, err := resolver.MeasurePackage(t.Context(), small, resolver.ResourceLimits{})
	require.NoError(t, err)
	tracker := &trackingResolver{
		bySource: map[string]resolver.Resolution{
			"example.com/acme/small/aws": {LocalPath: small},
			"example.com/acme/large/aws": {LocalPath: large},
			"example.com/acme/child/aws": {LocalPath: child},
		},
		calls: make(map[string]int),
	}

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver:       tracker,
		MaxDepth:       3,
		ResourceLimits: resolver.ResourceLimits{
			MaxTotalBytes: smallUsage.Bytes,
		},
	})

	require.Zero(t, tracker.callCount("example.com/acme/child/aws"))
	require.Len(t, result.Modules, 1)
	require.Equal(t, "example.com/acme/small/aws", result.Modules[0].Source)
	require.Equal(t, []string{filepath.Join(small, "main.tf")}, result.ScanPaths)
}

func TestResolveAcquiresRemoteModulesFromParallelSeeds(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	seedA := filepath.Join(base, "seed-a")
	seedB := filepath.Join(base, "seed-b")
	moduleA := filepath.Join(base, "module-a")
	moduleB := filepath.Join(base, "module-b")
	for _, dir := range []string{seedA, seedB, moduleA, moduleB} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(seedA, "main.tf"), []byte(`
module "a" {
  source = "example.com/acme/a/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(seedB, "main.tf"), []byte(`
module "b" {
  source = "example.com/acme/b/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(moduleA, "main.tf"),
		[]byte(`resource "aws_vpc" "a" {}`),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(moduleB, "main.tf"),
		[]byte(`resource "aws_vpc" "b" {}`),
		0o600,
	))
	tracker := &trackingResolver{
		bySource: map[string]resolver.Resolution{
			"example.com/acme/a/aws": {LocalPath: moduleA},
			"example.com/acme/b/aws": {LocalPath: moduleB},
		},
		calls: make(map[string]int),
	}

	result := Resolve(t.Context(), &Request{
		RootPaths: []string{base},
		DiscoveryPaths: []string{
			filepath.Join(seedA, "main.tf"),
			filepath.Join(seedB, "main.tf"),
		},
		Resolver: tracker,
		MaxDepth: 2,
		ResourceLimits: resolver.ResourceLimits{
			MaxTotalBytes: 200 * 1024 * 1024,
		},
	})

	require.Equal(t, 1, tracker.callCount("example.com/acme/a/aws"))
	require.Equal(t, 1, tracker.callCount("example.com/acme/b/aws"))
	require.Contains(t, result.ScanPaths, filepath.Join(moduleA, "main.tf"))
	require.Contains(t, result.ScanPaths, filepath.Join(moduleB, "main.tf"))
}

func TestResolveStopsDeferredTraversalAtAcquisitionLimit(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	root := filepath.Join(base, "root")
	moduleA := filepath.Join(base, "module-a")
	moduleB := filepath.Join(base, "module-b")
	childA := filepath.Join(base, "child-a")
	childB := filepath.Join(base, "child-b")
	for _, dir := range []string{root, moduleA, moduleB, childA, childB} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "a" {
  source = "example.com/acme/a/aws"
}
module "b" {
  source = "example.com/acme/b/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(moduleA, "main.tf"), []byte(`
module "child_a" {
  source = "example.com/acme/child-a/aws"
}
resource "aws_vpc" "padding" {
  tags = { padding = "module a starts larger than module b" }
}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(moduleB, "main.tf"), []byte(`
module "child_b" {
  source = "example.com/acme/child-b/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(childA, "main.tf"),
		[]byte(`resource "aws_vpc" "child_a" {}`),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(childB, "main.tf"),
		make([]byte, 1024),
		0o600,
	))
	moduleAUsage, err := resolver.MeasurePackage(t.Context(), moduleA, resolver.ResourceLimits{})
	require.NoError(t, err)
	tracker := &trackingResolver{
		bySource: map[string]resolver.Resolution{
			"example.com/acme/a/aws":       {LocalPath: moduleA},
			"example.com/acme/b/aws":       {LocalPath: moduleB},
			"example.com/acme/child-a/aws": {LocalPath: childA},
			"example.com/acme/child-b/aws": {LocalPath: childB},
		},
		calls: make(map[string]int),
	}

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver:       tracker,
		MaxDepth:       3,
		ResourceLimits: resolver.ResourceLimits{
			MaxTotalBytes: moduleAUsage.Bytes,
		},
	})

	require.Zero(t, tracker.callCount("example.com/acme/child-a/aws"))
	require.Equal(t, 1, tracker.callCount("example.com/acme/child-b/aws"))
	require.Len(t, result.Modules, 1)
	require.Equal(t, "example.com/acme/b/aws", result.Modules[0].Source)
}

func TestResolveReservesAcquisitionAcrossConcurrentFrontiers(t *testing.T) {
	t.Parallel()

	const (
		seedCount        = 4
		maximumBytes     = int64(200)
		acquisitionBytes = maximumBytes * acquisitionOvershootFactor
	)
	base := t.TempDir()
	discoveryPaths := make([]string, 0, seedCount)
	resolutions := make(map[string]resolver.Resolution, seedCount)
	for i := range seedCount {
		seed := filepath.Join(base, fmt.Sprintf("seed-%d", i))
		module := filepath.Join(base, fmt.Sprintf("module-%d", i))
		require.NoError(t, os.MkdirAll(seed, 0o755))
		require.NoError(t, os.MkdirAll(module, 0o755))
		source := fmt.Sprintf("example.com/acme/module-%d/aws", i)
		require.NoError(t, os.WriteFile(
			filepath.Join(seed, "main.tf"),
			[]byte(fmt.Sprintf("module \"m\" {\n  source = %q\n}\n", source)),
			0o600,
		))
		require.NoError(t, os.WriteFile(
			filepath.Join(module, "main.tf"),
			[]byte(`resource "test" "example" {}`),
			0o600,
		))
		discoveryPaths = append(discoveryPaths, filepath.Join(seed, "main.tf"))
		resolutions[source] = resolver.Resolution{LocalPath: module}
	}
	tracker := &acquisitionTrackingResolver{
		bySource: resolutions,
		release:  make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result := Resolve(ctx, &Request{
		RootPaths:      []string{base},
		DiscoveryPaths: discoveryPaths,
		Resolver:       tracker,
		MaxDepth:       2,
		ResourceLimits: resolver.ResourceLimits{
			MaxPackageBytes: 300,
			MaxTotalBytes:   maximumBytes,
		},
	})

	require.NoError(t, ctx.Err())
	require.Equal(t, int64(seedCount), tracker.entered.Load())
	require.LessOrEqual(t, tracker.maximumBytes.Load(), acquisitionBytes)
	for _, event := range result.BudgetEvents {
		require.NotEqual(t, "acquisition", event.Gate)
	}
}

func TestShedToTotalLimitFiltersNestedPackagePathsByOwner(t *testing.T) {
	t.Parallel()

	parent := filepath.Join("packages", "parent")
	child := filepath.Join(parent, "nested")
	budget := resolver.NewResourceBudget(resolver.ResourceLimits{MaxTotalBytes: 1})
	require.NoError(t, budget.AdmitPackage(parent, resolver.PackageUsage{Bytes: 1, Files: 1}))
	require.NoError(t, budget.AdmitPackage(child, resolver.PackageUsage{Bytes: 2, Files: 1}))
	snapshot := walkerSnapshot{
		paths: []string{
			filepath.Join(parent, "main.tf"),
			filepath.Join(child, "main.tf"),
		},
		modules: []ResolvedModule{
			{
				CanonicalSource: "example.com/acme/parent/aws",
				PackageRoot:     parent,
				Depth:           1,
			},
			{
				CanonicalSource:   "example.com/acme/child/aws",
				PackageRoot:       child,
				ParentPackageRoot: parent,
				Depth:             2,
			},
		},
		sourceMappings: map[string]string{
			parent: "example.com/acme/parent/aws",
			child:  "example.com/acme/child/aws",
		},
	}

	shedToTotalLimit(&snapshot, budget, 1, true)

	require.Equal(t, []string{filepath.Join(parent, "main.tf")}, snapshot.paths)
	require.Equal(t, map[string]string{parent: "example.com/acme/parent/aws"}, snapshot.sourceMappings)
	require.Len(t, snapshot.modules, 1)
	require.Equal(t, parent, snapshot.modules[0].PackageRoot)
}

func TestResolveDerivesModuleAdmissionFromBaseline(t *testing.T) {
	t.Parallel()

	root, moduleDir := writeModuleGraphFixture(t)
	rootFile := filepath.Join(root, "main.tf")
	info, err := os.Stat(rootFile)
	require.NoError(t, err)

	source := "git::https://git@github.com/acme/network.git//modules/vpc?ref=v1"
	tracker := &trackingResolver{
		bySource: map[string]resolver.Resolution{
			source: {LocalPath: moduleDir},
		},
		calls: make(map[string]int),
	}
	result := Resolve(t.Context(), &Request{
		RootPaths:       []string{root},
		DiscoveryPaths:  []string{rootFile},
		BaselinePaths:   []string{rootFile},
		TotalParseBytes: info.Size(),
		Resolver:        tracker,
		MaxDepth:        2,
	})

	require.Equal(t, info.Size(), result.BaselineParseBytes)
	require.Zero(t, result.ModuleAdmissionBytes)
	require.Empty(t, result.Modules)
	require.Empty(t, result.ScanPaths)
	require.Len(t, result.BudgetEvents, 1)
	require.Equal(t, int64(0), result.BudgetEvents[0].Maximum)
	require.Zero(t, tracker.callCount(source))
}

func TestResolveConfinesRemoteLocalModulesToPackageRoot(t *testing.T) {
	root := t.TempDir()
	base := t.TempDir()
	packageRoot := filepath.Join(base, "package")
	selected := filepath.Join(packageRoot, "modules", "selected")
	shared := filepath.Join(packageRoot, "modules", "shared")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{selected, shared, outside} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "remote" {
  source = "example.com/acme/module/aws"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(selected, "main.tf"), []byte(`
module "shared" {
  source = "../shared"
}
module "escape" {
  source = "../../../outside"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(shared, "main.tf"), []byte(`resource "x" "shared" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "main.tf"), []byte(`resource "x" "outside" {}`), 0o644))

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: stubResolver{resolution: resolver.Resolution{
			LocalPath:   selected,
			PackageRoot: packageRoot,
		}},
		MaxDepth: 4,
	})

	require.Equal(t, []string{
		filepath.Join(selected, "main.tf"),
		filepath.Join(shared, "main.tf"),
	}, result.ScanPaths)
}

func TestFlatTerraformFilePathsSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`resource "x" "main" {}`), 0o644))
	outside := filepath.Join(t.TempDir(), "outside.tf")
	require.NoError(t, os.WriteFile(outside, []byte(`resource "x" "outside" {}`), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "linked.tf")))

	require.Equal(t, []string{mainPath}, flatTerraformFilePaths(t.Context(), dir, dir))
}

func TestResolveRevisitsSamePathWhenPackageRootDiffers(t *testing.T) {
	root := t.TempDir()
	base := t.TempDir()
	packageRoot := filepath.Join(base, "package")
	selected := filepath.Join(packageRoot, "modules", "selected")
	shared := filepath.Join(packageRoot, "modules", "shared")
	hidden := filepath.Join(packageRoot, "hidden")
	extra := filepath.Join(base, "extra")
	for _, dir := range []string{selected, shared, hidden, extra} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "narrow" {
  source = "git::https://example.com/narrow.git?ref=v1"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(selected, "main.tf"), []byte(`
module "shared" {
  source = "../shared"
}
module "broad" {
  source = "git::https://example.com/broad.git?ref=v1"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(shared, "main.tf"), []byte(`resource "x" "shared" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(hidden, "main.tf"), []byte(`
module "extra" {
  source = "git::https://example.com/extra.git?ref=v1"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(extra, "main.tf"), []byte(`resource "x" "extra" {}`), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(hidden, "main.tf"), filepath.Join(selected, "linked.tf")))

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver: mapResolver{bySource: map[string]resolver.Resolution{
			"git::https://example.com/narrow.git?ref=v1": {
				LocalPath:   selected,
				PackageRoot: selected,
			},
			"git::https://example.com/broad.git?ref=v1": {
				LocalPath:   selected,
				PackageRoot: packageRoot,
			},
			"git::https://example.com/extra.git?ref=v1": {
				LocalPath:   extra,
				PackageRoot: extra,
			},
		}},
		MaxDepth: 6,
	})

	require.Contains(t, result.ScanPaths, filepath.Join(selected, "main.tf"))
	require.Contains(t, result.ScanPaths, filepath.Join(shared, "main.tf"))
	require.Contains(t, result.ScanPaths, filepath.Join(extra, "main.tf"))
}

func TestResolveReportsResolutionFailure(t *testing.T) {
	root, _ := writeModuleGraphFixture(t)
	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver:       mapResolver{bySource: map[string]resolver.Resolution{}},
		MaxDepth:       2,
	})
	require.Empty(t, result.Modules)
	require.Len(t, result.Failures, 1)
	require.Equal(t, "network", result.Failures[0].Name)
	require.Contains(t, result.Failures[0].Reason, "unknown source")
}

func TestResolveReturnsPartialResultWhenPhaseDeadlineExpires(t *testing.T) {
	root, _ := writeModuleGraphFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	result := Resolve(ctx, &Request{
		RootPaths: []string{root},
		Resolver:  contextBlockingResolver{},
		MaxDepth:  2,
	})

	require.True(t, result.TimedOut)
	require.Empty(t, result.Modules)
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

func TestResolveStopsAcquiringFrontierPastAllowance(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(root, 0o755))

	batch := max(1, resolver.FetchConcurrency)
	count := batch + 2
	sources := make([]string, 0, count)
	resolutions := make(map[string]resolver.Resolution, count)
	calls := ""
	for i := range count {
		source := fmt.Sprintf("example.com/acme/m%04d/aws", i)
		sources = append(sources, source)
		dir := filepath.Join(base, fmt.Sprintf("m%04d", i))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), make([]byte, 100), 0o600))
		resolutions[source] = resolver.Resolution{LocalPath: dir}
		calls += fmt.Sprintf("module \"m%04d\" {\n  source = %q\n}\n", i, source)
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(calls), 0o600))
	tracker := &trackingResolver{bySource: resolutions, calls: make(map[string]int)}

	result := Resolve(t.Context(), &Request{
		RootPaths:      []string{root},
		DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
		Resolver:       tracker,
		MaxDepth:       2,
		ResourceLimits: resolver.ResourceLimits{MaxTotalBytes: 100},
	})

	acquired := 0
	for _, source := range sources {
		acquired += tracker.callCount(source)
	}
	require.Equal(t, 2, acquired)
	require.Equal(t, 1, tracker.callCount(sources[0]))
	unacquired := 0
	for _, event := range result.BudgetEvents {
		if event.Gate == "acquisition" {
			unacquired++
			require.Equal(t, "module_bytes_total", event.Limit)
		}
	}
	require.Equal(t, count-acquired, unacquired)
}

func TestShedToTotalLimitBreaksTiesDeterministically(t *testing.T) {
	t.Parallel()

	build := func() (walkerSnapshot, *resolver.ResourceBudget) {
		budget := resolver.NewResourceBudget(resolver.ResourceLimits{MaxTotalBytes: 1})
		snapshot := walkerSnapshot{sourceMappings: make(map[string]string)}
		for i := range 6 {
			root := filepath.Join("packages", fmt.Sprintf("%02d", i))
			require.NoError(t, budget.AdmitPackage(root, resolver.PackageUsage{Bytes: 1, Files: 1}))
			snapshot.paths = append(snapshot.paths, filepath.Join(root, "main.tf"))
			snapshot.modules = append(snapshot.modules, ResolvedModule{
				CanonicalSource: "example.com/acme/shared/aws",
				PackageRoot:     root,
				Depth:           1,
			})
			snapshot.sourceMappings[root] = "example.com/acme/shared/aws"
		}
		return snapshot, budget
	}

	snapshot, budget := build()
	shedToTotalLimit(&snapshot, budget, 2, true)
	for range 20 {
		other, otherBudget := build()
		shedToTotalLimit(&other, otherBudget, 2, true)
		require.Equal(t, snapshot.paths, other.paths)
		require.Equal(t, snapshot.modules, other.modules)
		require.Equal(t, snapshot.budgetEvents, other.budgetEvents)
	}
}

func TestParseModulesInDirDoesNotCacheCanceledParse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
module "child" {
  source = "./child"
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &walker{
		parseCache: moduleParseCache{entries: make(map[string]map[string]tfmodules.ParsedModule)},
		parseSem:   make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if mods := w.parseModulesInDir(ctx, dir, nil, dir); len(mods) != 0 {
		t.Fatalf("canceled parse returned %d modules", len(mods))
	}
	if _, ok := w.parseCache.get(filepath.Clean(dir) + "\x00" + filepath.Clean(dir) + "\x00all"); ok {
		t.Fatal("canceled parse must not be cached")
	}
	mods := w.parseModulesInDir(context.Background(), dir, nil, dir)
	found := false
	for _, mod := range mods {
		if mod.Name == "child" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("live parse missing child module: %#v", mods)
	}
}
