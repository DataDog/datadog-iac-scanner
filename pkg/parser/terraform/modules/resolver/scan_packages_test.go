/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package resolver

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const scanPackageSource = "registry.example/example/network/aws"

func TestScanSharesRegistryFallbackPackage(t *testing.T) {
	var baseline []string
	for _, cacheAvailable := range []bool{false, true} {
		for _, overlap := range []bool{false, true} {
			var ids []string
			synctest.Test(t, func(t *testing.T) {
				r, started, release := scanPackageFixture(t, registryPackageArchive(t), cacheAvailable)
				budget := NewResourceBudget(ResourceLimits{MaxPackageBytes: 4096, MaxTotalBytes: 96})
				ctx, cleanup := WithScanPackages(WithResourceBudget(t.Context(), budget))
				defer cleanup()
				res, errs := resolveTwoRegistryWorkspaces(ctx, r, started, release, overlap)
				require.NoError(t, errs[0])
				require.NoError(t, errs[1])
				require.Equal(t, res[0].LocalPath, res[1].LocalPath)
				root := res[0].PackageRoot
				for i := range res {
					require.Nil(t, res[i].Cleanup)
					usage, err := MeasurePackage(ctx, res[i].PackageRoot, budget.Limits())
					require.NoError(t, err)
					require.NoError(t, budget.AdmitPackage(res[i].PackageRoot, usage))
				}
				require.Equal(t, PackageUsage{Files: 4, Bytes: 64}, budget.TotalUsage())
				require.LessOrEqual(t, budget.TotalUsage().Bytes, budget.Limits().MaxTotalBytes)

				sibling, err := r.Resolve(ctx, &tfmodules.ParsedModule{Source: scanPackageSource + "//sibling", Version: "1.0.0"})
				require.NoError(t, err)
				require.Equal(t, root, sibling.PackageRoot)
				require.Equal(t, filepath.Join(root, "sibling"), sibling.LocalPath)
				require.EqualValues(t, 1, r.cfg.fetchCount.Load())
				source := model.ExtractedPathObject{DocumentSource: scanPackageSource + "//entry@1.0.0", DocumentPackageRoot: root}
				extraction := map[string]model.ExtractedPathObject{res[0].LocalPath: source}
				repo := t.TempDir()
				for _, dir := range []string{res[0].LocalPath, sibling.LocalPath} {
					path := filepath.Join(dir, "main.tf")
					require.FileExists(t, path)
					key := model.DocumentKey{Path: model.DocumentPath(path, repo, extraction), Kind: model.KindTerraform}
					ids = append(ids, key.ID())
				}
				cleanup()
				require.NoDirExists(t, root)
			})
			if baseline == nil {
				baseline = ids
			}
			require.Equal(t, baseline, ids, "cache available %t, overlap %t", cacheAvailable, overlap)
			require.NotEqual(t, ids[0], ids[1])
		}
	}
}

func TestScanSharesRegistryFallbackFailure(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			r, started, release := scanPackageFixture(t, []byte("invalid zip archive"), true)
			ctx, cleanup := WithScanPackages(t.Context())
			defer cleanup()
			_, errs := resolveTwoRegistryWorkspaces(ctx, r, started, release, overlap)
			require.Error(t, errs[0])
			require.Same(t, errs[0], errs[1])
			require.EqualValues(t, 1, r.cfg.fetchCount.Load())
			files, err := os.ReadDir(r.cfg.TmpDir)
			require.NoError(t, err)
			require.Empty(t, files)
		})
	}
}

func TestScanReusesAcquisitionFailureAtLimit(t *testing.T) {
	r, _, release := scanPackageFixture(t, []byte("invalid zip archive"), true)
	close(release)
	budget := NewResourceBudget(ResourceLimits{MaxPackageBytes: 128, MaxTotalBytes: 128})
	ctx, cleanup := WithScanPackages(WithResourceBudget(t.Context(), budget))
	defer cleanup()

	lease, ok := budget.TryAcquireAcquisition(128, 128)
	require.True(t, ok)
	defer lease.Release()
	entry := &tfmodules.ParsedModule{Source: scanPackageSource + "//entry", Version: "1.0.0"}
	_, firstErr := r.Resolve(ctx, entry)
	require.Error(t, firstErr)
	lease.Release()
	require.NoError(t, budget.AdmitPackage("unrelated", PackageUsage{Bytes: 128}))

	sibling := &tfmodules.ParsedModule{Source: scanPackageSource + "//sibling", Version: "1.0.0"}
	require.Equal(t, RetainedPackageStatus{Reuse: true}, r.LookupRetainedPackage(ctx, sibling))
	_, err := r.Resolve(ctx, sibling)
	require.Same(t, firstErr, err)
	require.EqualValues(t, 1, r.cfg.fetchCount.Load())
	require.Equal(t, int64(128), budget.TotalUsage().Bytes)
}

func TestScanPackageWaiterCanCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, started, release := scanPackageFixture(t, registryPackageArchive(t), false)
		ctx, cleanup := WithScanPackages(t.Context())
		defer cleanup()
		owner := make(chan error, 1)
		go func() {
			_, err := r.Resolve(ctx, &tfmodules.ParsedModule{Source: scanPackageSource + "//entry", Version: "1.0.0"})
			owner <- err
		}()
		<-started

		waitCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		waiter := make(chan error, 1)
		go func() {
			_, err := r.Resolve(waitCtx, &tfmodules.ParsedModule{Source: scanPackageSource + "//sibling", Version: "1.0.0"})
			waiter <- err
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()

		var waitErr error
		select {
		case waitErr = <-waiter:
		default:
		}
		close(release)
		require.NoError(t, <-owner)
		synctest.Wait()
		require.ErrorIs(t, waitErr, context.Canceled)
		require.EqualValues(t, 1, r.cfg.fetchCount.Load())
	})
}

func TestScanChargesRetainedPackageWhenSelectionFails(t *testing.T) {
	r, _, release := scanPackageFixture(t, registryPackageArchive(t), true)
	close(release)
	budget := NewResourceBudget(ResourceLimits{MaxPackageBytes: 4096, MaxTotalBytes: 96})
	ctx, cleanup := WithScanPackages(WithResourceBudget(t.Context(), budget))
	defer cleanup()

	valid := &tfmodules.ParsedModule{Source: scanPackageSource + "//entry", Version: "~> 1.0"}
	chain := NewChainResolver(LocalResolver{}, r)
	status := chain.LookupRetainedPackage(ctx, valid)
	require.Equal(t, RetainedPackageStatus{}, status)
	_, err := r.Resolve(ctx, &tfmodules.ParsedModule{Source: scanPackageSource + "//missing", Version: "1.0.0"})
	require.ErrorContains(t, err, "invalid acquired module package")
	require.Equal(t, PackageUsage{Files: 4, Bytes: 64}, budget.TotalUsage())

	status = chain.LookupRetainedPackage(ctx, valid)
	require.True(t, status.VersionPending)
	require.NotNil(t, status.Ready)
	<-status.Ready
	require.Equal(t, RetainedPackageStatus{Reuse: true}, chain.LookupRetainedPackage(ctx, valid))
	status = chain.LookupRetainedPackage(ctx, &tfmodules.ParsedModule{Source: valid.Source, Version: "2.0.0"})
	require.Equal(t, RetainedPackageStatus{}, status)
	res, err := chain.Resolve(ctx, valid)
	require.NoError(t, err)
	require.True(t, res.ChargedTo(budget))
	require.Equal(t, "1.0.0", res.ResolvedVersion)
	require.FileExists(t, filepath.Join(res.LocalPath, "main.tf"))
	require.Equal(t, PackageUsage{Files: 4, Bytes: 64}, budget.TotalUsage())
	require.EqualValues(t, 1, r.cfg.fetchCount.Load())
	cleanup()
	require.NoDirExists(t, res.PackageRoot)
}

func TestScanChecksEarlierResolverBeforeRegistryVersionLookup(t *testing.T) {
	r, _, release := scanPackageFixture(t, registryPackageArchive(t), true)
	close(release)
	ctx, cleanup := WithScanPackages(WithResourceBudget(t.Context(), NewResourceBudget(ResourceLimits{})))
	defer cleanup()
	mod := &tfmodules.ParsedModule{Source: scanPackageSource + "//entry", Version: "1.0.0"}
	_, err := r.Resolve(ctx, mod)
	require.NoError(t, err)

	transport := r.cfg.RegistryCache.client.Transport
	var requests int
	r.cfg.RegistryCache.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/versions") {
			requests++
		}
		return transport.RoundTrip(req)
	})
	mod.Version = "~> 1.0"
	status := NewChainResolver(fakeScreener{t: t}, r).LookupRetainedPackage(ctx, mod)
	require.Equal(t, RetainedPackageStatus{}, status)
	require.Zero(t, requests)
	// Once the preceding resolver rules the call out, resolve the constraint.
	chain := NewChainResolver(LocalResolver{}, r)
	status = chain.LookupRetainedPackage(ctx, mod)
	require.True(t, status.VersionPending)
	require.NotNil(t, status.Ready)
	<-status.Ready
	require.Equal(t, RetainedPackageStatus{Reuse: true}, chain.LookupRetainedPackage(ctx, mod))
	require.Equal(t, 1, requests)
}

func TestScanReusesDiskCachedPackage(t *testing.T) {
	r, _, release := scanPackageFixture(t, registryPackageArchive(t), false)
	close(release)
	cache := t.TempDir()
	cacheBudget, err := NewModuleCacheBudget(cache, 4096)
	require.NoError(t, err)
	r.cfg.Cache, err = NewModuleCacheWithDir(filepath.Join(cache, "modules"), cacheBudget)
	require.NoError(t, err)
	budget := NewResourceBudget(ResourceLimits{MaxTotalBytes: 128})
	ctx, cleanup := WithScanPackages(WithResourceBudget(t.Context(), budget))
	defer cleanup()

	lease, ok := budget.TryAcquireAcquisition(128, 128)
	require.True(t, ok)
	defer lease.Release()
	res, err := r.Resolve(ctx, &tfmodules.ParsedModule{Source: scanPackageSource + "//entry", Version: "1.0.0"})
	require.NoError(t, err)
	require.DirExists(t, res.PackageRoot)
	require.True(t, res.ChargedTo(budget))
	sibling := &tfmodules.ParsedModule{Source: scanPackageSource + "//sibling", Version: "1.0.0"}
	usage, err := MeasurePackage(ctx, res.PackageRoot, ResourceLimits{})
	require.NoError(t, err)
	require.Equal(t, usage, budget.TotalUsage())

	require.Equal(t, RetainedPackageStatus{Reuse: true}, r.LookupRetainedPackage(ctx, sibling))
	siblingResolution, err := r.Resolve(ctx, sibling)
	require.NoError(t, err)
	require.True(t, siblingResolution.ChargedTo(budget))
	require.Equal(t, usage, budget.TotalUsage())
	require.EqualValues(t, 1, r.cfg.fetchCount.Load())
}

func TestScanChargesCachedPackageWhenSelectionFails(t *testing.T) {
	r, _, release := scanPackageFixture(t, registryPackageArchive(t), false)
	close(release)
	cache := t.TempDir()
	cacheBudget, err := NewModuleCacheBudget(cache, 4096)
	require.NoError(t, err)
	r.cfg.Cache, err = NewModuleCacheWithDir(filepath.Join(cache, "modules"), cacheBudget)
	require.NoError(t, err)

	valid := &tfmodules.ParsedModule{Source: scanPackageSource + "//entry", Version: "1.0.0"}
	warm, err := r.Resolve(t.Context(), valid)
	require.NoError(t, err)
	warm.Cleanup()
	usage, err := MeasurePackage(t.Context(), warm.PackageRoot, ResourceLimits{})
	require.NoError(t, err)
	budget := NewResourceBudget(ResourceLimits{MaxPackageBytes: usage.Bytes, MaxTotalBytes: usage.Bytes})
	ctx, cleanup := WithScanPackages(WithResourceBudget(t.Context(), budget))
	defer cleanup()

	lease, ok := budget.TryAcquireAcquisition(usage.Bytes, usage.Bytes)
	require.True(t, ok)
	defer lease.Release()
	missing := &tfmodules.ParsedModule{Source: scanPackageSource + "//missing", Version: "1.0.0"}
	_, err = r.Resolve(ctx, missing)
	require.ErrorContains(t, err, "invalid acquired module package")
	lease.Release()

	require.Equal(t, usage, budget.TotalUsage())
	require.Equal(t, RetainedPackageStatus{Reuse: true}, r.LookupRetainedPackage(ctx, valid))
	other, changed := budget.PollAcquisition(usage.Bytes, usage.Bytes)
	defer other.Release()
	require.Nil(t, other)
	require.Nil(t, changed)

	res, err := r.Resolve(ctx, valid)
	require.NoError(t, err)
	require.Equal(t, warm.LocalPath, res.LocalPath)
	require.True(t, res.ChargedTo(budget))
	require.Equal(t, usage, budget.TotalUsage())
	require.EqualValues(t, 1, r.cfg.fetchCount.Load())
	require.Equal(t, 1, cacheBudget.pins[warm.PackageRoot])
	cleanup()
	require.NotContains(t, cacheBudget.pins, warm.PackageRoot)

	smallBudget := NewResourceBudget(ResourceLimits{MaxPackageBytes: usage.Bytes - 1})
	smallCtx, smallCleanup := WithScanPackages(WithResourceBudget(t.Context(), smallBudget))
	defer smallCleanup()
	_, err = r.Resolve(smallCtx, valid)
	require.ErrorAs(t, err, new(*BudgetExceededError))
	require.Zero(t, smallBudget.TotalUsage().Bytes)
	require.NotContains(t, cacheBudget.pins, warm.PackageRoot)
}

func registryPackageArchive(t *testing.T) []byte {
	t.Helper()
	var archive bytes.Buffer
	zipper := zip.NewWriter(&archive)
	for _, name := range []string{"entry/main.tf", "sibling/main.tf"} {
		file, err := zipper.Create(name)
		require.NoError(t, err)
		_, err = io.WriteString(file, "resource \"example\" \"fixture\" {}\n")
		require.NoError(t, err)
	}
	require.NoError(t, zipper.Close())
	return archive.Bytes()
}

func scanPackageFixture(t *testing.T, archive []byte, cacheAvailable bool) (*GoGetterResolver, <-chan struct{}, chan<- struct{}) {
	t.Helper()
	cfg := NewGoGetterConfig()
	cfg.TmpDir = t.TempDir()
	if cacheAvailable {
		cache := t.TempDir()
		budget, err := NewModuleCacheBudget(cache, 1)
		require.NoError(t, err)
		cfg.Cache, err = NewModuleCacheWithDir(filepath.Join(cache, "modules"), budget)
		require.NoError(t, err)
	}
	cfg.RegistryCache = NewRegistryCache(DefaultFetchTimeout)
	cfg.RegistryCache.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
		status, body := http.StatusOK, `{"modules.v1":"/v1/modules/"}`
		switch {
		case strings.HasSuffix(req.URL.Path, "/versions"):
			body = `{"modules":[{"versions":[{"version":"1.0.0"}]}]}`
		case strings.HasSuffix(req.URL.Path, "/download"):
			header.Set("X-Terraform-Get", "https://archive.example/module.zip")
			status, body = http.StatusNoContent, ""
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: header}, nil
	})
	started, release := make(chan struct{}, 3), make(chan struct{})
	cfg.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Type", "application/zip")
		header.Set("Content-Length", strconv.Itoa(len(archive)))
		body := io.Reader(http.NoBody)
		if req.Method != http.MethodHead {
			started <- struct{}{}
			<-release
			body = bytes.NewReader(archive)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(body)}, nil
	})}
	return NewGoGetterResolver(cfg), started, release
}

func resolveTwoRegistryWorkspaces(
	ctx context.Context, r *GoGetterResolver, started <-chan struct{}, release chan<- struct{}, overlap bool,
) (results [2]Resolution, errs [2]error) {
	resolve := func(i int) {
		results[i], errs[i] = r.Resolve(ctx, &tfmodules.ParsedModule{
			Source: scanPackageSource + "//entry", Version: "1.0.0", Name: "network",
			FileName: filepath.Join("workspace"+strconv.Itoa(i), "main.tf"),
		})
	}
	if overlap {
		go resolve(0)
		<-started
		go resolve(1)
		synctest.Wait()
		close(release)
		synctest.Wait()
	} else {
		close(release)
		resolve(0)
		resolve(1)
	}
	return results, errs
}
