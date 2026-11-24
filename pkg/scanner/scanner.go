/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scanner

import (
	"context"
	"errors"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/internal/memwatch"
	"github.com/DataDog/datadog-iac-scanner/internal/metrics"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/hclcache"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
)

type serviceSlice []*runner.Service

func PrepareAndScan(
	ctx context.Context,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	services serviceSlice,
) error {
	// A config or platform filter can leave no service, which is an empty scan,
	// not a mix of providers.
	if len(services) == 0 {
		return nil
	}
	metrics.Metric.Start("prepare_sources")

	// Scope the bounded HCL parse cache strictly to prepare_sources so Terraform
	// file, variable, and data-source parses share ASTs without retaining or
	// refilling cached ASTs during StartScan/eval peak memory.
	prepareCtx := ctx
	var prepareHCLCache *hclcache.Cache
	if hasTerraformService(services) && hclcache.FromContext(ctx) == nil {
		prepareHCLCache = hclcache.New(0)
		defer prepareHCLCache.Close()
		prepareCtx = hclcache.WithCache(ctx, prepareHCLCache)
	}

	// The disk walk serves every disk scan.
	if fsp, ok := runner.DiskSourceProvider(services); ok {
		err := runner.PrepareDiskSources(prepareCtx, fsp, services, scanID, openAPIResolveReferences, maxResolverDepth)
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		if err != nil {
			return err
		}
		// The cached file bytes were only needed during the shared walk; release them
		// before eval so they are not held through the query phase.
		fsp.ReleaseContentCache()
		releasePrepareState(services, prepareHCLCache)
		return StartScan(ctx, scanID, services)
	}

	// The in-memory (server) dispatch: one pass over the pushed files, rendering
	// each pushed Helm chart once.
	if mp, ok := runner.MemorySourceProvider(services); ok {
		err := runner.PrepareMemorySources(prepareCtx, mp, services, scanID, openAPIResolveReferences, maxResolverDepth)
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		if err != nil {
			return err
		}
		releasePrepareState(services, prepareHCLCache)
		return StartScan(ctx, scanID, services)
	}

	metrics.Metric.Stop()
	memwatch.Sample(ctx, memwatch.PhasePrepareSources)
	return errors.New("services must share one source provider")
}

func hasTerraformService(services serviceSlice) bool {
	for _, s := range services {
		if s == nil || s.Parser == nil {
			continue
		}
		for _, p := range s.Parser.Platform {
			if strings.EqualFold(p, "terraform") {
				return true
			}
		}
	}
	return false
}

// releasePrepareState drops the dedup state that only the prepare phase uses,
// so it is not held through eval.
func releasePrepareState(services serviceSlice, hclCache *hclcache.Cache) {
	hclCache.Close()
	for _, s := range services {
		s.ClearContentInterner()
		s.ClearParsedShares()
		s.ClearTreeCons()
	}
	model.ClearYAMLScalarInterner()
}

// evalGcFileThreshold is the minimum file count at which StartScan measures the
// live heap for GC relief; below it the check (a full GC) is not worth running.
const evalGcFileThreshold = 10000

// evalGcHeapBytes is the live-heap size, measured after prepare, above which
// StartScan enables GC pressure relief (reduced GC percent plus the eval ticker)
// for payload build and eval. Heap, not file count: mid-size corpora never need
// the relief and pay +30% CPU for it; multi-GiB scans would otherwise carry it
// as headroom before every collection, driving peak RSS.
const evalGcHeapBytes = 3 << 30 // 3 GiB

// reducedEvalGCPercent is the GC percent used on heap-gated scans: lower peak
// for more frequent collections over a multi-GiB live set.
const reducedEvalGCPercent = 30

// liveHeapAfterGC returns the live heap after a full collection (which also
// drains the prepare phase's parse garbage).
func liveHeapAfterGC() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// sequentialScanFileThreshold is the minimum total file count across services
// at which StartScan runs parser services sequentially to avoid overlapping
// per-platform OPA payloads, compilers, and detector caches in peak RSS.
// Below this threshold, services run concurrently so small multi-platform
// scans overlap their single-threaded setup phases.
const sequentialScanFileThreshold = 300

// StartScan will run scans by parser
func StartScan(ctx context.Context, scanID string, services serviceSlice) error {
	defer metrics.Metric.Stop()
	defer memwatch.Sample(ctx, memwatch.PhaseStartScan)
	metrics.Metric.Start("start_scan")
	contextLogger := logger.FromContext(ctx)

	contextLogger.Info().Msgf("Starting scan with id: %s", scanID)

	total := services.GetQueriesLength()
	contextLogger.Info().Msgf("Got %d queries", total)

	totalFiles := services.TotalFiles()

	// GC pressure relief for large scans, gated on measured live heap.
	if totalFiles > evalGcFileThreshold && liveHeapAfterGC() > evalGcHeapBytes {
		previous := debug.SetGCPercent(reducedEvalGCPercent)
		defer debug.SetGCPercent(previous)
		for _, service := range services {
			service.Inspector.SetEvalGcRelief(true)
		}
	}

	if len(services) > 1 && totalFiles >= sequentialScanFileThreshold {
		return runServicesSequentially(ctx, scanID, services)
	}
	return runServicesConcurrently(ctx, scanID, services)
}

func runServicesSequentially(ctx context.Context, scanID string, services serviceSlice) error {
	var wg sync.WaitGroup
	for _, service := range services {
		if err := ctx.Err(); err != nil {
			return err
		}
		serviceErrCh := make(chan error, 1)
		wg.Add(1)
		service.StartScan(ctx, scanID, serviceErrCh, &wg)
		wg.Wait()
		if service.Inspector != nil {
			service.Inspector.ReleaseDetectorCaches()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case err := <-serviceErrCh:
			if err != nil {
				return err
			}
		default:
		}
	}
	return nil
}

func runServicesConcurrently(ctx context.Context, scanID string, services serviceSlice) error {
	var wg sync.WaitGroup
	wgDone := make(chan bool)
	errCh := make(chan error)

	workersCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, service := range services {
		wg.Add(1)
		go service.StartScan(workersCtx, scanID, errCh, &wg)
	}

	go func() {
		wg.Wait()
		close(wgDone)
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wgDone:
		releaseDetectorCaches(services)
		return nil
	case err := <-errCh:
		return err
	}
}

func releaseDetectorCaches(services serviceSlice) {
	seen := make(map[interface{}]struct{}, len(services))
	for _, service := range services {
		if service == nil || service.Inspector == nil {
			continue
		}
		if _, ok := seen[service.Inspector]; ok {
			continue
		}
		seen[service.Inspector] = struct{}{}
		service.Inspector.ReleaseDetectorCaches()
	}
}

// GetQueriesLength returns the Total of queries for all Services
func (s serviceSlice) GetQueriesLength() int {
	count := 0
	for _, service := range s {
		count += service.Inspector.LenQueriesByPlat(service.Parser.Platform)
	}
	return count
}

// TotalFiles returns the number of files collected across services.
func (s serviceSlice) TotalFiles() int {
	total := 0
	for _, service := range s {
		total += service.FileCount()
	}
	return total
}
