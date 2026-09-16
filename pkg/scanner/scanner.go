/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scanner

import (
	"context"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/internal/memwatch"
	"github.com/DataDog/datadog-iac-scanner/internal/metrics"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
)

type serviceSlice []*runner.Service

func PrepareAndScan(
	ctx context.Context,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	services serviceSlice,
	flagEvaluator featureflags.FlagEvaluator,
) error {
	metrics.Metric.Start("prepare_sources")

	// The shared walk parses every file concurrently, so it is gated behind the
	// same flag as parallel per-service parsing; when the flag is off we keep the
	// legacy per-service prepare path.
	if fsp, ok := runner.SharedWalkProvider(services); ok &&
		flagEvaluator.EvaluateWithOrgAndEnv(featureflags.IaCEnableKicsParallelFileParsing) {
		err := runner.PrepareSharedWalk(ctx, fsp, services, scanID, openAPIResolveReferences, maxResolverDepth)
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		if err != nil {
			return err
		}
		// The analyzer's cached file bytes were only needed during the shared
		// walk above; OriginalData now holds each file's content for the rest
		// of the scan. Release the cache before eval so it isn't held through
		// the memory-intensive query phase.
		fsp.ReleaseContentCache()
		for _, s := range services {
			s.ClearContentInterner()
			s.ClearParsedShares()
			s.ClearTreeCons()
		}
		return StartScan(ctx, scanID, services)
	}

	var wg sync.WaitGroup
	wgDone := make(chan bool)
	errCh := make(chan error)

	workersCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, service := range services {
		wg.Add(1)
		go service.PrepareSources(workersCtx, scanID, openAPIResolveReferences, maxResolverDepth, &wg, errCh, flagEvaluator)
	}

	go func() {
		wg.Wait()
		close(wgDone)
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		return ctx.Err()
	case <-wgDone:
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		if fsp, ok := runner.SharedWalkProvider(services); ok {
			fsp.ReleaseContentCache()
		}
		for _, s := range services {
			s.ClearContentInterner()
			s.ClearParsedShares()
			s.ClearTreeCons()
		}
		return StartScan(ctx, scanID, services)
	case err := <-errCh:
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		return err
	}
}

// evalGcFileThreshold is the minimum number of collected files at which
// StartScan considers GC pressure relief (reduced GC percent plus the eval
// forced-GC ticker) for the payload-build and eval phases; below it the
// check itself (a full GC) is not worth running. This is the single
// definition shared by both mechanisms (the Inspector consumes the decision
// via SetEvalGcRelief, not its own file count).
const evalGcFileThreshold = 10000

// evalGcHeapBytes is the live-heap size, measured after prepare, above which
// StartScan enables GC pressure relief (reduced GC percent plus the eval
// forced-GC ticker) for payload build and eval. The gate is the scan's actual
// memory need, not a proxy like file count: mid-size corpora (30k+ files,
// ~1-1.5 GiB live entering eval) never need GC pressure relief, and the
// extra GC marking CPU only slows them down (measured +30% user CPU on such
// a corpus with the previous file-count gate). Multi-GiB scans like
// community-operators (~5 GiB live entering eval) would otherwise double
// that as GC headroom before every collection, driving the peak RSS.
const evalGcHeapBytes = 3 << 30 // 3 GiB

// reducedEvalGCPercent is the GC percent used during payload build and eval
// on scans whose live heap exceeds evalGcHeapBytes: a substantially lower
// peak in exchange for more frequent collections over a multi-GiB live set.
// Smaller scans keep the default GOGC pacing.
const reducedEvalGCPercent = 30

// liveHeapAfterGC returns the live heap size after a full collection, so the
// GC-percent decision is made on real live data rather than heap-plus-garbage.
// The collection itself is not wasted work: it drains the prepare phase's
// parse garbage before eval starts.
func liveHeapAfterGC() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// StartScan will run concurrent scans by parser
func StartScan(ctx context.Context, scanID string, services serviceSlice) error {
	defer metrics.Metric.Stop()
	defer memwatch.Sample(ctx, memwatch.PhaseStartScan)
	metrics.Metric.Start("start_scan")
	contextLogger := logger.FromContext(ctx)
	var wg sync.WaitGroup
	wgDone := make(chan bool)
	errCh := make(chan error)

	contextLogger.Info().Msgf("Starting scan with id: %s", scanID)

	total := services.GetQueriesLength()
	contextLogger.Info().Msgf("Got %d queries", total)

	// GC pressure relief for large scans: lower the GC percent and run the
	// eval forced-GC ticker — both gated on the same measured live heap, so
	// mid-size corpora keep the default pacing and no forced collections.
	if services.TotalFiles() > evalGcFileThreshold && liveHeapAfterGC() > evalGcHeapBytes {
		previous := debug.SetGCPercent(reducedEvalGCPercent)
		defer debug.SetGCPercent(previous)
		for _, service := range services {
			service.Inspector.SetEvalGcRelief(true)
		}
	}

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
		return nil
	case err := <-errCh:
		return err
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
