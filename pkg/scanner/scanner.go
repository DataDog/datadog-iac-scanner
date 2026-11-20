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
	"sync"

	"github.com/DataDog/datadog-iac-scanner/internal/memwatch"
	"github.com/DataDog/datadog-iac-scanner/internal/metrics"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
)

type serviceSlice []*runner.Service

func PrepareAndScan(
	ctx context.Context,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	services serviceSlice,
) (model.EvaluationFailures, error) {
	// A config or platform filter can leave no service, which is an empty scan,
	// not a mix of providers.
	if len(services) == 0 {
		return model.EvaluationFailures{}, nil
	}
	metrics.Metric.Start("prepare_sources")

	// The disk walk serves every disk scan.
	if fsp, ok := runner.DiskSourceProvider(services); ok {
		err := runner.PrepareDiskSources(ctx, fsp, services, scanID, openAPIResolveReferences, maxResolverDepth)
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		if err != nil {
			return model.EvaluationFailures{}, err
		}
		// The cached file bytes were only needed during the shared walk; release them
		// before eval so they are not held through the query phase.
		fsp.ReleaseContentCache()
		releasePrepareState(services)
		return StartScan(ctx, scanID, services)
	}

	// The in-memory (server) dispatch: one pass over the pushed files, rendering
	// each pushed Helm chart once.
	if mp, ok := runner.MemorySourceProvider(services); ok {
		err := runner.PrepareMemorySources(ctx, mp, services, scanID, openAPIResolveReferences, maxResolverDepth)
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		if err != nil {
			return model.EvaluationFailures{}, err
		}
		releasePrepareState(services)
		return StartScan(ctx, scanID, services)
	}

	metrics.Metric.Stop()
	memwatch.Sample(ctx, memwatch.PhasePrepareSources)
	return model.EvaluationFailures{}, errors.New("services must share one source provider")
}

// releasePrepareState drops the dedup state that only the prepare phase uses,
// so it is not held through eval.
func releasePrepareState(services serviceSlice) {
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

// StartScan will run concurrent scans by parser
func StartScan(ctx context.Context, scanID string, services serviceSlice) (model.EvaluationFailures, error) {
	defer metrics.Metric.Stop()
	defer memwatch.Sample(ctx, memwatch.PhaseStartScan)
	metrics.Metric.Start("start_scan")
	if err := ctx.Err(); err != nil {
		return model.EvaluationFailures{}, err
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("Starting scan with id: %s", scanID)
	contextLogger.Info().Msgf("Got %d queries", services.GetQueriesLength())
	if services.TotalFiles() > evalGcFileThreshold && liveHeapAfterGC() > evalGcHeapBytes {
		previous := debug.SetGCPercent(reducedEvalGCPercent)
		defer debug.SetGCPercent(previous)
		for _, service := range services {
			service.Inspector.SetEvalGcRelief(true)
		}
	}
	type serviceOutcome struct {
		failures model.EvaluationFailures
		fatal    error
	}
	outcomes := make(chan serviceOutcome, len(services))
	workersCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var joined sync.WaitGroup
	for _, service := range services {
		joined.Add(1)
		go func() {
			defer joined.Done()
			failures, err := service.StartScan(workersCtx, scanID)
			outcomes <- serviceOutcome{failures: failures, fatal: err}
		}()
	}
	groups := make([]model.EvaluationFailures, 0, len(services))
	var operational []error
	parentDone := ctx.Done()
	remaining := len(services)
	for remaining > 0 {
		select {
		case outcome := <-outcomes:
			remaining--
			groups = append(groups, outcome.failures)
			if outcome.fatal == nil {
				continue
			}
			// Peer cancellation is an effect of the original fatal cause. Every
			// leaf must be cancellation; a joined sink failure is never discarded.
			if context.Cause(workersCtx) != nil && ctx.Err() == nil && onlyCancellation(outcome.fatal) {
				continue
			}
			operational = append(operational, outcome.fatal)
			cancel(outcome.fatal)
		case <-parentDone:
			cancel(ctx.Err())
			parentDone = nil
		}
	}
	joined.Wait()
	if ctx.Err() != nil {
		operational = append(operational, ctx.Err())
	}
	return model.MergeEvaluationFailures(groups...), errors.Join(operational...)
}

func onlyCancellation(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyCancellation(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return onlyCancellation(wrapped.Unwrap())
	default:
		return false
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
