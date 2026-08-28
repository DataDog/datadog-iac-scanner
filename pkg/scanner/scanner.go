/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scanner

import (
	"context"
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
		return StartScan(ctx, scanID, services)
	case err := <-errCh:
		metrics.Metric.Stop()
		memwatch.Sample(ctx, memwatch.PhasePrepareSources)
		return err
	}
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
