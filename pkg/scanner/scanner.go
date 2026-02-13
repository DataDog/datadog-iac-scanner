/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scanner

import (
	"context"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/kics"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
)

type serviceSlice []*kics.Service

func PrepareAndScan(
	ctx context.Context,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	services serviceSlice,
	flagEvaluator featureflags.FlagEvaluator,
) error {
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
		return ctx.Err()
	case <-wgDone:
		return StartScan(ctx, scanID, services)
	case err := <-errCh:
		return err
	}
}

// StartScan will run concurrent scans by parser
func StartScan(ctx context.Context, scanID string, services serviceSlice) error {
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
