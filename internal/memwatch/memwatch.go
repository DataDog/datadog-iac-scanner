/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package memwatch records the process peak resident set size together with the
// scan phase it was reached in.
package memwatch

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
)

const (
	PhaseStartup        = "startup"
	PhaseAnalyzePaths   = "analyze_paths"
	PhaseModuleResolve  = "remote_module_resolve"
	PhaseGetQueries     = "get_queries"
	PhasePrepareSources = "prepare_sources"
	PhaseModuleEval     = "local_module_eval"
	PhaseStartScan      = "start_scan"
	PhaseGenerateReport = "generate_report"
)

type watcherKey struct{}

type Watcher struct {
	mu        sync.Mutex
	logger    zerolog.Logger
	sampleRSS func() (uint64, bool)
	peakBytes uint64
	peakPhase string
	stopped   bool
}

func Start(ctx context.Context, log *zerolog.Logger) (context.Context, *Watcher) {
	w := &Watcher{
		logger:    *log,
		sampleRSS: peakRSSBytes,
	}
	w.sample(PhaseStartup)
	return context.WithValue(ctx, watcherKey{}, w), w
}

func Sample(ctx context.Context, phase string) {
	if w, ok := ctx.Value(watcherKey{}).(*Watcher); ok {
		w.sample(phase)
	}
}

func (w *Watcher) Peak() (bytes uint64, phase string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peakBytes, w.peakPhase
}

func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.stopped {
		return
	}
	w.stopped = true

	if w.peakBytes == 0 {
		return
	}

	w.logger.Info().
		Uint64("peak_rss_bytes", w.peakBytes).
		Str("peak_rss_phase", w.peakPhase).
		Msg("memwatch: peak resident memory summary")
}

func (w *Watcher) sample(phase string) {
	current, ok := w.sampleRSS()
	if !ok {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if current > w.peakBytes {
		w.peakBytes = current
		w.peakPhase = phase
	}
}
