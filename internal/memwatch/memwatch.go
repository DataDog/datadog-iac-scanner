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
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// sampleInterval is how often the watcher samples between phase boundaries.
const sampleInterval = 500 * time.Millisecond

// progressThresholds are the resident sizes, in bytes, that are logged when
// first reached, with the last phase that completed and the work then in flight. A scan killed for
// its memory never reaches the summary Stop logs, so these are what say where
// it was.
var progressThresholds = []uint64{1 << 30, 2 << 30, 4 << 30, 8 << 30, 12 << 30}

const (
	PhaseStartup        = "startup"
	PhaseAnalyzePaths   = "analyze_paths"
	PhaseModuleResolve  = "remote_module_resolve"
	PhaseGetQueries     = "get_queries"
	PhasePrepareSources = "prepare_sources"
	PhaseModuleEval     = "local_module_eval"
	PhaseCombine        = "combine_documents"
	PhasePayloads       = "build_payloads"
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

	phase     string
	active    map[int]string
	nextID    int
	nextLevel int
	done      chan struct{}
}

func Start(ctx context.Context, log *zerolog.Logger) (context.Context, *Watcher) {
	w := &Watcher{
		logger:    *log,
		sampleRSS: peakRSSBytes,
	}
	w.sample(PhaseStartup)
	w.done = make(chan struct{})
	go w.run(w.done)
	return context.WithValue(ctx, watcherKey{}, w), w
}

// run samples until done is closed.
func (w *Watcher) run(done <-chan struct{}) {
	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			w.sample("")
		}
	}
}

// Begin records label as work in flight until the returned function is called.
// Labels of the work in flight are logged with the progress thresholds, so the
// work running when memory grew is known.
func Begin(ctx context.Context, label string) (end func()) {
	w, ok := ctx.Value(watcherKey{}).(*Watcher)
	if !ok {
		return func() {}
	}
	w.mu.Lock()
	if w.active == nil {
		w.active = map[int]string{}
	}
	id := w.nextID
	w.nextID++
	w.active[id] = label
	w.mu.Unlock()
	return func() {
		w.mu.Lock()
		delete(w.active, id)
		w.mu.Unlock()
	}
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
	if w.done != nil {
		close(w.done)
	}

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
	// A phase is sampled when it completes, so a periodic sample, which has no
	// phase of its own, was taken in the work after the last completed phase.
	if phase == "" {
		phase = w.phase
	} else {
		w.phase = phase
	}
	if current > w.peakBytes {
		w.peakBytes = current
		w.peakPhase = phase
	}
	for w.nextLevel < len(progressThresholds) && current >= progressThresholds[w.nextLevel] {
		active := make([]string, 0, len(w.active))
		for _, label := range w.active {
			active = append(active, label)
		}
		slices.Sort(active)
		w.logger.Info().
			Uint64("rss_bytes", current).
			Uint64("threshold_bytes", progressThresholds[w.nextLevel]).
			Str("last_completed_phase", phase).
			Strs("in_flight", active).
			Msg("memwatch: resident memory threshold reached")
		w.nextLevel++
	}
}
