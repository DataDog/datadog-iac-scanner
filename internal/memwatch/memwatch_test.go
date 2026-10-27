package memwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func requirePeakRSSSampling(t *testing.T) {
	t.Helper()
	if _, ok := peakRSSBytes(); !ok {
		t.Skip("peak RSS sampling is unsupported on this platform")
	}
}

func TestWatcherLogsSummary(t *testing.T) {
	requirePeakRSSSampling(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.InfoLevel)

	ctx, w := Start(context.Background(), &logger)
	Sample(ctx, PhaseStartScan)
	w.Stop()

	out := logs.String()
	if !strings.Contains(out, "memwatch: peak resident memory summary") {
		t.Fatalf("expected summary log, got %q", out)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &entry); err != nil {
		t.Fatalf("unmarshal summary log: %v", err)
	}
	phase, ok := entry["peak_rss_phase"].(string)
	if !ok || phase == "" {
		t.Fatalf("expected peak_rss_phase in summary, got %q", out)
	}
	if _, ok := entry["peak_rss_bytes"].(float64); !ok {
		t.Fatalf("expected peak_rss_bytes in summary, got %q", out)
	}
}

func TestSampleKeepsLargestPeakAndItsPhase(t *testing.T) {
	values := []uint64{100, 300, 200}
	w := &Watcher{
		logger: zerolog.Nop(),
		sampleRSS: func() (uint64, bool) {
			value := values[0]
			values = values[1:]
			return value, true
		},
	}
	ctx := context.WithValue(context.Background(), watcherKey{}, w)

	Sample(ctx, PhaseAnalyzePaths)
	Sample(ctx, PhaseModuleResolve)
	Sample(ctx, PhaseStartScan)

	peak, phase := w.Peak()
	if peak != 300 || phase != PhaseModuleResolve {
		t.Fatalf("Peak() = (%d, %q), want (300, %q)", peak, phase, PhaseModuleResolve)
	}
}

func TestWatchersKeepIndependentPeaks(t *testing.T) {
	first := &Watcher{
		logger:    zerolog.Nop(),
		sampleRSS: func() (uint64, bool) { return 100, true },
	}
	second := &Watcher{
		logger:    zerolog.Nop(),
		sampleRSS: func() (uint64, bool) { return 200, true },
	}
	firstCtx := context.WithValue(context.Background(), watcherKey{}, first)
	secondCtx := context.WithValue(context.Background(), watcherKey{}, second)

	Sample(firstCtx, PhaseAnalyzePaths)
	Sample(secondCtx, PhaseModuleResolve)

	firstPeak, firstPhase := first.Peak()
	secondPeak, secondPhase := second.Peak()
	if firstPeak != 100 || firstPhase != PhaseAnalyzePaths {
		t.Fatalf("first Peak() = (%d, %q)", firstPeak, firstPhase)
	}
	if secondPeak != 200 || secondPhase != PhaseModuleResolve {
		t.Fatalf("second Peak() = (%d, %q)", secondPeak, secondPhase)
	}
}

func TestSampleWithoutWatcherIsNoop(t *testing.T) {
	Sample(context.Background(), PhaseStartScan)
}

func TestUnsupportedSamplerLeavesPeakEmpty(t *testing.T) {
	w := &Watcher{
		logger:    zerolog.Nop(),
		sampleRSS: func() (uint64, bool) { return 0, false },
	}
	ctx := context.WithValue(context.Background(), watcherKey{}, w)

	Sample(ctx, PhaseStartup)

	peak, phase := w.Peak()
	if peak != 0 || phase != "" {
		t.Fatalf("Peak() = (%d, %q), want (0, empty)", peak, phase)
	}
}

func TestSampleLogsEachThresholdOnceWithPhaseAndWorkInFlight(t *testing.T) {
	values := []uint64{1 << 29, 3 << 29, 5 << 30, 5 << 30, 13 << 30}
	var logs bytes.Buffer
	w := &Watcher{
		logger: zerolog.New(&logs).Level(zerolog.InfoLevel),
		sampleRSS: func() (uint64, bool) {
			value := values[0]
			values = values[1:]
			return value, true
		},
	}
	ctx := context.WithValue(context.Background(), watcherKey{}, w)

	Sample(ctx, PhaseModuleEval)
	end := Begin(ctx, "root b")
	endOther := Begin(ctx, "root a")
	Sample(ctx, "")
	endOther()
	Sample(ctx, "")
	Sample(ctx, "")
	end()
	Sample(ctx, PhaseStartScan)

	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		entries = append(entries, entry)
	}
	// 1.5 GiB crosses 1 GiB; 5 GiB crosses 2 and 4 together; 13 GiB crosses 8 and 12.
	if len(entries) != 5 {
		t.Fatalf("got %d threshold logs, want 5: %q", len(entries), logs.String())
	}
	first := entries[0]
	if first["last_completed_phase"] != PhaseModuleEval || first["threshold_bytes"].(float64) != float64(1<<30) {
		t.Fatalf("first log = %v", first)
	}
	if flight := first["in_flight"].([]any); len(flight) != 2 || flight[0] != "root a" || flight[1] != "root b" {
		t.Fatalf("in_flight = %v, want both roots sorted", flight)
	}
	if flight := entries[1]["in_flight"].([]any); len(flight) != 1 || flight[0] != "root b" {
		t.Fatalf("second in_flight = %v, want only root b", flight)
	}
	last := entries[4]
	if last["last_completed_phase"] != PhaseStartScan || last["threshold_bytes"].(float64) != float64(12<<30) {
		t.Fatalf("last log = %v", last)
	}
}

func TestBeginWithoutWatcherIsNoop(t *testing.T) {
	Begin(context.Background(), "root")()
}
