package memwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestReadLimitFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if v, ok := readLimitFile(write("set", "17179869184\n")); !ok || v != 17179869184 {
		t.Fatalf("limit = %d, %v", v, ok)
	}
	if _, ok := readLimitFile(write("max", "max\n")); ok {
		t.Fatal("max means no limit")
	}
	if _, ok := readLimitFile(write("v1", "9223372036854771712\n")); ok {
		t.Fatal("the cgroup v1 unlimited value means no limit")
	}
	if _, ok := readLimitFile(filepath.Join(dir, "missing")); ok {
		t.Fatal("a missing file means no limit")
	}
}
