/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"runtime/debug"
	"testing"
	"time"
)

func gcPercent() int {
	p := debug.SetGCPercent(100)
	debug.SetGCPercent(p)
	return p
}

// Relief is held while any scan holds it and restores the setting it found.
func TestGCRelief_ReferenceCounted(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(100))
	acquireGCRelief()
	acquireGCRelief()
	if got := gcPercent(); got != gcReliefPercent {
		t.Fatalf("GC percent %d while held", got)
	}
	releaseGCRelief()
	if got := gcPercent(); got != gcReliefPercent {
		t.Fatalf("GC percent %d while still held once", got)
	}
	releaseGCRelief()
	if got := gcPercent(); got != 100 {
		t.Fatalf("GC percent %d after release, want 100", got)
	}
}

// A lower setting in force is not raised.
func TestGCRelief_KeepsALowerSetting(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	acquireGCRelief()
	if got := gcPercent(); got != 10 {
		t.Fatalf("GC percent %d, want the lower 10 kept", got)
	}
	releaseGCRelief()
	if got := gcPercent(); got != 10 {
		t.Fatalf("GC percent %d after release, want 10", got)
	}
}

// The watcher turns relief on past its threshold and off when stopped.
func TestWatchLiveHeap_TurnsReliefOnAndOff(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(100))
	stop := watchLiveHeap(1) // any live heap passes
	deadline := time.Now().Add(5 * time.Second)
	for gcPercent() != gcReliefPercent && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := gcPercent(); got != gcReliefPercent {
		t.Fatalf("GC percent %d past the threshold", got)
	}
	stop()
	if got := gcPercent(); got != 100 {
		t.Fatalf("GC percent %d after stop", got)
	}
	// Below the threshold nothing changes.
	stop = watchLiveHeap(1 << 62)
	time.Sleep(3 * gcReliefPoll)
	if got := gcPercent(); got != 100 {
		t.Fatalf("GC percent %d below the threshold", got)
	}
	stop()
}
