/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"time"
)

const (
	// gcReliefLiveBytes is the live heap past which a scan collects more
	// often. Module evaluation can grow a scan of a few files into hundreds
	// of thousands of documents; with the default GC percent the heap then
	// peaks near three times what is live.
	gcReliefLiveBytes = 1 << 30
	// gcReliefPercent is the GC percent while relief is on.
	gcReliefPercent = 30
	// gcReliefPoll is how often the live heap is read.
	gcReliefPoll = 250 * time.Millisecond
)

// gcRelief lowers the process GC percent while any scan holding it has a
// large live heap. The setting is process-wide, so it is reference-counted:
// concurrent scans do not restore it under one another.
var gcRelief struct {
	mu       sync.Mutex
	holders  int
	previous int
}

func acquireGCRelief() {
	gcRelief.mu.Lock()
	defer gcRelief.mu.Unlock()
	if gcRelief.holders == 0 {
		gcRelief.previous = debug.SetGCPercent(gcReliefPercent)
		if gcRelief.previous >= 0 && gcRelief.previous < gcReliefPercent {
			// A lower setting is already in force; keep it.
			debug.SetGCPercent(gcRelief.previous)
		}
	}
	gcRelief.holders++
}

func releaseGCRelief() {
	gcRelief.mu.Lock()
	defer gcRelief.mu.Unlock()
	gcRelief.holders--
	if gcRelief.holders == 0 {
		debug.SetGCPercent(gcRelief.previous)
	}
}

// watchLiveHeap turns relief on once the live heap reaches threshold and
// keeps it until the returned stop is called.
func watchLiveHeap(threshold uint64) (stop func()) {
	done := make(chan struct{})
	finished := make(chan bool, 1)
	go func() {
		sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
		ticker := time.NewTicker(gcReliefPoll)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				finished <- false
				return
			case <-ticker.C:
			}
			metrics.Read(sample)
			if sample[0].Value.Kind() == metrics.KindUint64 && sample[0].Value.Uint64() >= threshold {
				acquireGCRelief()
				<-done
				finished <- true
				return
			}
		}
	}()
	return func() {
		close(done)
		if <-finished {
			releaseGCRelief()
		}
	}
}
