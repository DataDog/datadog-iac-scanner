/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package logger

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe to read while the writer flushes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestBatchingWriter_WarningsFlushWithWhatPrecedesThem(t *testing.T) {
	var out syncBuffer
	w := NewBatchingWriter(&out)
	defer func() { _ = w.Close() }()
	info := `{"level":"info","message":"a"}` + "\n"
	warn := `{"level":"warn","message":"b"}` + "\n"
	_, _ = w.Write([]byte(info))
	if out.String() != "" {
		// The periodic flush may have run; only the order matters then.
		t.Log("info line already flushed")
	}
	_, _ = w.Write([]byte(warn))
	if got := out.String(); got != info+warn {
		t.Fatalf("after a warning, output = %q, want both lines in order", got)
	}
}

func TestBatchingWriter_InfoLinesAreWrittenWithinTheInterval(t *testing.T) {
	var out syncBuffer
	w := NewBatchingWriter(&out)
	defer func() { _ = w.Close() }()
	line := `{"level":"info","message":"a"}` + "\n"
	_, _ = w.Write([]byte(line))
	deadline := time.Now().Add(10 * batchFlushInterval)
	for out.String() == "" && time.Now().Before(deadline) {
		time.Sleep(batchFlushInterval / 4)
	}
	if out.String() != line {
		t.Fatalf("output = %q, want the line written by the periodic flush", out.String())
	}
}

func TestBatchingWriter_LargeBatchesAndCloseWriteEverythingInOrder(t *testing.T) {
	var out syncBuffer
	w := NewBatchingWriter(&out)
	var want strings.Builder
	for i := 0; i < 5000; i++ {
		line := `{"level":"debug","message":"` + strings.Repeat("x", i%50) + `"}` + "\n"
		want.WriteString(line)
		_, _ = w.Write([]byte(line))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if out.String() != want.String() {
		t.Fatal("output differs from the lines written")
	}
}

func TestFlush_RunsTheRegisteredFlush(t *testing.T) {
	defer SetFlush(nil)
	called := false
	SetFlush(func() { called = true })
	Flush()
	if !called {
		t.Fatal("registered flush not run")
	}
	SetFlush(nil)
	Flush() // no flush registered: nothing happens
}
