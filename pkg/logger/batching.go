/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package logger

import (
	"bytes"
	"io"
	"sync"
	"time"
)

const (
	// batchFlushBytes is how much buffered output is written at once.
	batchFlushBytes = 64 << 10
	// batchFlushInterval is the longest a buffered line waits to be written.
	batchFlushInterval = 100 * time.Millisecond
)

// batchedLevels are the JSON log line prefixes buffered; any other line,
// warnings and errors included, is written at once with what precedes it.
var batchedLevels = [][]byte{
	[]byte(`{"level":"info"`),
	[]byte(`{"level":"debug"`),
	[]byte(`{"level":"trace"`),
}

// BatchingWriter writes JSON log lines in batches. A scan can log one line
// per finding, hundreds of thousands of them, and one write per line then
// costs more than the scan's own work. Info and lower lines wait at most
// batchFlushInterval; any other line is written immediately, after the lines
// buffered before it, so warnings and errors are never delayed.
type BatchingWriter struct {
	mu   sync.Mutex
	out  io.Writer
	buf  bytes.Buffer
	stop chan struct{}
	done chan struct{}
}

// NewBatchingWriter starts batching writes to out until Close.
func NewBatchingWriter(out io.Writer) *BatchingWriter {
	w := &BatchingWriter{out: out, stop: make(chan struct{}), done: make(chan struct{})}
	go w.flushPeriodically()
	return w
}

func (w *BatchingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if w.buf.Len() >= batchFlushBytes || !batched(p) {
		if err := w.flushLocked(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func batched(line []byte) bool {
	for _, prefix := range batchedLevels {
		if bytes.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// Flush writes what is buffered.
func (w *BatchingWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

func (w *BatchingWriter) flushLocked() error {
	if w.buf.Len() == 0 {
		return nil
	}
	_, err := w.out.Write(w.buf.Bytes())
	w.buf.Reset()
	return err
}

func (w *BatchingWriter) flushPeriodically() {
	defer close(w.done)
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			_ = w.Flush()
		}
	}
}

// Close stops the periodic flush and writes what is buffered.
func (w *BatchingWriter) Close() error {
	close(w.stop)
	<-w.done
	return w.Flush()
}

var (
	flushMu sync.Mutex
	flushFn func()
)

// SetFlush registers what Flush runs, for the process's log output.
func SetFlush(fn func()) {
	flushMu.Lock()
	defer flushMu.Unlock()
	flushFn = fn
}

// Flush writes any log output still buffered. Code that exits the process
// itself calls it first.
func Flush() {
	flushMu.Lock()
	fn := flushFn
	flushMu.Unlock()
	if fn != nil {
		fn()
	}
}
