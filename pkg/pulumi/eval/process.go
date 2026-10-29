/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

// maxOutput is how much of a program's output (the end) is kept.
const maxOutput = 256 << 10

// waitDelay bounds the wait for output pipes after the process exited.
const waitDelay = 5 * time.Second

// tailBuffer keeps the last bytes written to it. It trims only once it holds
// twice its limit, so that a long output does not shift the buffer on every write.
type tailBuffer struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.limit {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.limit:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if over := len(t.buf) - t.limit; over > 0 {
		return string(t.buf[over:])
	}
	return string(t.buf)
}

type command struct {
	argv    []string
	dir     string
	env     childEnv
	timeout time.Duration
}

type runResult struct {
	err      error
	timedOut bool
	output   string
}

// run runs a command in its own process group with a timeout. The whole group
// is killed on timeout or cancellation, and after the command exits, so that
// nothing the program started keeps running.
func run(ctx context.Context, c *command) runResult {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.argv[0], c.argv[1:]...) //nolint:gosec // runs the program under evaluation, by design
	cmd.Dir = c.dir
	cmd.Env = c.env.list()
	out := &tailBuffer{limit: maxOutput}
	cmd.Stdout, cmd.Stderr = out, out
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	_ = killProcessGroup(cmd)
	// A program that exited successfully but left a process holding its
	// output open (killed just above) still succeeded.
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		err = nil
	}
	return runResult{
		err:      err,
		timedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
		output:   out.String(),
	}
}
