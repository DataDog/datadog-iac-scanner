/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	gitBudgetSampleInterval    = 25 * time.Millisecond
	gitBudgetMaxSampleInterval = 500 * time.Millisecond
)

func runGitCommandWithResourceBudget(
	ctx context.Context, cmd *exec.Cmd, path string, budget *ResourceBudget,
) ([]byte, error) {
	maximum := budget.Limits().MaxPackageBytes
	if budget == nil || maximum <= 0 {
		return cmd.CombinedOutput()
	}
	baselineTotal, err := gitDirectoryBytes(ctx, path)
	if err != nil {
		return nil, err
	}
	objectMonitor, err := newGitObjectMonitor(ctx, path)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return output.Bytes(), err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	timer := time.NewTimer(objectMonitor.samplingInterval())
	defer timer.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				return output.Bytes(), err
			}
			if budgetErr := gitDirectoryBudgetError(ctx, path, baselineTotal, maximum); budgetErr != nil {
				return output.Bytes(), budgetErr
			}
			return output.Bytes(), nil
		case <-timer.C:
			if budgetErr := objectMonitor.budgetError(ctx, maximum); budgetErr != nil {
				_ = cmd.Process.Kill()
				<-done
				return output.Bytes(), budgetErr
			}
			timer.Reset(objectMonitor.samplingInterval())
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			return output.Bytes(), ctx.Err()
		}
	}
}

// gitObjectGuard watches a clone's object store while a command that may fetch
// objects lazily runs. `git archive` against a partial clone downloads missing
// blobs on demand, which grows the store without going through a fetch, so the
// guard aborts the command on breach and can undo the objects it pulled in.
type gitObjectGuard struct {
	gitDir   string
	monitor  *gitObjectMonitor
	existing map[string]bool
	maximum  int64

	mu     sync.Mutex
	breach error
}

func newGitObjectGuard(ctx context.Context, gitDir string, budget *ResourceBudget) (*gitObjectGuard, error) {
	maximum := budget.Limits().MaxPackageBytes
	if maximum <= 0 {
		return nil, nil //nolint:nilnil
	}
	monitor, err := newGitObjectMonitor(ctx, gitDir)
	if err != nil {
		return nil, err
	}
	existing, err := snapshotPackageTree(monitor.objectsDir)
	if err != nil {
		return nil, err
	}
	return &gitObjectGuard{
		gitDir:   gitDir,
		monitor:  monitor,
		existing: existing,
		maximum:  maximum,
	}, nil
}

// watch polls the object store until the returned stop function is called,
// aborting the running command as soon as the growth limit is breached. stop
// returns the breach error, if any.
func (g *gitObjectGuard) watch(ctx context.Context, abort func()) (stop func() error) {
	if g == nil {
		return func() error { return nil }
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		timer := time.NewTimer(g.monitor.samplingInterval())
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				if err := g.monitor.budgetError(ctx, g.maximum); err != nil {
					g.mu.Lock()
					if g.breach == nil {
						g.breach = err
					}
					g.mu.Unlock()
					abort()
					return
				}
				timer.Reset(g.monitor.samplingInterval())
			}
		}
	}()
	return func() error {
		close(done)
		<-finished
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.breach
	}
}

// rollback removes object files that appeared since the guard was created. The
// caller must hold the clone's object write lock so no reader observes the
// partially fetched objects being removed.
func (g *gitObjectGuard) rollback() {
	if g == nil {
		return
	}
	rollbackPackageTree(g.monitor.objectsDir, g.existing)
}

func gitDirectoryBudgetError(ctx context.Context, path string, baseline, maximum int64) error {
	measured, err := gitDirectoryBytes(ctx, path)
	if err != nil {
		return err
	}
	return gitGrowthBudgetError(measured-baseline, maximum)
}

func gitGrowthBudgetError(growth, maximum int64) error {
	if growth <= maximum {
		return nil
	}
	return &BudgetExceededError{
		Gate:     "stream",
		Limit:    limitPackageBytes,
		Maximum:  maximum,
		Measured: growth,
	}
}

type gitObjectMonitor struct {
	objectsDir string
	baseline   int64

	interval   time.Duration
	lastGrowth int64
	lastSample time.Time
}

func newGitObjectMonitor(ctx context.Context, path string) (*gitObjectMonitor, error) {
	monitor := &gitObjectMonitor{
		objectsDir: filepath.Join(path, "objects"),
		interval:   gitBudgetSampleInterval,
	}
	total, err := monitor.currentBytes(ctx)
	if err != nil {
		return nil, err
	}
	monitor.baseline = total
	return monitor, nil
}

func (m *gitObjectMonitor) budgetError(ctx context.Context, maximum int64) error {
	measured, err := m.currentBytes(ctx)
	if err != nil {
		return err
	}
	growth := measured - m.baseline
	m.recordSample(growth, maximum, time.Now())
	return gitGrowthBudgetError(growth, maximum)
}

// samplingInterval is how long to wait before measuring the object store again.
// A full scan is not cheap on a large clone, so the wait is spaced out by how
// long the observed download rate would need to consume the remaining headroom.
// A clone that is barely growing is scanned rarely, while a fast one is still
// sampled often enough to stop close to the limit.
func (m *gitObjectMonitor) samplingInterval() time.Duration {
	return m.interval
}

func (m *gitObjectMonitor) recordSample(growth, maximum int64, now time.Time) {
	previousGrowth, previousSample := m.lastGrowth, m.lastSample
	m.lastGrowth, m.lastSample = growth, now
	if previousSample.IsZero() {
		return
	}
	elapsed := now.Sub(previousSample)
	added := growth - previousGrowth
	headroom := maximum - growth
	if elapsed <= 0 || added <= 0 || headroom <= 0 {
		m.interval = gitBudgetSampleInterval
		return
	}
	rate := float64(added) / elapsed.Seconds()
	untilLimit := time.Duration(float64(headroom) / rate / 2 * float64(time.Second))
	m.interval = min(max(untilLimit, gitBudgetSampleInterval), gitBudgetMaxSampleInterval)
}

func (m *gitObjectMonitor) currentBytes(ctx context.Context) (int64, error) {
	entries, err := os.ReadDir(m.objectsDir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if !entry.IsDir() {
			continue
		}
		if name := entry.Name(); name != "pack" && !isLooseObjectDir(name) {
			continue
		}
		size, err := regularFilesBytes(ctx, filepath.Join(m.objectsDir, entry.Name()))
		if err != nil {
			return 0, err
		}
		total += size
	}
	return total, nil
}

func regularFilesBytes(ctx context.Context, path string) (int64, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total, nil
}

func isLooseObjectDir(name string) bool {
	return len(name) == 2 && strings.IndexFunc(name, func(r rune) bool {
		return !strings.ContainsRune("0123456789abcdef", r)
	}) == -1
}

func gitDirectoryBytes(ctx context.Context, path string) (int64, error) {
	usage, err := MeasurePackage(ctx, path, ResourceLimits{})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return usage.Bytes, err
}
