/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunGitCommandStopsAtResourceBudget(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestGitResourceBudgetHelper", "--", dir)
	cmd.Env = append(os.Environ(), "GO_WANT_GIT_BUDGET_HELPER=1")
	budget := NewResourceBudget(ResourceLimits{MaxPackageBytes: 512})

	_, err := runGitCommandWithResourceBudget(t.Context(), cmd, dir, budget)

	var budgetErr *BudgetExceededError
	require.True(t, errors.As(err, &budgetErr))
	require.Equal(t, "package_bytes", budgetErr.Limit)
	info, statErr := os.Stat(filepath.Join(dir, "objects", "pack", "incoming.pack"))
	require.NoError(t, statErr)
	require.LessOrEqual(t, info.Size(), int64(1536))
}

func TestGitObjectMonitorCountsLooseObjects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	monitor, err := newGitObjectMonitor(t.Context(), dir)
	require.NoError(t, err)
	objectDir := filepath.Join(dir, "objects", "aa")
	require.NoError(t, os.MkdirAll(objectDir, 0o755))
	objectPath := filepath.Join(objectDir, "object")
	require.NoError(t, os.WriteFile(objectPath, make([]byte, 256), 0o600))
	require.NoError(t, monitor.budgetError(t.Context(), 512))
	file, err := os.OpenFile(objectPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = file.Write(make([]byte, 257))
	require.NoError(t, err)
	require.NoError(t, file.Close())

	err = monitor.budgetError(t.Context(), 512)

	var budgetErr *BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)
	require.Equal(t, int64(513), budgetErr.Measured)
}

func TestGitObjectMonitorFindsLooseObjectsWhenDirectoryTimestampIsUnchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	objectDir := filepath.Join(dir, "objects", "aa")
	require.NoError(t, os.MkdirAll(objectDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(objectDir, "existing"), []byte("x"), 0o600))
	info, err := os.Stat(objectDir)
	require.NoError(t, err)
	monitor, err := newGitObjectMonitor(t.Context(), dir)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(objectDir, "new"), make([]byte, 513), 0o600))
	require.NoError(t, os.Chtimes(objectDir, info.ModTime(), info.ModTime()))

	err = monitor.budgetError(t.Context(), 512)
	var budgetErr *BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)
	require.Equal(t, int64(513), budgetErr.Measured)
}

func TestGitResourceBudgetHelper(t *testing.T) {
	if os.Getenv("GO_WANT_GIT_BUDGET_HELPER") != "1" {
		return
	}
	dir := os.Args[len(os.Args)-1]
	packDir := filepath.Join(dir, "objects", "pack")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		os.Exit(1)
	}
	file, err := os.Create(filepath.Join(packDir, "incoming.pack"))
	if err != nil {
		os.Exit(1)
	}
	defer func() { _ = file.Close() }()
	chunk := make([]byte, 256)
	for {
		if _, err := file.Write(chunk); err != nil {
			os.Exit(1)
		}
		if err := file.Sync(); err != nil {
			os.Exit(1)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGitObjectMonitorSpacesSamplesByGrowthRate(t *testing.T) {
	t.Parallel()

	start := time.Now()
	monitor := &gitObjectMonitor{interval: gitBudgetSampleInterval}
	monitor.recordSample(0, 10<<20, start)

	// A trickle of objects leaves plenty of headroom, so the next scan waits.
	monitor.recordSample(1024, 10<<20, start.Add(time.Second))
	require.Equal(t, gitBudgetMaxSampleInterval, monitor.samplingInterval())

	// A download that would consume the headroom in milliseconds is sampled at
	// the tightest interval.
	monitor.recordSample(10<<20-1024, 10<<20, start.Add(2*time.Second))
	require.Equal(t, gitBudgetSampleInterval, monitor.samplingInterval())
}

func TestGitObjectGuardAbortsAndRollsBackLazyObjectFetch(t *testing.T) {
	t.Parallel()

	gitDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(gitDir, "objects"), 0o755))
	guard, err := newGitObjectGuard(
		t.Context(), gitDir, NewResourceBudget(ResourceLimits{MaxPackageBytes: 512}),
	)
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "-test.run=TestGitResourceBudgetHelper", "--", gitDir)
	cmd.Env = append(os.Environ(), "GO_WANT_GIT_BUDGET_HELPER=1")
	extracted := int64(0)

	err = extractArchiveCommandWithResourceBudget(
		t.Context(), cmd, t.TempDir(), &extracted, 1024, nil, guard,
	)

	var budgetErr *BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)
	require.Equal(t, "package_bytes", budgetErr.Limit)

	rollbackGitObjects(guard, nil)
	_, statErr := os.Stat(filepath.Join(gitDir, "objects", "pack", "incoming.pack"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
