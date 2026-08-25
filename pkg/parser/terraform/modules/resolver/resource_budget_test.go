/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageCounterEnforcesLimitsBeforeAccounting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limits ResourceLimits
		sizes  []int64
		limit  string
	}{
		{
			name:   "file bytes",
			limits: ResourceLimits{MaxFileBytes: 3},
			sizes:  []int64{4},
			limit:  "file_bytes",
		},
		{
			name:   "file count",
			limits: ResourceLimits{MaxPackageFiles: 1},
			sizes:  []int64{1, 1},
			limit:  "package_file_count",
		},
		{
			name:   "package bytes",
			limits: ResourceLimits{MaxPackageBytes: 3},
			sizes:  []int64{2, 2},
			limit:  "package_bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			counter := NewResourceBudget(tt.limits).NewPackageCounter()
			var err error
			for _, size := range tt.sizes {
				err = counter.AddEntry(size)
				if err != nil {
					break
				}
			}
			var budgetErr *BudgetExceededError
			require.ErrorAs(t, err, &budgetErr)
			require.Equal(t, tt.limit, budgetErr.Limit)
		})
	}
}

func TestResourceBudgetReconcilesPackages(t *testing.T) {
	t.Parallel()

	budget := NewResourceBudget(ResourceLimits{MaxTotalBytes: 5})
	require.NoError(t, budget.AdmitPackage("/tmp/a", PackageUsage{Bytes: 4, Files: 1}))
	require.NoError(t, budget.AdmitPackage("/tmp/a", PackageUsage{Bytes: 6, Files: 2}))
	require.NoError(t, budget.AdmitPackage("/tmp/b", PackageUsage{Bytes: 2, Files: 1}))
	require.NoError(t, budget.AdmitPackage("/tmp/a", PackageUsage{Bytes: 4, Files: 1}))
	require.Equal(t, PackageUsage{Bytes: 8, Files: 3}, budget.TotalUsage())
}

func TestResourceBudgetReservesAcquisitionAgainstUsage(t *testing.T) {
	t.Parallel()

	budget := NewResourceBudget(ResourceLimits{})
	require.NoError(t, budget.AdmitPackage("/tmp/a", PackageUsage{Bytes: 4}))

	reserved, ok := budget.ReserveAcquisition(10, 8)
	require.True(t, ok)
	require.Equal(t, int64(6), reserved)

	_, ok = budget.ReserveAcquisition(10, 1)
	require.False(t, ok)
	budget.ReleaseAcquisition(reserved)

	reserved, ok = budget.ReserveAcquisition(10, 3)
	require.True(t, ok)
	require.Equal(t, int64(3), reserved)
}

func TestMeasurePackageStopsAtConfiguredLimit(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.tf"), []byte("123"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "two.tf"), []byte("456"), 0o600))

	_, err := MeasurePackage(t.Context(), root, ResourceLimits{MaxPackageBytes: 5})
	var budgetErr *BudgetExceededError
	require.True(t, errors.As(err, &budgetErr))
	require.Equal(t, int64(6), budgetErr.Measured)
}

func TestMeasurePackageIgnoresPerFileLimit(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "large.zip"), make([]byte, 8), 0o600))

	usage, err := MeasurePackage(t.Context(), root, ResourceLimits{MaxFileBytes: 5})
	require.NoError(t, err)
	require.Equal(t, int64(9), usage.Bytes)
	require.Equal(t, 2, usage.Files)
}
