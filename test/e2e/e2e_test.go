package test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/require"
)

// Test_E2EExclusions checks inline-disable silences exactly the requested rule per fixture pair.
func Test_E2EExclusions(t *testing.T) {
	pairs := []struct {
		name         string
		baseline     string
		disabled     string
		expectedSlug string
	}{
		{
			name:         "terraform",
			baseline:     filepath.Join("fixtures", "no-exclusions.tf"),
			disabled:     filepath.Join("fixtures", "inline-disabled-rule.tf"),
			expectedSlug: "terraform-aws-team-tag-not-present",
		},
		{
			name:         "kubernetes",
			baseline:     filepath.Join("fixtures", "k8s-no-exclusions.yaml"),
			disabled:     filepath.Join("fixtures", "k8s-inline-disabled-rule.yaml"),
			expectedSlug: "kubernetes-container-is-privileged",
		},
		{
			name:         "cicd",
			baseline:     filepath.Join("fixtures", ".github/cicd-no-exclusions.yaml"),
			disabled:     filepath.Join("fixtures", ".github/cicd-inline-disabled-rule.yaml"),
			expectedSlug: "cicd-github-unpinned-actions-full-length-commit-sha",
		},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			baseline := runScan(t, p.baseline)
			disabled := runScan(t, p.disabled)

			require.Equal(t, baseline.Files, disabled.Files, "scans must process the same number of files")

			removed := violationDiff(baseline.ViolationBreakdowns, disabled.ViolationBreakdowns)
			added := violationDiff(disabled.ViolationBreakdowns, baseline.ViolationBreakdowns)

			require.Empty(t, added, "inline-disable should not introduce new violations, got: %v", added)
			require.Contains(t, removed, p.expectedSlug, "inline-disable should silence %s, got removed: %v", p.expectedSlug, removed)
			require.Len(t, removed, 1, "inline-disable should silence exactly one rule, got: %v", removed)
			require.Equal(t, removed[p.expectedSlug], baseline.Violations-disabled.Violations,
				"violation drop must match the silenced rule's count")
		})
	}
}

func runScan(t *testing.T, testFile string) scan.ScanStats {
	t.Helper()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{testFile}
	params.OutputPath = t.TempDir()
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
	}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	metadata, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)
	return metadata.Stats
}

func violationDiff(a, b map[string]map[string]int) map[string]int {
	flat := func(m map[string]map[string]int) map[string]int {
		out := map[string]int{}
		for _, slugs := range m {
			for slug, count := range slugs {
				out[slug] = count
			}
		}
		return out
	}
	af, bf := flat(a), flat(b)
	diff := map[string]int{}
	for slug, count := range af {
		if d := count - bf[slug]; d > 0 {
			diff[slug] = d
		}
	}
	return diff
}
