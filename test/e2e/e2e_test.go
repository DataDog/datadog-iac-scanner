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

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	require.NoError(t, err)
	return abs
}

// Test_E2EExclusions checks inline-disable silences exactly the requested rule per fixture pair.
// Rules are loaded from testdata/rules/ rather than the embedded corpus (assets/queries/ removed).
func Test_E2EExclusions(t *testing.T) {
	pairs := []struct {
		name         string
		baseline     string
		disabled     string
		expectedSlug string
		queriesPaths []string
	}{
		{
			name:         "terraform",
			baseline:     filepath.Join("fixtures", "no-exclusions.tf"),
			disabled:     filepath.Join("fixtures", "inline-disabled-rule.tf"),
			expectedSlug: "terraform-aws-team-tag-not-present",
			queriesPaths: []string{filepath.Join("testdata", "rules", "terraform")},
		},
		{
			name:         "kubernetes",
			baseline:     filepath.Join("fixtures", "k8s-no-exclusions.yaml"),
			disabled:     filepath.Join("fixtures", "k8s-inline-disabled-rule.yaml"),
			expectedSlug: "kubernetes-container-is-privileged",
			queriesPaths: []string{filepath.Join("testdata", "rules", "k8s")},
		},
		{
			name:         "cicd",
			baseline:     filepath.Join("fixtures", ".github/cicd-no-exclusions.yaml"),
			disabled:     filepath.Join("fixtures", ".github/cicd-inline-disabled-rule.yaml"),
			expectedSlug: "cicd-github-unpinned-actions-full-length-commit-sha",
			queriesPaths: []string{filepath.Join("testdata", "rules", "cicd")},
		},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			absQueriesPaths := make([]string, len(p.queriesPaths))
			for i, qp := range p.queriesPaths {
				absQueriesPaths[i] = mustAbs(t, qp)
			}
			baseline := runScan(t, p.baseline, absQueriesPaths)
			disabled := runScan(t, p.disabled, absQueriesPaths)

			require.NotEmpty(t, baseline.ViolationBreakdowns, "no violations in baseline: check queriesPaths")
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

func runScan(t *testing.T, testFile string, queriesPaths []string) scan.ScanStats {
	t.Helper()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{testFile}
	params.OutputPath = t.TempDir()
	params.QueriesPath = queriesPaths
	params.ChangedDefaultQueryPath = true
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

// Test_E2ETerraformPlanFlag verifies JSON platform gating:
// 1. Terraform plan JSON is scanned only when --x-terraform-plan is enabled (CLI disk scans)
// 2. CloudFormation and other platform JSON files are scanned regardless of the flag
// 3. Terraform-only scans do not register the JSON parser when the flag is disabled
func Test_E2ETerraformPlanFlag(t *testing.T) {
	fixturesDir := filepath.Join("..", "fixtures", "tfplan_flag_test")

	t.Run("tfplan scanned with flag enabled", func(t *testing.T) {
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		params.Path = []string{filepath.Join(fixturesDir, "tfplan.json")}
		params.OutputPath = t.TempDir()
		params.QueriesPath = []string{mustAbs(t, filepath.Join("..", "..", "assets", "queries"))}
		params.ShouldScanTfPlans = true
		params.Platform = []string{"terraform"}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}

		metadata, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		// Verify that the Terraform plan JSON file was processed
		require.Greater(t, metadata.Stats.Files, 0, "Terraform plan JSON should be scanned when flag is enabled")
	})

	t.Run("tfplan not scanned with flag disabled", func(t *testing.T) {
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		params.Path = []string{filepath.Join(fixturesDir, "tfplan.json")}
		params.OutputPath = t.TempDir()
		params.QueriesPath = []string{mustAbs(t, filepath.Join("..", "..", "assets", "queries"))}
		params.ShouldScanTfPlans = false
		params.Platform = []string{"terraform"}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}

		metadata, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		// Verify that the Terraform plan JSON file was NOT processed
		require.Equal(t, 0, metadata.Stats.Files, "Terraform plan JSON should not be scanned when flag is disabled")
	})

	t.Run("cloudformation json scanned with flag enabled", func(t *testing.T) {
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		params.Path = []string{filepath.Join(fixturesDir, "cloudformation.json")}
		params.OutputPath = t.TempDir()
		params.QueriesPath = []string{mustAbs(t, filepath.Join("..", "..", "assets", "queries"))}
		params.ShouldScanTfPlans = true
		params.Platform = []string{"cloudformation"}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}

		metadata, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		require.Greater(t, metadata.Stats.Files, 0, "CloudFormation JSON should be scanned when cloudformation platform is enabled")
	})

	t.Run("cloudformation json scanned with flag disabled", func(t *testing.T) {
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		params.Path = []string{filepath.Join(fixturesDir, "cloudformation.json")}
		params.OutputPath = t.TempDir()
		params.QueriesPath = []string{mustAbs(t, filepath.Join("..", "..", "assets", "queries"))}
		params.ShouldScanTfPlans = false
		params.Platform = []string{"cloudformation"}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}

		metadata, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		require.Greater(t, metadata.Stats.Files, 0, "CloudFormation JSON should be scanned even when tf-plan flag is disabled")
	})

	t.Run("both files in same scan - both scanned when flag enabled", func(t *testing.T) {
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		params.Path = []string{fixturesDir}
		params.OutputPath = t.TempDir()
		params.QueriesPath = []string{mustAbs(t, filepath.Join("..", "..", "assets", "queries"))}
		params.ShouldScanTfPlans = true
		params.Platform = []string{"terraform", "cloudformation"}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}

		metadata, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		require.Equal(t, 2, metadata.Stats.Files, "Should scan both tfplan.json and cloudformation.json when flag is enabled")
	})
}
