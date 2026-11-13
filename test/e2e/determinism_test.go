package test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/require"
)

// Test_E2EFindingOrderIsDeterministic runs the same scan several times, with
// different worker counts, and requires the reports to match once the scan
// duration is dropped. A scan's findings, their order, and the line a finding
// whose identity is raised more than once reports must not depend on the
// order rules were scheduled in.
func Test_E2EFindingOrderIsDeterministic(t *testing.T) {
	fixtures := []struct {
		file         string
		queriesPaths []string
	}{
		{
			file:         filepath.Join("fixtures", "no-exclusions.tf"),
			queriesPaths: []string{filepath.Join("testdata", "rules", "terraform")},
		},
		{
			file:         filepath.Join("fixtures", "k8s-no-exclusions.yaml"),
			queriesPaths: []string{filepath.Join("testdata", "rules", "k8s")},
		},
		{
			file:         filepath.Join("fixtures", ".github", "cicd-no-exclusions.yaml"),
			queriesPaths: []string{filepath.Join("testdata", "rules", "cicd")},
		},
		{
			file:         filepath.Join("fixtures", "positive.tofu"),
			queriesPaths: []string{filepath.Join("testdata", "rules", "terraform")},
		},
		{
			file:         filepath.Join("fixtures", "positive.tf.json"),
			queriesPaths: []string{filepath.Join("testdata", "rules", "terraform")},
		},
	}

	// The scan duration is stamped into the report, so reports of one scan
	// differ by it alone.
	durationTag := regexp.MustCompile(`DATADOG_EXECUTION_TIME_SECS:[0-9.]+`)

	for _, fixture := range fixtures {
		t.Run(fixture.file, func(t *testing.T) {
			absQueriesPaths := make([]string, len(fixture.queriesPaths))
			for i, qp := range fixture.queriesPaths {
				absQueriesPaths[i] = mustAbs(t, qp)
			}

			var want []byte
			for _, workers := range []int{0, 0, 1, 8} {
				sarif := scanSARIF(t, fixture.file, absQueriesPaths, workers)
				got := durationTag.ReplaceAll(sarif, []byte("DATADOG_EXECUTION_TIME_SECS:0"))
				require.NotEmpty(t, got, "the scan must write a report")
				if want == nil {
					require.NotContains(t, string(got), "DATADOG_EXECUTION_TIME_SECS:DATADOG_EXECUTION_TIME_SECS")
					want = got
					continue
				}
				require.Equal(t, string(want), string(got),
					"the report changed between runs or with %d workers", workers)
			}
		})
	}
}

// scanSARIF scans one file with the given worker count and returns the SARIF
// report the scan wrote.
func scanSARIF(t *testing.T, testFile string, queriesPaths []string, workers int) []byte {
	t.Helper()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{testFile}
	params.OutputPath = t.TempDir()
	params.QueriesPath = queriesPaths
	params.ChangedDefaultQueryPath = true
	params.ParallelScanFlag = workers
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
	}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	_, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)
	sarif, err := os.ReadFile(filepath.Join(params.OutputPath, "kics-result.sarif"))
	require.NoError(t, err)
	return sarif
}
