package test

import (
	"context"
	"encoding/json"
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

// determinismFixtures are the rules the determinism fixture directory raises,
// with the findings each rule must report. The privileged-container rule
// raises one result per container of one deployment, so two findings of one
// identity are collapsed and the report must keep the first container's
// line, whatever order the rules were evaluated in.
var determinismFixtures = []struct {
	queryName string
	wantLines []int
	wantFile  string
}{
	{queryName: "Team tag missing on AWS resource", wantLines: []int{5}, wantFile: "main.tf"},
	// Two privileged containers of one deployment: two results of one
	// identity, the report keeps the first container's line.
	{queryName: "Container is privileged", wantLines: []int{19}, wantFile: "workload.yaml"},
	{queryName: "Unpinned actions full length commit SHA", wantLines: []int{8, 13}, wantFile: filepath.Join(".github", "workflows", "determinism.yml")},
}

// Test_E2EFindingOrderIsDeterministic scans Terraform, Kubernetes and CI/CD
// fixtures several times, with different worker counts, and requires the
// reports to match once the scan duration is dropped. A scan's findings,
// their order, and the line a finding whose identity is raised more than
// once reports must not depend on the order rules were scheduled in.
func Test_E2EFindingOrderIsDeterministic(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "determinism")
	ruleDirs := []string{"terraform", "k8s", "cicd"}
	absQueriesPaths := make([]string, 0, len(ruleDirs))
	for _, dir := range ruleDirs {
		absQueriesPaths = append(absQueriesPaths, mustAbs(t, filepath.Join("testdata", "rules", dir)))
	}

	// The scan duration is stamped into the report, so reports of one scan
	// differ by it alone.
	durationTag := regexp.MustCompile(`DATADOG_EXECUTION_TIME_SECS:[0-9.]+`)

	var want string
	for _, workers := range []int{0, 0, 1, 8} {
		sarif := scanSARIF(t, fixtureDir, absQueriesPaths, workers)
		got := durationTag.ReplaceAllString(string(sarif), "DATADOG_EXECUTION_TIME_SECS:0")
		require.NotEmpty(t, got, "the scan must write a report")
		if want == "" {
			want = got
			requireDeterministicFindings(t, []byte(got))
			continue
		}
		require.Equal(t, want, got, "the report changed between runs or with %d workers", workers)
	}
}

// requireDeterministicFindings pins what the fixture scan must report: every
// rule's findings, at the expected lines.
func requireDeterministicFindings(t *testing.T, sarif []byte) {
	t.Helper()
	var report struct {
		Runs []struct {
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					Tags []string `json:"tags"`
				} `json:"properties"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(sarif, &report))
	require.Len(t, report.Runs, 1)

	got := map[string][]int{}
	gotFiles := map[string]string{}
	for _, r := range report.Runs[0].Results {
		got[r.RuleID] = append(got[r.RuleID], r.Locations[0].PhysicalLocation.Region.StartLine)
		gotFiles[r.RuleID] = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
	}
	for _, fixture := range determinismFixtures {
		lines := got[fixture.queryName]
		require.NotEmpty(t, lines, "%s must report findings", fixture.queryName)
		require.ElementsMatch(t, fixture.wantLines, lines,
			"%s must report exactly one finding per expected location; with a shared identity the report keeps the first one", fixture.queryName)
	}
}

// scanSARIF scans one path with the given worker count and returns the SARIF
// report the scan wrote.
func scanSARIF(t *testing.T, testPath string, queriesPaths []string, workers int) []byte {
	t.Helper()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{testPath}
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
