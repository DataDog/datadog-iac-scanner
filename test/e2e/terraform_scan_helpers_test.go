package test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/require"
)

// runTerraformScanTo is runTerraformScan with the reports written to out.
func runTerraformScanTo(t *testing.T, dir, rules, out string, plans ...bool) scan.ScanStats {
	t.Helper()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{dir}
	params.OutputPath = out
	params.OutputName = "result"
	params.QueriesPath = []string{filepath.Join(rules, "terraform")}
	params.ChangedDefaultQueryPath = true
	params.LibrariesPath = filepath.Join(rules, "libraries")
	params.ChangedDefaultLibrariesPath = true
	params.Platform = []string{"Terraform"}
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
	}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	params.ShouldScanTfPlans = len(plans) > 0 && plans[0]
	metadata, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)
	return metadata.Stats
}

// anchoredLines lists "file:line" of the SARIF results of rule.
func anchoredLines(t *testing.T, dir, rule string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "result.sarif"))
	require.NoError(t, err)
	var report struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					Physical struct {
						Artifact struct {
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
	require.NoError(t, json.Unmarshal(raw, &report))
	var out []string
	for _, r := range report.Runs[0].Results {
		if r.RuleID != rule || len(r.Locations) == 0 {
			continue
		}
		loc := r.Locations[0].Physical
		out = append(out, loc.Artifact.URI+":"+itoa(loc.Region.StartLine))
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
