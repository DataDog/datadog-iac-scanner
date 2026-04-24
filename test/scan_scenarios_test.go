package test

import (
	"context"
	"encoding/json"
	"flag"
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

var updateScanScenarios = flag.Bool("update", false, "update scan scenario golden files")

type sarifDocument struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	HelpURI              string                 `json:"helpUri"`
	DefaultConfiguration sarifConfiguration     `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	ArtifactURI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

type normalizedSARIF struct {
	Rules   []normalizedRule   `json:"rules"`
	Results []normalizedResult `json:"results"`
}

type normalizedRule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Level   string   `json:"level"`
	HelpURI string   `json:"helpUri,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

type normalizedResult struct {
	RuleID      string   `json:"ruleId"`
	Level       string   `json:"level"`
	Message     string   `json:"message"`
	ArtifactURI string   `json:"artifactUri,omitempty"`
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	StartColumn int      `json:"startColumn"`
	EndColumn   int      `json:"endColumn"`
	Tags        []string `json:"tags,omitempty"`
}

func TestScanScenarios(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	require.NoError(t, err)

	fixturesRoot := filepath.Join(repoRoot, "test", "fixtures", "scan_scenarios")
	expectedRoot := filepath.Join(fixturesRoot, "expected")
	entries, err := os.ReadDir(fixturesRoot)
	require.NoError(t, err)

	var scenarios []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "expected" {
			continue
		}
		scenarios = append(scenarios, entry.Name())
	}
	sort.Strings(scenarios)
	require.NotEmpty(t, scenarios)

	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			scenarioPath := filepath.Join(fixturesRoot, scenario)
			normalized := runScenarioScan(t, repoRoot, scenarioPath)

			gotJSON, err := json.MarshalIndent(normalized, "", "  ")
			require.NoError(t, err)
			gotJSON = append(gotJSON, '\n')

			expectedPath := filepath.Join(expectedRoot, scenario+".json")
			if *updateScanScenarios {
				require.NoError(t, os.MkdirAll(expectedRoot, 0o755))
				require.NoError(t, os.WriteFile(expectedPath, gotJSON, 0o644))
			}

			expectedJSON, err := os.ReadFile(expectedPath)
			require.NoErrorf(t, err, "missing golden file for %s; run go test ./test -run TestScanScenarios -update", scenario)
			require.JSONEq(t, string(expectedJSON), string(gotJSON))
		})
	}
}

func runScenarioScan(t *testing.T, repoRoot, scenarioPath string) normalizedSARIF {
	t.Helper()

	params, ctx := scan.GetDefaultParameters(context.Background(), repoRoot)
	require.NotNil(t, params)

	params.Path = []string{scenarioPath}
	params.OutputPath = t.TempDir()
	params.OutputName = "scan-scenarios.sarif"
	params.RepoPath = repoRoot
	params.Platform = []string{"Kubernetes"}
	params.FlagEvaluator = featureflags.NewLocalEvaluatorWithOverrides(map[string]bool{
		featureflags.IacEnableKustomizeResolver: true,
	})
	params.SCIInfo = model.SCIInfo{
		DiffAware: model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{
			RepositoryUrl: "https://example.invalid/datadog-iac-scanner",
			CommitSHA:     "scan-scenarios-test",
			Branch:        "scan-scenarios",
		},
	}

	_, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)

	reportPath := filepath.Join(params.OutputPath, params.OutputName)
	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)

	return normalizeSARIF(t, data)
}

func normalizeSARIF(t *testing.T, data []byte) normalizedSARIF {
	t.Helper()

	var doc sarifDocument
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Len(t, doc.Runs, 1)

	run := doc.Runs[0]
	out := normalizedSARIF{
		Rules:   make([]normalizedRule, 0, len(run.Tool.Driver.Rules)),
		Results: make([]normalizedResult, 0, len(run.Results)),
	}

	for _, rule := range run.Tool.Driver.Rules {
		out.Rules = append(out.Rules, normalizedRule{
			ID:      rule.ID,
			Name:    rule.Name,
			Level:   rule.DefaultConfiguration.Level,
			HelpURI: rule.HelpURI,
			Tags:    sortedStringProperty(rule.Properties, "tags"),
		})
	}

	for _, result := range run.Results {
		nr := normalizedResult{
			RuleID:  result.RuleID,
			Level:   result.Level,
			Message: result.Message.Text,
			Tags:    sortedStringProperty(result.Properties, "tags"),
		}
		if len(result.Locations) > 0 {
			loc := result.Locations[0].PhysicalLocation
			nr.ArtifactURI = filepath.ToSlash(loc.ArtifactLocation.ArtifactURI)
			nr.StartLine = loc.Region.StartLine
			nr.EndLine = loc.Region.EndLine
			nr.StartColumn = loc.Region.StartColumn
			nr.EndColumn = loc.Region.EndColumn
		}
		out.Results = append(out.Results, nr)
	}

	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].ID != out.Rules[j].ID {
			return out.Rules[i].ID < out.Rules[j].ID
		}
		return out.Rules[i].Name < out.Rules[j].Name
	})
	sort.Slice(out.Results, func(i, j int) bool {
		a, b := out.Results[i], out.Results[j]
		switch {
		case a.RuleID != b.RuleID:
			return a.RuleID < b.RuleID
		case a.ArtifactURI != b.ArtifactURI:
			return a.ArtifactURI < b.ArtifactURI
		case a.StartLine != b.StartLine:
			return a.StartLine < b.StartLine
		case a.StartColumn != b.StartColumn:
			return a.StartColumn < b.StartColumn
		default:
			return a.Message < b.Message
		}
	})

	return out
}

func sortedStringProperty(properties map[string]interface{}, key string) []string {
	if len(properties) == 0 {
		return nil
	}
	raw, ok := properties[key]
	if !ok {
		return nil
	}

	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}

	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
