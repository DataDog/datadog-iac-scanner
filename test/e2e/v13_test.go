package test

// Comprehensive local tests for code-security.datadog.yaml v1.3 features:
//   - per-rule ignore-paths / only-paths
//   - per-rule severity override
//   - global-config only-platforms / ignore-platforms

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	sarifmodel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Rule slugs (QueryID) — used in ViolationBreakdowns.
const (
	ruleTeamTag         = "terraform-aws-team-tag-not-present"
	ruleTeamTagLegacyID = "a2b3c4d5-e6f7-8901-gh23-ijkl456m7890"
	rulePrivileged      = "kubernetes-container-is-privileged"
	ruleCicdPinned      = "cicd-github-unpinned-actions-full-length-commit-sha"
)

// Fixture root under test/e2e/fixtures/v13/
// Paths are relative to the test/e2e working directory so that file.FilePath
// inside the engine stays relative and matches the filter patterns in RuleConfigs.
const fixtureV13 = "fixtures/v13"

func strPtr(s string) *string { return &s }

// allQueriesPaths covers all three platforms under test.
var allQueriesPaths = []string{
	filepath.Join("testdata", "rules", "terraform"),
	filepath.Join("testdata", "rules", "k8s"),
	filepath.Join("testdata", "rules", "cicd"),
}

// sarifRuleIDMap builds a slug→queryName map by reading metadata.json files from
// the local testdata rules directories. SARIF uses the query name as ruleId.
func sarifRuleIDMap(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range allQueriesPaths {
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name(), "metadata.json"))
			require.NoError(t, err)
			var meta struct {
				ID        string `json:"id"`
				QueryName string `json:"queryName"`
			}
			require.NoError(t, json.Unmarshal(data, &meta))
			out[meta.ID] = meta.QueryName
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// SARIF helpers (for path and severity inspection)
// -----------------------------------------------------------------------------

type sarifResult struct {
	RuleID    string
	Level     string   // "error" | "warning" | "note" | "none"
	Locations []string // artifact URIs
}

func parseSARIF(t *testing.T, outputDir string) []sarifResult {
	t.Helper()
	entries, err := os.ReadDir(outputDir)
	require.NoError(t, err)

	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sarif") {
			data, err := os.ReadFile(filepath.Join(outputDir, e.Name()))
			require.NoError(t, err)

			var doc struct {
				Runs []struct {
					Results []struct {
						RuleID    string `json:"ruleId"`
						Level     string `json:"level"`
						Locations []struct {
							PhysicalLocation struct {
								ArtifactLocation struct {
									URI string `json:"uri"`
								} `json:"artifactLocation"`
							} `json:"physicalLocation"`
						} `json:"locations"`
					} `json:"results"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal(data, &doc))

			var out []sarifResult
			for _, run := range doc.Runs {
				for _, r := range run.Results {
					var locs []string
					for _, l := range r.Locations {
						locs = append(locs, l.PhysicalLocation.ArtifactLocation.URI)
					}
					out = append(out, sarifResult{
						RuleID:    r.RuleID,
						Level:     r.Level,
						Locations: locs,
					})
				}
			}
			return out
		}
	}
	return nil
}

// filterSARIF returns results for a rule. nameMap is the slug→queryName map
// from sarifRuleIDMap; pass nil to match by ruleId directly.
func filterSARIF(results []sarifResult, ruleID string, nameMap map[string]string) []sarifResult {
	name := nameMap[ruleID]
	var out []sarifResult
	for _, r := range results {
		if r.RuleID == ruleID || (name != "" && r.RuleID == name) {
			out = append(out, r)
		}
	}
	return out
}

// locationsContain returns true if any location URI contains the given substring.
func locationsContain(results []sarifResult, substr string) bool {
	for _, r := range results {
		for _, l := range r.Locations {
			if strings.Contains(l, substr) {
				return true
			}
		}
	}
	return false
}

// levelsFor returns the distinct SARIF level values for a rule's findings.
func levelsFor(results []sarifResult, ruleID string, nameMap map[string]string) map[string]bool {
	levels := map[string]bool{}
	for _, r := range filterSARIF(results, ruleID, nameMap) {
		levels[r.Level] = true
	}
	return levels
}

// -----------------------------------------------------------------------------
// Scan helper
// -----------------------------------------------------------------------------

type scanResult struct {
	metadata scan.ScanMetadata
	sarifDir string
	nameMap  map[string]string // rule slug → SARIF ruleId (query name)
}

// countForRule returns the total finding count for a rule across all severities.
// Reads from ViolationBreakdowns: map[severity][ruleID] = count.
func (s *scanResult) countForRule(ruleID string) int {
	total := 0
	for _, byRule := range s.metadata.Stats.ViolationBreakdowns {
		total += byRule[ruleID]
	}
	return total
}

// ruleHasFindings returns true if the rule produced any findings.
func (s *scanResult) ruleHasFindings(ruleID string) bool {
	return s.countForRule(ruleID) > 0
}

// severitiesForRule returns the set of severities that have findings for a rule.
func (s *scanResult) severitiesForRule(ruleID string) map[string]bool {
	out := map[string]bool{}
	for sev, byRule := range s.metadata.Stats.ViolationBreakdowns {
		if byRule[ruleID] > 0 {
			out[sev] = true
		}
	}
	return out
}

// sarifFindings returns the SARIF results for a rule.
func (s *scanResult) sarifFindings(t *testing.T, ruleID string) []sarifResult {
	t.Helper()
	return filterSARIF(parseSARIF(t, s.sarifDir), ruleID, s.nameMap)
}

// sarifLevels returns the distinct SARIF level values for a rule's findings.
func (s *scanResult) sarifLevels(t *testing.T, ruleID string) map[string]bool {
	t.Helper()
	return levelsFor(parseSARIF(t, s.sarifDir), ruleID, s.nameMap)
}

func runV13Scan(t *testing.T, cfg config.IacConfig, scanDirs ...string) scanResult {
	t.Helper()

	// Keep paths relative (like the existing e2e tests), so file.FilePath inside
	// the engine remains relative and matches the relative filter patterns.
	absQueryPaths := make([]string, len(allQueriesPaths))
	for i, qp := range allQueriesPaths {
		abs, err := filepath.Abs(qp)
		require.NoError(t, err)
		absQueryPaths[i] = abs
	}

	outDir := t.TempDir()

	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = scanDirs
	params.OutputPath = outDir
	params.OutputName = "result"
	params.QueriesPath = absQueryPaths
	params.ChangedDefaultQueryPath = true
	params.Platform = scan.ApplyPlatformFilters(
		[]string{"Terraform", "Kubernetes", "CICD"},
		cfg.OnlyPlatforms, cfg.IgnorePlatforms,
	)
	params.Config = cfg
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{
			RepositoryUrl: "test/url",
			CommitSHA:     "deadbeef",
			Branch:        "main",
		},
	}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()

	meta, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)
	return scanResult{metadata: meta, sarifDir: outDir, nameMap: sarifRuleIDMap(t)}
}

// relFixture returns the path relative to test/e2e/ for a path under fixtures/v13.
// Relative paths are required so that file.FilePath inside the engine stays
// relative and can be matched by the filter patterns we put in RuleConfigs.
func relFixture(rel string) string {
	return filepath.Join(fixtureV13, rel)
}

// allFixtureDirs returns relative paths for all three platform fixture dirs.
func allFixtureDirs() []string {
	return []string{
		relFixture("terraform"),
		relFixture("k8s"),
		relFixture(".github"),
	}
}

// -----------------------------------------------------------------------------
// TestV13_Baseline — confirm all rules fire before any v1.3 config
// -----------------------------------------------------------------------------

func TestV13_Baseline(t *testing.T) {
	res := runV13Scan(t, config.IacConfig{}, allFixtureDirs()...)

	assert.True(t, res.ruleHasFindings(ruleTeamTag), "terraform rule should fire")
	assert.True(t, res.ruleHasFindings(rulePrivileged), "k8s rule should fire")
	assert.True(t, res.ruleHasFindings(ruleCicdPinned), "cicd rule should fire")

	t.Logf("Baseline counts  tf=%d  k8s=%d  cicd=%d",
		res.countForRule(ruleTeamTag),
		res.countForRule(rulePrivileged),
		res.countForRule(ruleCicdPinned),
	)
}

// -----------------------------------------------------------------------------
// Per-rule ignore-paths
// -----------------------------------------------------------------------------

func TestV13_RuleConfig_IgnorePaths_DropsMatchingDir(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {IgnorePaths: []string{relFixture("terraform/prod")}},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	// prod/ should not appear in any finding for this rule
	assert.False(t,
		locationsContain(res.sarifFindings(t, ruleTeamTag), "prod"),
		"findings from prod/ should be hard-dropped",
	)
}

func TestV13_RuleConfig_IgnorePaths_KeepsOtherDir(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {IgnorePaths: []string{relFixture("terraform/prod")}},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	// test/ should still have findings
	assert.True(t,
		locationsContain(res.sarifFindings(t, ruleTeamTag), "test"),
		"findings from test/ should survive ignore of prod/",
	)
}

func TestV13_RuleConfig_IgnorePaths_DropAll(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {
				IgnorePaths: []string{
					relFixture("terraform/prod"),
					relFixture("terraform/test"),
				},
			},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	assert.Zero(t, res.countForRule(ruleTeamTag), "all findings should be dropped")
}

func TestV13_RuleConfig_IgnorePaths_OtherRulesUnaffected(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {
				IgnorePaths: []string{
					relFixture("terraform/prod"),
					relFixture("terraform/test"),
				},
			},
		},
	}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.Zero(t, res.countForRule(ruleTeamTag), "tf rule should be fully dropped")
	assert.Positive(t, res.countForRule(rulePrivileged), "k8s rule unaffected")
	assert.Positive(t, res.countForRule(ruleCicdPinned), "cicd rule unaffected")
}

// -----------------------------------------------------------------------------
// Per-rule only-paths
// -----------------------------------------------------------------------------

func TestV13_RuleConfig_OnlyPaths_RestrictsToDir(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {OnlyPaths: []string{relFixture("terraform/prod")}},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))
	findings := res.sarifFindings(t, ruleTeamTag)

	require.NotEmpty(t, findings, "prod/ findings should remain")
	assert.False(t,
		locationsContain(findings, "test"),
		"test/ findings should be dropped by only-paths",
	)
}

func TestV13_RuleConfig_OnlyPaths_DropAll_WhenNothingMatches(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {OnlyPaths: []string{"/no/such/path"}},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	assert.Zero(t, res.countForRule(ruleTeamTag), "no findings expected when only-paths matches nothing")
}

func TestV13_RuleConfig_OnlyPaths_MultipleAllowed(t *testing.T) {
	// both prod/ and test/ are in only-paths → all findings survive
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {
				OnlyPaths: []string{
					relFixture("terraform/prod"),
					relFixture("terraform/test"),
				},
			},
		},
	}
	baseline := runV13Scan(t, config.IacConfig{}, relFixture("terraform"))
	withFilter := runV13Scan(t, cfg, relFixture("terraform"))

	assert.Equal(t, baseline.countForRule(ruleTeamTag), withFilter.countForRule(ruleTeamTag),
		"all dirs in only-paths → same count as no filter")
}

// -----------------------------------------------------------------------------
// ignore-paths takes precedence over only-paths on the same rule
// -----------------------------------------------------------------------------

func TestV13_RuleConfig_IgnorePathsPrecedenceOverOnlyPaths(t *testing.T) {
	prod := relFixture("terraform/prod")
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {
				IgnorePaths: []string{prod},
				OnlyPaths:   []string{prod},
			},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	assert.False(t,
		locationsContain(res.sarifFindings(t, ruleTeamTag), "prod"),
		"ignore-paths should take precedence over only-paths",
	)
}

// -----------------------------------------------------------------------------
// Per-rule severity override
// -----------------------------------------------------------------------------

func TestV13_RuleConfig_SeverityOverride_DefaultIsHigh(t *testing.T) {
	// Confirm baseline severity before overriding
	res := runV13Scan(t, config.IacConfig{}, relFixture("k8s"))
	sevs := res.severitiesForRule(rulePrivileged)
	assert.True(t, sevs["HIGH"], "baseline k8s rule severity should be HIGH, got: %v", sevs)
}

func TestV13_RuleConfig_SeverityOverride_ToLow(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			rulePrivileged: {Severity: strPtr("low")},
		},
	}
	res := runV13Scan(t, cfg, relFixture("k8s"))
	sevs := res.severitiesForRule(rulePrivileged)

	assert.True(t, sevs["LOW"], "severity should be overridden to LOW: %v", sevs)
	assert.False(t, sevs["HIGH"], "original HIGH should not appear: %v", sevs)
}

func TestV13_RuleConfig_SeverityOverride_AllLevels(t *testing.T) {
	for _, level := range []string{"critical", "high", "medium", "low", "info"} {
		level := level
		t.Run(level, func(t *testing.T) {
			cfg := config.IacConfig{
				RuleConfigs: map[string]config.IacRuleConfig{
					ruleTeamTag: {Severity: strPtr(level)},
				},
			}
			res := runV13Scan(t, cfg, relFixture("terraform"))
			sevs := res.severitiesForRule(ruleTeamTag)
			require.NotEmpty(t, sevs, "should have findings for rule")
			assert.True(t, sevs[strings.ToUpper(level)], "expected %s in severities, got: %v", strings.ToUpper(level), sevs)
		})
	}
}

func TestV13_RuleConfig_SeverityOverride_DoesNotChangeCount(t *testing.T) {
	baseline := runV13Scan(t, config.IacConfig{}, relFixture("terraform"))
	baseCount := baseline.countForRule(ruleTeamTag)

	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {Severity: strPtr("medium")},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	assert.Equal(t, baseCount, res.countForRule(ruleTeamTag), "severity override must not change finding count")
}

func TestV13_RuleConfig_SeverityOverride_DoesNotAffectOtherRules(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {Severity: strPtr("critical")},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"), relFixture("k8s"))

	tfSevs := res.severitiesForRule(ruleTeamTag)
	assert.True(t, tfSevs["CRITICAL"], "terraform rule should be CRITICAL: %v", tfSevs)

	k8sSevs := res.severitiesForRule(rulePrivileged)
	assert.True(t, k8sSevs["HIGH"], "k8s rule should remain HIGH: %v", k8sSevs)
}

// Verify the SARIF level reflects the overridden severity.
func TestV13_RuleConfig_SeverityOverride_SARIFLevel(t *testing.T) {
	for sev, wantLevel := range sarifmodel.SeverityLevelEquivalence {
		sev, wantLevel := sev, wantLevel
		t.Run(string(sev), func(t *testing.T) {
			cfg := config.IacConfig{
				RuleConfigs: map[string]config.IacRuleConfig{
					rulePrivileged: {Severity: strPtr(strings.ToLower(string(sev)))},
				},
			}
			res := runV13Scan(t, cfg, relFixture("k8s"))
			levels := res.sarifLevels(t, rulePrivileged)
			assert.True(t, levels[wantLevel],
				"severity %s should map to SARIF level %q, got: %v", sev, wantLevel, levels)
		})
	}
}

// -----------------------------------------------------------------------------
// Severity + ignore-paths combined on the same rule
// -----------------------------------------------------------------------------

func TestV13_RuleConfig_SeverityAndIgnorePaths_Combined(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {
				IgnorePaths: []string{relFixture("terraform/prod")},
				Severity:    strPtr("info"),
			},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))
	findings := res.sarifFindings(t, ruleTeamTag)

	require.NotEmpty(t, findings, "test/ findings should survive")
	assert.False(t, locationsContain(findings, "prod"), "prod/ must be dropped")

	// All surviving findings must be at INFO level (overridden from LOW)
	sevs := res.severitiesForRule(ruleTeamTag)
	assert.True(t, sevs["INFO"], "surviving findings should be INFO: %v", sevs)
	assert.False(t, sevs["LOW"], "original LOW severity should no longer appear: %v", sevs)
}

// -----------------------------------------------------------------------------
// Global platform filters — only-platforms
// -----------------------------------------------------------------------------

func TestV13_OnlyPlatforms_SinglePlatform_Terraform(t *testing.T) {
	cfg := config.IacConfig{OnlyPlatforms: []string{"Terraform"}}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.True(t, res.ruleHasFindings(ruleTeamTag), "Terraform rule should fire")
	assert.False(t, res.ruleHasFindings(rulePrivileged), "Kubernetes rule should not fire")
	assert.False(t, res.ruleHasFindings(ruleCicdPinned), "CICD rule should not fire")
}

func TestV13_OnlyPlatforms_SinglePlatform_Kubernetes(t *testing.T) {
	cfg := config.IacConfig{OnlyPlatforms: []string{"Kubernetes"}}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.False(t, res.ruleHasFindings(ruleTeamTag))
	assert.True(t, res.ruleHasFindings(rulePrivileged))
	assert.False(t, res.ruleHasFindings(ruleCicdPinned))
}

func TestV13_OnlyPlatforms_MultiPlatform(t *testing.T) {
	cfg := config.IacConfig{OnlyPlatforms: []string{"Terraform", "Kubernetes"}}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.True(t, res.ruleHasFindings(ruleTeamTag))
	assert.True(t, res.ruleHasFindings(rulePrivileged))
	assert.False(t, res.ruleHasFindings(ruleCicdPinned), "CICD excluded by only-platforms")
}

func TestV13_OnlyPlatforms_AllPlatforms_EquivalentToNoFilter(t *testing.T) {
	baseline := runV13Scan(t, config.IacConfig{}, allFixtureDirs()...)

	cfg := config.IacConfig{OnlyPlatforms: []string{"Terraform", "Kubernetes", "CICD"}}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.Equal(t, baseline.countForRule(ruleTeamTag), res.countForRule(ruleTeamTag))
	assert.Equal(t, baseline.countForRule(rulePrivileged), res.countForRule(rulePrivileged))
	assert.Equal(t, baseline.countForRule(ruleCicdPinned), res.countForRule(ruleCicdPinned))
}

// -----------------------------------------------------------------------------
// Global platform filters — ignore-platforms
// -----------------------------------------------------------------------------

func TestV13_IgnorePlatforms_ExcludeKubernetes(t *testing.T) {
	cfg := config.IacConfig{IgnorePlatforms: []string{"Kubernetes"}}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.True(t, res.ruleHasFindings(ruleTeamTag))
	assert.False(t, res.ruleHasFindings(rulePrivileged), "Kubernetes excluded")
	assert.True(t, res.ruleHasFindings(ruleCicdPinned))
}

func TestV13_IgnorePlatforms_ExcludeMultiple(t *testing.T) {
	cfg := config.IacConfig{IgnorePlatforms: []string{"Kubernetes", "CICD"}}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.True(t, res.ruleHasFindings(ruleTeamTag))
	assert.False(t, res.ruleHasFindings(rulePrivileged))
	assert.False(t, res.ruleHasFindings(ruleCicdPinned))
}

func TestV13_IgnorePlatforms_ExcludeAll_NoFindings(t *testing.T) {
	cfg := config.IacConfig{IgnorePlatforms: []string{"Terraform", "Kubernetes", "CICD"}}
	res := runV13Scan(t, cfg, allFixtureDirs()...)

	assert.Zero(t, res.metadata.Stats.Violations, "no violations when all platforms excluded")
}

// -----------------------------------------------------------------------------
// Platform filter + rule config combined
// -----------------------------------------------------------------------------

func TestV13_PlatformFilter_And_RuleConfig_Combined(t *testing.T) {
	cfg := config.IacConfig{
		OnlyPlatforms: []string{"Terraform"},
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTag: {
				IgnorePaths: []string{relFixture("terraform/prod")},
				Severity:    strPtr("medium"),
			},
		},
	}
	res := runV13Scan(t, cfg, allFixtureDirs()...)
	findings := res.sarifFindings(t, ruleTeamTag)

	// Platform filter: k8s and cicd not running
	assert.False(t, res.ruleHasFindings(rulePrivileged))
	assert.False(t, res.ruleHasFindings(ruleCicdPinned))

	// Rule config: prod/ dropped, test/ survives at MEDIUM
	require.NotEmpty(t, findings, "test/ terraform findings should remain")
	assert.False(t, locationsContain(findings, "prod"), "prod/ dropped by ignore-paths")
	sevs := res.severitiesForRule(ruleTeamTag)
	assert.True(t, sevs["MEDIUM"], "severity should be MEDIUM: %v", sevs)
}

// -----------------------------------------------------------------------------
// k8s production vs staging path filtering
// -----------------------------------------------------------------------------

func TestV13_K8s_OnlyProductionPath(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			rulePrivileged: {OnlyPaths: []string{relFixture("k8s/production")}},
		},
	}
	res := runV13Scan(t, cfg, relFixture("k8s"))
	findings := res.sarifFindings(t, rulePrivileged)

	require.NotEmpty(t, findings, "production finding expected")
	assert.True(t, locationsContain(findings, "production"), "production should have findings")
	assert.False(t, locationsContain(findings, "staging"), "staging should be dropped by only-paths")
}

func TestV13_K8s_IgnoreProductionPath(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			rulePrivileged: {IgnorePaths: []string{relFixture("k8s/production")}},
		},
	}
	res := runV13Scan(t, cfg, relFixture("k8s"))
	findings := res.sarifFindings(t, rulePrivileged)

	require.NotEmpty(t, findings, "staging finding should survive")
	assert.False(t, locationsContain(findings, "production"), "production dropped by ignore-paths")
	assert.True(t, locationsContain(findings, "staging"), "staging survives")
}

// -----------------------------------------------------------------------------
// Legacy rule ID matching
// -----------------------------------------------------------------------------

func TestV13_RuleConfig_MatchByLegacyID(t *testing.T) {
	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			ruleTeamTagLegacyID: {
				IgnorePaths: []string{
					relFixture("terraform/prod"),
					relFixture("terraform/test"),
				},
			},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	assert.Zero(t, res.countForRule(ruleTeamTag), "legacy ID should match and drop all findings")
}

// -----------------------------------------------------------------------------
// Edge case: empty RuleConfigs has no effect
// -----------------------------------------------------------------------------

func TestV13_EmptyRuleConfigs_NoEffect(t *testing.T) {
	baseline := runV13Scan(t, config.IacConfig{}, relFixture("terraform"))

	cfg := config.IacConfig{RuleConfigs: map[string]config.IacRuleConfig{}}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	assert.Equal(t, baseline.countForRule(ruleTeamTag), res.countForRule(ruleTeamTag),
		"empty rule-configs should be a no-op")
}

// -----------------------------------------------------------------------------
// Edge case: rule config for non-matching rule ID has no effect
// -----------------------------------------------------------------------------

func TestV13_RuleConfig_UnknownRuleID_NoEffect(t *testing.T) {
	baseline := runV13Scan(t, config.IacConfig{}, relFixture("terraform"))

	cfg := config.IacConfig{
		RuleConfigs: map[string]config.IacRuleConfig{
			"this-rule-does-not-exist": {
				IgnorePaths: []string{relFixture("terraform/prod")},
				Severity:    strPtr("critical"),
			},
		},
	}
	res := runV13Scan(t, cfg, relFixture("terraform"))

	assert.Equal(t, baseline.countForRule(ruleTeamTag), res.countForRule(ruleTeamTag),
		"config for unknown rule ID should have no effect on other rules")
}
