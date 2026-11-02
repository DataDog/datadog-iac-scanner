package test

import (
	"context"
	"encoding/json"
	"os"
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

func Test_E2ETofuScannedAsTerraform(t *testing.T) {
	queriesPaths := []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform"))}

	stats := runScan(t, filepath.Join("fixtures", "positive.tofu"), queriesPaths)

	require.Equal(t, 1, stats.Files, "the .tofu fixture must be scanned")
	require.NotEmpty(t, stats.ViolationBreakdowns, "no violations on the .tofu fixture: check queriesPaths")
	fired := false
	for _, slugs := range stats.ViolationBreakdowns {
		if _, ok := slugs["terraform-aws-team-tag-not-present"]; ok {
			fired = true
		}
	}
	require.True(t, fired, "terraform-aws-team-tag-not-present must fire on a .tofu file")
}

func Test_E2EJSONConfigScannedAsTerraform(t *testing.T) {
	queriesPaths := []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform"))}

	for _, fixture := range []string{
		filepath.Join("fixtures", "positive.tf.json"),
		filepath.Join("fixtures", "positive.tofu.json"),
	} {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			stats := runScan(t, fixture, queriesPaths)
			require.Equal(t, 1, stats.Files, "%s must be scanned", fixture)
			require.NotEmpty(t, stats.ViolationBreakdowns, "no violations on %s: check queriesPaths", fixture)
			fired := false
			for _, slugs := range stats.ViolationBreakdowns {
				if _, ok := slugs["terraform-aws-team-tag-not-present"]; ok {
					fired = true
				}
			}
			require.True(t, fired, "terraform-aws-team-tag-not-present must fire on %s", fixture)
		})
	}
}

// Test_E2ETerraformPlanFlag verifies that:
// 1. Terraform plan JSON files are scanned when the flag is enabled
// 2. CloudFormation JSON files are NOT scanned (even though they are JSON)
// 3. The flag correctly gates the JSON parser registration
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

	t.Run("cloudformation json not scanned even with flag enabled", func(t *testing.T) {
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

		// CloudFormation JSON files should NOT be processed because the JSON parser
		// is gated to only process Terraform JSON files
		require.Equal(t, 0, metadata.Stats.Files, "CloudFormation JSON should not be scanned (JSON parser only processes Terraform)")
	})

	t.Run("both files in same scan - only tfplan scanned", func(t *testing.T) {
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

		// Should only process the Terraform plan JSON, not the CloudFormation JSON
		// The CloudFormation JSON file is filtered out by the analyzer because
		// it's a JSON file but not a Terraform plan
		require.Equal(t, 1, metadata.Stats.Files, "Should scan exactly 1 file (tfplan.json), CloudFormation JSON excluded")
	})
}

func scanFindingLines(t *testing.T, path string) map[int]bool {
	t.Helper()
	outDir := t.TempDir()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{path}
	params.OutputPath = outDir
	params.OutputName = "result"
	params.QueriesPath = []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform"))}
	params.ChangedDefaultQueryPath = true
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
	}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	_, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(outDir, "result.sarif"))
	require.NoError(t, err)
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))

	lines := map[int]bool{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			for _, l := range r.Locations {
				lines[l.PhysicalLocation.Region.StartLine] = true
			}
		}
	}
	return lines
}

func Test_E2ETerraformZeroCountBlocksProduceNoFindings(t *testing.T) {
	const enabledLine, zeroLine, disabledLine, unknownLine, localFlagLine, emptyForEachLine, tfvarsLine = 8, 13, 18, 23, 32, 37, 44
	for name, path := range map[string]string{
		"absolute path": mustAbs(t, filepath.Join("fixtures", "zero-count")),
		"relative path": filepath.Join("fixtures", "zero-count"),
	} {
		t.Run(name, func(t *testing.T) {
			lines := scanFindingLines(t, path)
			require.True(t, lines[enabledLine], "the enabled bucket must produce a finding: %v", lines)
			require.True(t, lines[unknownLine], "the bucket with an unknown count must produce a finding: %v", lines)
			require.False(t, lines[zeroLine], "count = 0 must produce no finding: %v", lines)
			require.False(t, lines[disabledLine], "a count that evaluates to 0 must produce no finding: %v", lines)
			require.False(t, lines[localFlagLine], "a count read through a local that evaluates to 0 must produce no finding: %v", lines)
			require.False(t, lines[emptyForEachLine], "an empty for_each must produce no finding: %v", lines)
			require.False(t, lines[tfvarsLine], "a count set to 0 by terraform.tfvars must produce no finding: %v", lines)
		})
	}

	const jsonEnabledLine, jsonZeroLine, jsonFromVarLine = 9, 12, 16
	jsonLines := scanFindingLines(t, filepath.Join("fixtures", "zero-count-json"))
	require.True(t, jsonLines[jsonEnabledLine], "the enabled .tf.json bucket must produce a finding: %v", jsonLines)
	require.False(t, jsonLines[jsonZeroLine], "count = 0 in .tf.json must produce no finding: %v", jsonLines)
	require.False(t, jsonLines[jsonFromVarLine], "a .tf.json count that evaluates to 0 must produce no finding: %v", jsonLines)

	failedRoot := t.TempDir()
	failedRootFile := filepath.Join(failedRoot, "main.tf")
	require.NoError(t, os.WriteFile(failedRootFile, []byte("resource \"aws_s3_bucket\" \"zero\" {\n  count  = 0\n  bucket = \"zero\"\n}\n"), 0o600))
	require.NoError(t, os.Chmod(failedRoot, 0o300))
	t.Cleanup(func() { require.NoError(t, os.Chmod(failedRoot, 0o700)) })
	const failedRootZeroLine = 3
	lines := scanFindingLines(t, failedRootFile)
	require.True(t, lines[failedRootZeroLine], "count = 0 in a root that fails to evaluate is scanned as written: %v", lines)
}

func Test_E2ETerraformSharedModuleRootRouting(t *testing.T) {
	scanRoutingRule := func(t *testing.T, ruleDir string) []string {
		t.Helper()
		outDir := t.TempDir()
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		repo := mustAbs(t, filepath.Join("fixtures", "root-routing"))
		params.Path = []string{repo}
		params.RepoPath = repo
		params.OutputPath = outDir
		params.OutputName = "result"
		params.QueriesPath = []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform_root_routing", ruleDir))}
		params.ChangedDefaultQueryPath = true
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		_, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		data, err := os.ReadFile(filepath.Join(outDir, "result.sarif"))
		require.NoError(t, err)
		var doc struct {
			Runs []struct {
				Results []struct {
					Properties map[string]interface{} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		require.NoError(t, json.Unmarshal(data, &doc))
		var roots []string
		for _, run := range doc.Runs {
			for _, r := range run.Results {
				root, _ := r.Properties["root_module"].(string)
				roots = append(roots, root)
			}
		}
		return roots
	}

	t.Run("restricted rule reports only the violating root", func(t *testing.T) {
		require.Equal(t, []string{"envs/b"}, scanRoutingRule(t, "versioning_by_root"))
	})

	t.Run("unrestricted rule reports every root", func(t *testing.T) {
		require.ElementsMatch(t, []string{"envs/a", "envs/b"}, scanRoutingRule(t, "versioning_any_root"))
	})
}

func Test_E2ETerraformExpandedRootSiblingFingerprint(t *testing.T) {
	outDir := t.TempDir()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	repo := mustAbs(t, filepath.Join("fixtures", "expanded-root-sibling"))
	params.Path = []string{repo}
	params.RepoPath = repo
	params.OutputPath = outDir
	params.OutputName = "result"
	params.QueriesPath = []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform_root_routing", "versioning_any_root"))}
	params.ChangedDefaultQueryPath = true
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
	}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	_, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(outDir, "result.sarif"))
	require.NoError(t, err)
	var doc struct {
		Runs []struct {
			Results []struct {
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
				PartialFingerprints struct {
					DatadogFingerprint string `json:"DATADOG_FINGERPRINT"`
				} `json:"partialFingerprints"`
				Properties map[string]interface{} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))

	type finding struct {
		Fingerprint, ResourceID, URI string
		Line                         int
	}
	var findings []finding
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			require.Len(t, r.Locations, 1)
			id, _ := r.Properties["resource_id"].(string)
			loc := r.Locations[0].PhysicalLocation
			findings = append(findings, finding{r.PartialFingerprints.DatadogFingerprint, id, loc.ArtifactLocation.URI, loc.Region.StartLine})
		}
	}
	require.ElementsMatch(t, []finding{
		{"ff3c1d71b5ae18ee3cd4f3bc175ca0670fd225a6eee80dd6a7fe498e1ba0de0f", "aws_s3_bucket.plain", "main.tf", 2},
		{"fe9c590fc2a281afd796d5f191a66b90227b55dc3b63abc1f6fc17bf2ec73c0e", `aws_s3_bucket.each["a"]`, "main.tf", 7},
		{"7408bbbd7649b3b4c43159c51d721356e87143ef5f5a3168b21b90959e641a1e", `aws_s3_bucket.each["b"]`, "main.tf", 7},
	}, findings)
}

func Test_E2ETerraformUnknownMeta(t *testing.T) {
	type finding struct {
		Resource string
		Message  string
		Line     int
	}
	scanUnknownMeta := func(t *testing.T, fixture string) []finding {
		t.Helper()
		outDir := t.TempDir()
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		repo := mustAbs(t, filepath.Join("fixtures", "unknown-meta", fixture))
		params.Path = []string{repo}
		params.RepoPath = repo
		params.OutputPath = outDir
		params.OutputName = "result"
		params.QueriesPath = []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform_unknown_meta"))}
		params.ChangedDefaultQueryPath = true
		params.ShouldScanTfPlans = true
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		_, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		data, err := os.ReadFile(filepath.Join(outDir, "result.sarif"))
		require.NoError(t, err)
		var doc struct {
			Runs []struct {
				Results []struct {
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
					Locations []struct {
						PhysicalLocation struct {
							Region struct {
								StartLine int `json:"startLine"`
							} `json:"region"`
						} `json:"physicalLocation"`
					} `json:"locations"`
					Properties map[string]interface{} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		require.NoError(t, json.Unmarshal(data, &doc))
		var findings []finding
		for _, run := range doc.Runs {
			for _, r := range run.Results {
				require.Len(t, r.Locations, 1)
				id, _ := r.Properties["resource_id"].(string)
				findings = append(findings, finding{Resource: id, Message: r.Message.Text, Line: r.Locations[0].PhysicalLocation.Region.StartLine})
			}
		}
		return findings
	}

	const sourceAmiLine, sourceControlLine, planValuesLineOfA, planControlLine = 6, 15, 13, 36
	require.ElementsMatch(t, []finding{
		{Resource: "aws_instance.a", Message: "Instance unknown meta", Line: sourceAmiLine},
		{Resource: "aws_instance.c", Message: "Instance unknown meta", Line: sourceControlLine},
	}, scanUnknownMeta(t, "source"))
	require.ElementsMatch(t, []finding{
		{Resource: "aws_instance.a", Message: "Instance unknown meta", Line: planValuesLineOfA},
		{Resource: "aws_instance.c", Message: "Instance unknown meta", Line: planControlLine},
	}, scanUnknownMeta(t, "plan"))
}

func Test_E2ETerraformPlainRootEvaluatedValues(t *testing.T) {
	type finding struct {
		Resource string
		Line     int
	}
	scanPlainRoot := func(t *testing.T, fixture string) []finding {
		t.Helper()
		outDir := t.TempDir()
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		repo := mustAbs(t, filepath.Join("fixtures", "plain-root-values", fixture))
		params.Path = []string{repo}
		params.RepoPath = repo
		params.OutputPath = outDir
		params.OutputName = "result"
		params.QueriesPath = []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform_plain_root_values"))}
		params.ChangedDefaultQueryPath = true
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		_, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		data, err := os.ReadFile(filepath.Join(outDir, "result.sarif"))
		require.NoError(t, err)
		var doc struct {
			Runs []struct {
				Results []struct {
					Locations []struct {
						PhysicalLocation struct {
							Region struct {
								StartLine int `json:"startLine"`
							} `json:"region"`
						} `json:"physicalLocation"`
					} `json:"locations"`
					Properties map[string]interface{} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		require.NoError(t, json.Unmarshal(data, &doc))
		var findings []finding
		for _, run := range doc.Runs {
			for _, r := range run.Results {
				require.Len(t, r.Locations, 1)
				id, _ := r.Properties["resource_id"].(string)
				findings = append(findings, finding{Resource: id, Line: r.Locations[0].PhysicalLocation.Region.StartLine})
			}
		}
		return findings
	}

	const aclLine = 5
	want := []finding{{Resource: "aws_s3_bucket.b", Line: aclLine}}

	t.Run("directive file values reach the rule", func(t *testing.T) {
		require.Equal(t, want, scanPlainRoot(t, "directive"))
	})
	t.Run("directive overrides auto-loaded tfvars", func(t *testing.T) {
		require.Equal(t, want, scanPlainRoot(t, "directive-overrides-autoloaded"))
	})
	t.Run("negative control: non-matching directive value reports nothing", func(t *testing.T) {
		require.Empty(t, scanPlainRoot(t, "private-control"))
	})
}

func Test_E2ETerraformReferencesJoinAcrossModuleCalls(t *testing.T) {
	scan1 := func(t *testing.T) map[string][]string {
		t.Helper()
		outDir := t.TempDir()
		params, ctx := scan.GetDefaultParameters(context.Background(), "")
		repo := mustAbs(t, filepath.Join("fixtures", "references-join"))
		params.Path = []string{repo}
		params.RepoPath = repo
		params.OutputPath = outDir
		params.OutputName = "result"
		params.QueriesPath = []string{mustAbs(t, filepath.Join("testdata", "rules", "terraform_references_join"))}
		params.ChangedDefaultQueryPath = true
		params.SCIInfo = model.SCIInfo{
			DiffAware:            model.DiffAware{Enabled: false},
			RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
		}
		params.FlagEvaluator = featureflags.NewLocalEvaluator()
		_, err := console.ExecuteScan(ctx, params)
		require.NoError(t, err)

		data, err := os.ReadFile(filepath.Join(outDir, "result.sarif"))
		require.NoError(t, err)
		var doc struct {
			Runs []struct {
				Results []struct {
					Properties map[string]interface{} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		require.NoError(t, json.Unmarshal(data, &doc))
		byRoot := map[string][]string{}
		for _, run := range doc.Runs {
			for _, r := range run.Results {
				root, _ := r.Properties["root_module"].(string)
				id, _ := r.Properties["resource_id"].(string)
				byRoot[root] = append(byRoot[root], id)
			}
		}
		return byRoot
	}

	byRoot := scan1(t)
	require.ElementsMatch(t, []string{"module.a.aws_subnet.s[2]", "module.b.aws_subnet.s[1]", "module.b.aws_subnet.s[2]"}, byRoot["envs/main"], "%v", byRoot)
	require.Empty(t, byRoot["envs/unset"], "a root whose association reads an unset variable is uncertain: %v", byRoot)
	require.Len(t, byRoot, 1, "%v", byRoot)
}
