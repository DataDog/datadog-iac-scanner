package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
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

type kustomizeFinding struct {
	file, root string
	line       int
	suppressed bool
}

// scanKustomize scans files written to a temporary tree (a value starting with
// "symlink:" is written as a symlink to the rest of it) and returns the
// privileged-container findings and the raw SARIF.
func scanKustomizePlatform(t *testing.T, files map[string]string, enable bool, platform string,
	rules ...string) ([]kustomizeFinding, string) {
	findings, raw := scanKustomizeRestricted(t, files, enable, func(params *scan.Parameters) {
		params.Platform = []string{platform}
	}, rules...)
	return findings, raw
}

func scanKustomize(t *testing.T, files map[string]string, enable bool, rules ...string) ([]kustomizeFinding, string) {
	return scanKustomizeRestricted(t, files, enable, nil, rules...)
}

func scanKustomizeRestricted(t *testing.T, files map[string]string, enable bool,
	configure func(params *scan.Parameters), rules ...string) ([]kustomizeFinding, string) {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		// A "symlink:" value makes the file a symlink to the rest of it.
		if target, ok := strings.CutPrefix(c, "symlink:"); ok {
			if err := os.Symlink(filepath.FromSlash(target), full); err != nil {
				t.Skipf("symlinks unsupported: %v", err)
			}
			continue
		}
		require.NoError(t, os.WriteFile(full, []byte(c), 0o600))
	}
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{dir}
	params.RepoPath = dir
	params.OutputPath = t.TempDir()
	if len(rules) == 0 {
		rules = []string{"k8s"}
	}
	params.QueriesPath = nil
	for _, r := range rules {
		params.QueriesPath = append(params.QueriesPath, mustAbs(t, filepath.Join("testdata", "rules", r)))
	}
	params.ChangedDefaultQueryPath = true
	params.EnableKustomize = enable
	if configure != nil {
		configure(params)
	}
	params.SCIInfo = model.SCIInfo{RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url"}}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	_, err := console.ExecuteScan(ctx, params)
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(params.OutputPath, "kics-result.sarif"))
	require.NoError(t, err)
	var sarif struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
						Region           struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Suppressions []json.RawMessage `json:"suppressions"`
				Properties   struct {
					Kustomize struct {
						RenderRoot string `json:"render_root"`
					} `json:"kustomize"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(raw, &sarif))
	var out []kustomizeFinding
	for _, r := range sarif.Runs[0].Results {
		loc := r.Locations[0].PhysicalLocation
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(loc.ArtifactLocation.URI)))
		require.NoError(t, err)
		require.True(t, loc.Region.StartLine >= 1 && loc.Region.StartLine <= strings.Count(string(content), "\n")+1,
			"line %d outside %s", loc.Region.StartLine, loc.ArtifactLocation.URI)
		out = append(out, kustomizeFinding{loc.ArtifactLocation.URI, r.Properties.Kustomize.RenderRoot,
			loc.Region.StartLine, len(r.Suppressions) > 0})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file+out[i].root < out[j].file+out[j].root })
	return out, string(raw)
}

const privilegedDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx
          securityContext:
            privileged: true
`

func Test_E2EKustomize(t *testing.T) {
	tree := func(extra map[string]string) map[string]string {
		files := map[string]string{
			"base/kustomization.yaml":         "resources:\n  - deployment.yaml\n",
			"base/deployment.yaml":            privilegedDeployment,
			"overlays/dev/kustomization.yaml": "namePrefix: dev-\nnamespace: dev\nresources:\n  - ../../base\n",
			"overlays/prod/kustomization.yaml": "namespace: prod\nresources:\n  - ../../base\n" +
				"secretGenerator:\n  - name: creds\n    literals:\n      - PASSWORD=canary-e2e-literal\n",
		}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}

	t.Run("one finding per overlay on the base line", func(t *testing.T) {
		got, raw := scanKustomize(t, tree(nil), true)
		require.Equal(t, []kustomizeFinding{
			{"base/deployment.yaml", "overlays/dev", 12, false}, {"base/deployment.yaml", "overlays/prod", 12, false},
		}, got)
		require.NotContains(t, raw, "canary-e2e-literal")
		require.NotContains(t, raw, "Y2FuYXJ5LWUyZS1saXRlcmFs") // base64 of the canary
	})

	t.Run("a patch fixing prod leaves dev", func(t *testing.T) {
		got, _ := scanKustomize(t, tree(map[string]string{
			"overlays/prod/kustomization.yaml": "resources:\n  - ../../base\npatches:\n  - path: fix.yaml\n",
			"overlays/prod/fix.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n" +
				"    spec:\n      containers:\n        - name: web\n          securityContext:\n            privileged: false\n",
		}), true)
		require.Equal(t, []kustomizeFinding{{"base/deployment.yaml", "overlays/dev", 12, false}}, got)
	})

	t.Run("a remote base falls back to the raw scan", func(t *testing.T) {
		got, _ := scanKustomize(t, map[string]string{
			"app/kustomization.yaml": "resources:\n  - deployment.yaml\n  - https://example.invalid/base.yaml\n",
			"app/deployment.yaml":    privilegedDeployment,
		}, true)
		require.Equal(t, []kustomizeFinding{{"app/deployment.yaml", "", 12, false}}, got)
	})

	for name, prod := range map[string]string{
		"refused by the planner": "resources:\n  - ../../base\n  - https://example.invalid/extra.yaml\n",
		"failing to render":      "resources:\n  - ../../base\n  - missing.yaml\n",
	} {
		t.Run("a root "+name+" keeps its shared base scanned as written", func(t *testing.T) {
			got, _ := scanKustomize(t, tree(map[string]string{"overlays/prod/kustomization.yaml": prod}), true)
			require.Equal(t, []kustomizeFinding{
				{"base/deployment.yaml", "", 12, false}, {"base/deployment.yaml", "overlays/dev", 12, false},
			}, got)
		})
	}

	t.Run("a failed root keeps a manifest it lists outside its directories scanned as written", func(t *testing.T) {
		got, _ := scanKustomize(t, tree(map[string]string{
			"base/kustomization.yaml":          "resources:\n  - deployment.yaml\n  - ../shared/side.yaml\n",
			"shared/side.yaml":                 strings.Replace(privilegedDeployment, "name: web\nspec", "name: side\nspec", 1),
			"overlays/prod/kustomization.yaml": "resources:\n  - ../../base\n  - missing.yaml\n",
		}), true)
		require.Equal(t, []kustomizeFinding{
			{"base/deployment.yaml", "", 12, false}, {"base/deployment.yaml", "overlays/dev", 12, false},
			{"shared/side.yaml", "", 12, false}, {"shared/side.yaml", "overlays/dev", 12, false},
		}, got)
	})

	t.Run("a failed root keeps a manifest it reaches through a symlink scanned as written", func(t *testing.T) {
		got, _ := scanKustomize(t, map[string]string{
			"shared/deployment.yaml":           privilegedDeployment,
			"overlays/dev/kustomization.yaml":  "resources:\n  - ../../shared/deployment.yaml\n",
			"overlays/prod/kustomization.yaml": "resources:\n  - link.yaml\n  - missing.yaml\n",
			"overlays/prod/link.yaml":          "symlink:../../shared/deployment.yaml",
		}, true)
		require.Contains(t, got, kustomizeFinding{"shared/deployment.yaml", "", 12, false})
	})

	t.Run("a failed root keeps a manifest of a base it reaches through a symlinked directory scanned as written",
		func(t *testing.T) {
			got, _ := scanKustomize(t, map[string]string{
				"base/kustomization.yaml":          "resources:\n  - ../shared/deployment.yaml\n",
				"shared/deployment.yaml":           privilegedDeployment,
				"overlays/dev/kustomization.yaml":  "resources:\n  - ../../base\n",
				"overlays/prod/kustomization.yaml": "resources:\n  - alias\n  - missing.yaml\n",
				"overlays/prod/alias":              "symlink:../../base",
			}, true)
			require.Contains(t, got, kustomizeFinding{"shared/deployment.yaml", "", 12, false})
		})

	t.Run("same-kind resources of one file report their own lines", func(t *testing.T) {
		dep := func(name, privileged string) string {
			return strings.NewReplacer("name: web\n", "name: "+name+"\n", "privileged: true", "privileged: "+privileged).
				Replace(privilegedDeployment)
		}
		// Empty and comment-only documents separate the resources: the YAML
		// parser skips them when it indexes documents.
		base := dep("one", "true") + "---\n# a comment\n---\n---\n" + dep("two", "false") + "---\n" + dep("three", "true")
		lines := func(files map[string]string) []string {
			_, raw := scanKustomize(t, files, true)
			var sarif struct {
				Runs []struct {
					Results []struct {
						Locations []struct {
							PhysicalLocation struct {
								ArtifactLocation struct{ URI string }    `json:"artifactLocation"`
								Region           struct{ StartLine int } `json:"region"`
							} `json:"physicalLocation"`
						} `json:"locations"`
					} `json:"results"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal([]byte(raw), &sarif))
			var out []string
			for _, r := range sarif.Runs[0].Results {
				l := r.Locations[0].PhysicalLocation
				out = append(out, fmt.Sprintf("%s:%d", l.ArtifactLocation.URI, l.Region.StartLine))
			}
			sort.Strings(out)
			return out
		}
		files := map[string]string{
			"base/kustomization.yaml":    "namespace: team\nresources:\n  - app.yaml\n",
			"base/app.yaml":              base,
			"overlay/kustomization.yaml": "namespace: team\nresources:\n  - ../base\n",
		}
		require.Equal(t, []string{"base/app.yaml:12", "base/app.yaml:41"}, lines(files))

		files["base/app.yaml"] = strings.Replace(base, dep("two", "false"), dep("two", "true"), 1)
		require.Equal(t, []string{"base/app.yaml:12", "base/app.yaml:28", "base/app.yaml:41"}, lines(files))

		files["base/app.yaml"] = base
		files["overlay/kustomization.yaml"] += "patches:\n  - path: fix.yaml\n"
		// The patch file holds an empty and a comment-only document before
		// the patches, which the patch document index must skip too.
		patch := func(name string) string {
			return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: " + name + "\nspec:\n  template:\n" +
				"    spec:\n      containers:\n        - name: web\n          securityContext:\n            privileged: true\n"
		}
		files["overlay/fix.yaml"] = "---\n# a comment\n---\n" + patch("one") + "---\n" + patch("two") + "---\n" + patch("three")
		require.Equal(t, []string{"overlay/fix.yaml:14", "overlay/fix.yaml:26", "overlay/fix.yaml:38"}, lines(files))
	})

	t.Run("flag off scans files as written", func(t *testing.T) {
		got, _ := scanKustomize(t, tree(nil), false)
		require.Equal(t, []kustomizeFinding{{"base/deployment.yaml", "", 12, false}}, got)
	})

	safeBase := strings.Replace(privilegedDeployment, "privileged: true", "privileged: false", 1)
	patch := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n" +
		"      containers:\n        - name: web\n          securityContext:\n%s            privileged: true\n"
	t.Run("a field set by an overlay patch lands on the patch", func(t *testing.T) {
		for name, files := range map[string]map[string]string{
			"strategic merge file": {"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\npatches:\n  - path: p.yaml\n",
				"overlays/dev/p.yaml": fmt.Sprintf(patch, "")},
			"inline": {"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\npatches:\n  - patch: |-\n" +
				indent(fmt.Sprintf(patch, ""), "      ")},
			"added field": {"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\npatches:\n  - path: p.yaml\n",
				"overlays/dev/p.yaml": fmt.Sprintf(patch, ""), "base/deployment.yaml": strings.Replace(privilegedDeployment,
					"          securityContext:\n            privileged: true\n", "", 1)},
			"json 6902": {"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\npatches:\n  - path: p.yaml\n" +
				"    target: {kind: Deployment, name: web}\n",
				"overlays/dev/p.yaml": "- op: replace\n  path: /spec/template/spec/containers/0/securityContext/privileged\n  value: true\n"},
		} {
			files["base/kustomization.yaml"] = "resources:\n  - deployment.yaml\n"
			if _, ok := files["base/deployment.yaml"]; !ok {
				files["base/deployment.yaml"] = safeBase
			}
			got, _ := scanKustomize(t, files, true)
			want := kustomizeFinding{"overlays/dev/p.yaml", "overlays/dev", 11, false}
			switch name {
			case "json 6902":
				// A list index never proves which container it selects: the
				// field keeps its base line.
				want = kustomizeFinding{"base/deployment.yaml", "overlays/dev", 12, false}
			case "inline":
				want = kustomizeFinding{"overlays/dev/kustomization.yaml", "overlays/dev", 15, false}
			}
			require.Equal(t, []kustomizeFinding{want}, got, name)
			// No regression: every file today's raw scan reports still has a finding.
			raw, _ := scanKustomize(t, files, false)
			for _, r := range raw {
				require.True(t, slices.ContainsFunc(got, func(f kustomizeFinding) bool { return f.file == r.file }),
					"%s: raw finding on %s lost", name, r.file)
			}
		}
	})

	t.Run("a suppression comment in a patch is honored", func(t *testing.T) {
		ignored := fmt.Sprintf(patch, "            # dd-iac-scan ignore-line\n")
		for name, overlay := range map[string]map[string]string{
			"file": {"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\npatches:\n  - path: p.yaml\n",
				"overlays/dev/p.yaml": ignored},
			"inline": {"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\npatches:\n  - patch: |-\n" +
				indent(ignored, "      ")},
		} {
			overlay["base/kustomization.yaml"] = "resources:\n  - deployment.yaml\n"
			overlay["base/deployment.yaml"] = safeBase
			got, _ := scanKustomize(t, overlay, true)
			require.Len(t, got, 1, name)
			require.True(t, got[0].suppressed, name)
		}
	})
	t.Run("a generated Secret is reported on its generator entry without its values", func(t *testing.T) {
		got, raw := scanKustomize(t, map[string]string{
			"app/kustomization.yaml": "secretGenerator:\n  - name: creds\n    literals:\n      - PASSWORD=canary-secret-value\n",
			"app/deployment.yaml":    safeBase,
		}, true, "k8s_secret")
		require.Len(t, got, 1)
		require.Equal(t, "app/kustomization.yaml", got[0].file)
		require.Equal(t, 2, got[0].line, "the finding lands on the generator entry's name line")
		require.NotContains(t, raw, "canary-secret-value")
		require.NotContains(t, raw, "Y2FuYXJ5LXNlY3JldC12YWx1ZQ==") // base64 of the canary
	})

	t.Run("a generator-only repository is not scanned for other platforms", func(t *testing.T) {
		got, raw := scanKustomizePlatform(t, map[string]string{
			"app/kustomization.yaml": "secretGenerator:\n  - name: only\n    literals:\n      - PASSWORD=generator-only-canary\n",
		}, true, "Terraform", "k8s_secret")
		require.Empty(t, got, "no Kubernetes finding may be reported under -t Terraform")
		require.NotContains(t, raw, "generator-only-canary")
		require.NotContains(t, raw, "render_root", "Kubernetes rendering must not run")
	})

	t.Run("a replacement into an ordinary resource name reports the source name", func(t *testing.T) {
		got, raw := scanKustomize(t, map[string]string{
			"base/kustomization.yaml": "resources:\n  - deployment.yaml\n  - cm.yaml\n",
			"base/deployment.yaml":    privilegedDeployment,
			"base/cm.yaml":            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\ndata:\n  TOKEN: canary-ordinary-replacement\n",
			"overlays/dev/kustomization.yaml": "namePrefix: dev-\nresources:\n  - ../../base\n" +
				"replacements:\n  - source: {kind: ConfigMap, name: cfg, fieldPath: data.TOKEN}\n    targets:\n      - select: {kind: Deployment}\n        fieldPaths:\n          - metadata.name\n",
		}, true)
		require.NotContains(t, raw, "canary-ordinary-replacement")
		require.Contains(t, raw, "IAC_RESOURCE_NAME:web",
			"the replacement renamed the Deployment; the finding must report the source name")
		require.Contains(t, raw, "render_root",
			"the root must have rendered; a raw fallback makes the canary assertions trivial")
		require.NotEmpty(t, got)
	})

	t.Run("a generator-only repository is scanned", func(t *testing.T) {
		got, _ := scanKustomize(t, map[string]string{
			"app/kustomization.yaml": "secretGenerator:\n  - name: only\n    literals:\n      - PASSWORD=generator-only-canary\n",
		}, true, "k8s_secret")
		require.Equal(t, []kustomizeFinding{{"app/kustomization.yaml", "app", 2, false}}, got)
	})

	t.Run("a replacement copying generated data into a name leaves no value in any output", func(t *testing.T) {
		got, raw := scanKustomize(t, map[string]string{
			"app/kustomization.yaml": "configMapGenerator:\n  - name: cfg\n    literals:\n      - TOKEN=canary-replacement-value\n" +
				"secretGenerator:\n  - name: creds\n    literals:\n      - PASSWORD=other\n" +
				"replacements:\n  - source: {kind: ConfigMap, name: cfg, fieldPath: data.TOKEN}\n    targets:\n      - select: {kind: Secret}\n        fieldPaths:\n          - metadata.name\n",
			"app/deployment.yaml": safeBase,
		}, true, "k8s_secret")
		require.NotContains(t, raw, "canary-replacement-value")
		require.NotContains(t, raw, "Y2FuYXJ5LXJlcGxhY2VtZW50LXZhbHVl") // base64 of the canary
		for _, f := range got {
			require.Equal(t, "app/kustomization.yaml", f.file)
		}
		require.NotEmpty(t, got)
	})

}

func indent(s, prefix string) string {
	return prefix + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n"+prefix) + "\n"
}
