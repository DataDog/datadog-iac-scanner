/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfproperties

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/DataDog/datadog-iac-scanner/test/tfharness"
	"github.com/stretchr/testify/require"
)

// determinismCells samples the corpus for the determinism checks: every
// expansion cell, so modules and expansions are covered, and every tenth
// value cell, so the indirection kinds rotate through.
func determinismCells() []tfcorpus.Cell {
	var cells []tfcorpus.Cell
	cells = append(cells, tfcorpus.ExpansionGrid()...)
	value := tfcorpus.ValueGrid()
	for i := 0; i < len(value); i += 10 {
		cells = append(cells, value[i])
	}
	return cells
}

// reportedKey is the stable identity of one reported finding.
func reportedKey(v *model.Vulnerability) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s", v.QueryID, v.FileName, v.Line,
		v.ResourceType, v.ResourceName, v.SearchKey, v.ModuleCallChain)
}

// TestRepeatedScansProduceTheSameFindings checks that scanning the same
// corpus twice gives the same findings in the same order, and that the order
// the files are handed to the engine in does not change the output.
func TestRepeatedScansProduceTheSameFindings(t *testing.T) {
	cells := determinismCells()
	rules := tfcorpus.WriteRules(t)
	libs := tfharness.LibraryPath(t)
	dir, _ := tfcorpus.Materialize(t, cells)

	first := tfharness.Inspect(t, dir, rules, libs)
	again := tfharness.Inspect(t, dir, rules, libs)
	require.Equal(t, reportedKeys(first.Vulns), reportedKeys(again.Vulns),
		"two scans of the same corpus differ")

	files := tfharness.ParseTree(t, dir)
	for seed := 1; seed <= 5; seed++ {
		shuffled := append(files[:0:0], files...)
		rng := rand.New(rand.NewSource(int64(seed)))
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		run := tfharness.InspectParsed(t, shuffled, rules, libs, dir)
		require.Equal(t, reportedKeys(first.Vulns), reportedKeys(run.Vulns),
			"scan with file order seed %d differs", seed)
	}
}

// reportedKeys renders the ordered findings of a run.
func reportedKeys(vs []model.Vulnerability) []string {
	out := make([]string, 0, len(vs))
	for i := range vs {
		out = append(out, reportedKey(&vs[i]))
	}
	return out
}

// TestRepeatedScansWriteTheSameReport checks that a whole scan, through the
// command-line path, writes the same SARIF twice.
func TestRepeatedScansWriteTheSameReport(t *testing.T) {
	if testing.Short() {
		t.Skip("the repeated reports run only in the full suite")
	}
	cells := determinismCells()
	rules := tfcorpus.WriteRules(t)
	libs := tfharness.LibraryPath(t)
	dir, _ := tfcorpus.Materialize(t, cells)
	first := tfharness.ScanPath(t, dir, rules, libs)
	second := tfharness.ScanPath(t, dir, rules, libs)
	require.Equal(t, string(first), string(second), "two scans wrote different SARIF")
}

// TestCompactFindingsKeepTheFirstOfEachIdentity checks the engine's
// identity compaction: when it keeps one finding per identity while
// decoding, it keeps the finding of each identity group that compares first,
// and no identity is lost. The corpus here is the counted expansions with
// the shared-identity probe rule, so one identity group holds one finding
// per instance, at a different line each.
func TestCompactFindingsKeepTheFirstOfEachIdentity(t *testing.T) {
	var cells []tfcorpus.Cell
	for _, c := range tfcorpus.ExpansionGrid() {
		if c.Expansion == "count3" || c.Expansion == "count258" || c.Expansion == "foreach_map" ||
			c.Expansion == "module_foreach" || c.Expansion == "module_count" {
			if !c.Fire {
				continue
			}
			cells = append(cells, c)
		}
	}
	rules := tfcorpus.WriteRulesMulti(t)
	libs := tfharness.LibraryPath(t)
	dir, _ := tfcorpus.Materialize(t, cells)

	full := tfharness.Inspect(t, dir, rules, libs)
	compact := tfharness.InspectCompact(t, dir, rules, libs)

	// Group the uncompacted findings by an identity built from the reported
	// fields themselves, not from the engine's identity function: the two
	// must agree, and a change to one of them shows up here.
	type identityKey struct{ file, rule, typ, name, idKey, chain string }
	groups := map[identityKey][]*model.Vulnerability{}
	var order []identityKey
	for i := range full.Vulns {
		v := &full.Vulns[i]
		k := identityKey{file: v.FileName, rule: v.QueryID, typ: v.ResourceType,
			name: v.ResourceName, idKey: v.IdentityKey, chain: v.ModuleCallChain}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], v)
	}
	var want []string
	distinctCandidates := false
	for _, k := range order {
		g := groups[k]
		best := g[0]
		for _, v := range g[1:] {
			if model.CompareFindings(v, best) < 0 {
				best = v
			}
		}
		// The selection is only observable where the candidates differ on a
		// field CompareFindings orders on.
		for _, v := range g {
			if model.CompareFindings(v, best) != 0 {
				distinctCandidates = true
			}
		}
		want = append(want, reportedKey(best))
	}
	require.True(t, distinctCandidates,
		"no identity group in the corpus holds candidates that compare differently, so the first-of-identity selection is not exercised")
	require.Len(t, compact.Vulns, len(want),
		"the compacted scan holds a different number of findings than the identity groups")
	require.Equal(t, want, reportedKeys(compact.Vulns),
		"the compacted scan did not keep the first finding of each identity")
	// The selected finding of the shared-identity rule is the remediation
	// that compares first.
	for i := range compact.Vulns {
		v := &compact.Vulns[i]
		if v.QueryID == "probe-legacy-resource-multi" {
			require.Equal(t, "aa-first", v.Remediation,
				"the compacted scan kept remediation %q, not the one that compares first", v.Remediation)
			break
		}
	}
}

// sarifFingerprints reads the report's per-result fingerprints, grouped by
// rule.
func sarifFingerprints(t *testing.T, sarif []byte) map[string][]string {
	t.Helper()
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
				Partial struct {
					Datadog string `json:"DATADOG_FINGERPRINT"`
				} `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(sarif, &report))
	out := map[string][]string{}
	for _, run := range report.Runs {
		for _, r := range run.Results {
			if len(r.Locations) == 0 {
				continue
			}
			out[r.RuleID] = append(out[r.RuleID], r.Partial.Datadog)
		}
	}
	for rule := range out {
		sort.Strings(out[rule])
	}
	return out
}

// TestFingerprintsDiscriminateModuleCalls checks the report path's stable
// identity: the fingerprint of the same identity is equal across runs, and
// the same rule reached through different module call chains carries
// different fingerprints.
func TestFingerprintsDiscriminateModuleCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("the report fingerprints run only in the full suite")
	}
	var cells []tfcorpus.Cell
	for _, c := range tfcorpus.ExpansionGrid() {
		if c.Expansion == "module_foreach" && c.Fire {
			cells = append(cells, c)
		}
	}
	require.NotEmpty(t, cells)
	rules := tfcorpus.WriteRules(t)
	libs := tfharness.LibraryPath(t)
	dir, _ := tfcorpus.Materialize(t, cells)

	first := sarifFingerprints(t, tfharness.ScanPath(t, dir, rules, libs))
	second := sarifFingerprints(t, tfharness.ScanPath(t, dir, rules, libs))
	for rule, fps := range first {
		require.NotEmpty(t, fps, "no fingerprint for rule %s", rule)
		require.Equal(t, fps, second[rule], "the fingerprints of rule %s differ between runs", rule)
	}
	// One module_foreach cell reports the same rule, file and line for two
	// call chains; their fingerprints must differ.
	foundDistinct := false
	for _, fps := range first {
		seen := map[string]bool{}
		for _, fp := range fps {
			seen[fp] = true
		}
		if len(seen) > 1 {
			foundDistinct = true
		}
	}
	require.True(t, foundDistinct,
		"no rule's findings carry different fingerprints for different module call chains")
}
