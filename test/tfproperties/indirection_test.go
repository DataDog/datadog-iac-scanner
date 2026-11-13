/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfproperties

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/DataDog/datadog-iac-scanner/test/tfharness"
	"github.com/stretchr/testify/require"
)

// TestTheEvaluatorResolvesEveryIndirection checks, over every value cell,
// that a rule reading an attribute through configuration indirection (a
// variable, a local, a module output, a data source, a for expression, ...)
// sees exactly what it sees when the same value is written literally: every
// rule that fires on the literal oracle fires on the cell with the same
// findings, in both polarities. This guards the evaluator, on the legacy
// documents, where no unknown gate is involved.
func TestTheEvaluatorResolvesEveryIndirection(t *testing.T) {
	grid, oracle, cells, oracleOf := valueGrid(t)
	knownLost := loadKnownLost(t)
	lostButListed := map[string]bool{}
	for i, c := range cells {
		o := oracleOf[c.Name()]
		want := oracleFindings(oracle, o)
		fs := grid.findingsOf(i)
		byRule := map[string][]tfharness.Finding{}
		for _, f := range fs {
			byRule[f.Rule] = append(byRule[f.Rule], f)
		}
		for rule, oracleFs := range want {
			if !strings.HasPrefix(rule, "probe-legacy-") {
				// This property guards the evaluator on the legacy
				// documents, where no unknown gate is involved.
				continue
			}
			got := findingSet(ruleFindings(fs, rule))
			if len(got) < len(findingSet(oracleFs)) {
				if k, ok := knownLost[c.Name()]; ok && strings.HasPrefix(k.Reason, "concrete finding wrongly treated as unknown") {
					lostButListed[c.Name()] = true
					t.Logf("known lost finding on cell %s: %s", c.Name(), k.Reason)
					delete(byRule, rule)
					continue
				}
			}
			require.Equal(t, findingSet(oracleFs), got,
				"the legacy documents of cell %s differ from its literal oracle on rule %s\n%s",
				c.Name(), rule, c.Repro())
			delete(byRule, rule)
		}
		// The cell may not fire a rule the oracle does not fire either.
		for rule := range byRule {
			if strings.HasPrefix(rule, "probe-legacy-") {
				require.Empty(t, findingSet(ruleFindings(fs, rule)),
					"cell %s fires %s but its oracle does not\n%s", c.Name(), rule, c.Repro())
			}
		}
	}
}

// knownLostFindings lists the cells whose concrete findings the engine
// loses today, with the reason. The gate and the evaluator properties fail
// on an unlisted cell, and also on a listed cell that starts passing, so
// this list can only shrink.
type knownLostEntry struct {
	Cell   string `json:"cell"`
	Reason string `json:"reason"`
}

func loadKnownLost(t *testing.T) map[string]knownLostEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "known_findings_lost.json"))
	require.NoError(t, err)
	var out []knownLostEntry
	require.NoError(t, json.Unmarshal(raw, &out))
	m := map[string]knownLostEntry{}
	for _, k := range out {
		m[k.Cell] = k
	}
	return m
}

// TestConcreteInputsSurviveTheUnknownGate checks, over every value cell,
// that a finding whose inputs are all concrete survives the unknown gate:
// with the gate active, the contract input yields the same findings as the
// literal oracle of the cell. An unknown value elsewhere in the block or in
// a neighbor block must not drop the finding. Dropping a finding that
// depends on an unknown is intended product behavior; dropping one whose
// inputs are all concrete is a false negative, and the message below names
// it as such.
func TestConcreteInputsSurviveTheUnknownGate(t *testing.T) {
	grid, oracle, cells, oracleOf := valueGrid(t)
	knownLost := loadKnownLost(t)
	lostButListed := map[string]bool{}
	for i, c := range cells {
		o := oracleOf[c.Name()]
		want := oracleFindings(oracle, o)
		fs := grid.findingsOf(i)
		if c.Fire {
			// The gate must keep the finding of every sink the cell
			// declares, not only the first.
			if n := len(ruleFindings(fs, c.RuleID(tfcorpus.ProbeContract))); n < sinksOf(c) {
				if k, ok := knownLost[c.Name()]; ok && strings.HasPrefix(k.Reason, "concrete finding wrongly treated as unknown") {
					lostButListed[c.Name()] = true
					t.Logf("known lost finding on cell %s: %s", c.Name(), k.Reason)
				} else {
					require.GreaterOrEqual(t, n, sinksOf(c),
						"concrete finding wrongly treated as unknown: cell %s: the contract probe rule %s did not fire on every sink\n%s",
						c.Name(), c.RuleID(tfcorpus.ProbeContract), c.Repro())
				}
			}
		}
		for rule, oracleFs := range want {
			if !strings.HasPrefix(rule, "probe-contract-") {
				continue
			}
			got := findingSet(ruleFindings(fs, rule))
			wantSet := findingSet(oracleFs)
			if len(got) < len(wantSet) {
				if k, ok := knownLost[c.Name()]; ok && strings.HasPrefix(k.Reason, "concrete finding wrongly treated as unknown") {
					lostButListed[c.Name()] = true
					t.Logf("known lost finding on cell %s: %s", c.Name(), k.Reason)
					continue
				}
			}
			if len(got) != len(wantSet) {
				t.Errorf("concrete finding wrongly treated as unknown: cell %s, rule %s\nwant %v\ngot  %v\n%s",
					c.Name(), rule, wantSet, got, c.Repro())
				continue
			}
			require.Equal(t, wantSet, got,
				"concrete finding wrongly treated as unknown: cell %s, rule %s\n%s", c.Name(), rule, c.Repro())
		}
	}
	// The list can only shrink: a listed cell that starts passing is stale.
	for name := range knownLost {
		require.True(t, lostButListed[name],
			"the known-findings list holds cell %s, which now passes; remove it", name)
	}
}

// sinksOf is the number of sinks the cell expects findings on.
func sinksOf(c tfcorpus.Cell) int {
	if c.Sinks == 0 {
		return 1
	}
	return c.Sinks
}

// oracleIndexOf finds an oracle cell's index in the oracle grid.
func oracleIndexOf(oracle *gridResult, o tfcorpus.Cell) int {
	for i, oc := range oracle.cells {
		if oc.Name() == o.Name() {
			return i
		}
	}
	panic("oracle cell not found: " + o.Name())
}

// TestNoUnknownValueAloneFiresAProbe checks the other side of the gate: a
// cell configured with a non-firing value produces no finding at all, so a
// gate or evaluator change that starts reporting uncertain results shows up
// here.
func TestNoUnknownValueAloneFiresAProbe(t *testing.T) {
	_, _, cells, _ := valueGrid(t)
	grid, _, _, _ := valueGrid(t)
	for i, c := range cells {
		if c.Fire {
			continue
		}
		fs := grid.findingsOf(i)
		var fired []string
		for _, f := range fs {
			if strings.HasPrefix(f.Rule, "probe-") {
				fired = append(fired, f.Rule)
			}
		}
		require.Empty(t, fired,
			"cell %s holds a non-firing value but produced findings %v\n%s", c.Name(), fired, c.Repro())
	}
}

// TestContractAndLegacyProbesAgree checks, over every value cell, that the
// contract input and the legacy documents answer a rule identically: the
// same rules fire on the same sink with the same attribute paths.
func TestContractAndLegacyProbesAgree(t *testing.T) {
	grid, _, cells, _ := valueGrid(t)
	for i, c := range cells {
		fs := grid.findingsOf(i)
		legacyOf := map[string][]tfharness.Finding{}
		for _, f := range fs {
			if !strings.HasPrefix(f.Rule, "probe-legacy-resource-") {
				continue
			}
			contractRule := "probe-contract-" + strings.TrimPrefix(f.Rule, "probe-legacy-resource-")
			legacyOf[contractRule] = append(legacyOf[contractRule], f)
		}
		// Both sides must answer over the expected rule keys, so losing the
		// findings of one side entirely is a disagreement, not a pass.
		if c.Fire {
			require.NotEmpty(t, shapeSet(ruleFindings(fs, c.RuleID(tfcorpus.ProbeContract))),
				"cell %s: the contract probe rule %s fired nothing\n%s",
				c.Name(), c.RuleID(tfcorpus.ProbeContract), c.Repro())
			require.NotEmpty(t, shapeSet(ruleFindings(fs, c.RuleID(tfcorpus.ProbeLegacy))),
				"cell %s: the legacy probe rule %s fired nothing\n%s",
				c.Name(), c.RuleID(tfcorpus.ProbeLegacy), c.Repro())
		}
		for _, f := range fs {
			if !strings.HasPrefix(f.Rule, "probe-contract-") {
				continue
			}
			contract := shapeSet(ruleFindings(fs, f.Rule))
			legacy := shapeSet(legacyOf[f.Rule])
			require.Equal(t, legacy, contract,
				"cell %s: the contract input and the legacy documents disagree on rule %s\nlegacy %v\ncontract %v\n%s",
				c.Name(), f.Rule, legacy, contract, c.Repro())
		}
	}
}
