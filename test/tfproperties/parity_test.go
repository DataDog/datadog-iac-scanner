/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfproperties

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/DataDog/datadog-iac-scanner/test/tfharness"
	"github.com/stretchr/testify/require"
)

// expansionCache lazily scans the expansion grid once per test binary.
var expansionCache struct {
	once  sync.Once
	grid  *gridResult
	cells []tfcorpus.Cell
}

func expansionGrid(t *testing.T) (*gridResult, []tfcorpus.Cell) {
	t.Helper()
	expansionCache.once.Do(func() {
		rules := tfcorpus.WriteRules(t)
		libs := tfharness.LibraryPath(t)
		expansionCache.cells = tfcorpus.ExpansionGrid()
		expansionCache.grid = scanGrid(t, expansionCache.cells, rules, libs)
	})
	return expansionCache.grid, expansionCache.cells
}

// expectedKeys returns the block names one call chain of the cell holds. The
// legacy documents report one finding per instance under the block label and
// carry the instance key in the Terraform address; the contract input keys
// the instance in its resource name. A module sink carries no key of its
// own: the module instance is the key.
func expectedKeys(c tfcorpus.Cell, contract bool) []string {
	switch {
	case c.SinkKind == "module":
		return []string{"sink"}
	case contract:
		return c.Keys
	default:
		out := make([]string, len(c.Keys))
		for i := range c.Keys {
			out[i] = "sink"
		}
		return out
	}
}

// checkInstanceGroups groups one rule's findings by call chain and checks
// that every chain holds exactly the expected instances — by name, and for
// the legacy documents by the instance key in the Terraform address — with
// one shared finding shape.
func checkInstanceGroups(t *testing.T, c tfcorpus.Cell, rule string, fs []tfharness.Finding, contract bool) {
	t.Helper()
	byChain := map[string][]tfharness.Finding{}
	for _, f := range fs {
		byChain[f.CallChain] = append(byChain[f.CallChain], f)
	}
	want := expectedKeys(c, contract)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	total := 0
	for chain, group := range byChain {
		var names []string
		shapes := map[string]bool{}
		for _, f := range group {
			names = append(names, f.ResourceName)
			shapes[f.ResourceType+"|"+normalizeKey(f.SearchKey)] = true
		}
		sort.Strings(names)
		total += len(group)
		require.Equal(t, sortedWant, names,
			"cell %s: rule %s on call chain %q does not hold exactly the instance keys the cell declares\n%s",
			c.Name(), rule, chain, c.Repro())
		require.Len(t, shapes, 1,
			"cell %s: rule %s on call chain %q: instances disagree on finding shape\n%s",
			c.Name(), rule, chain, c.Repro())
		if !contract && c.SinkKind != "module" {
			// The legacy address of each finding carries one instance key.
			var keys []string
			for _, f := range group {
				keys = append(keys, addressName(f.ResourceID))
			}
			sort.Strings(keys)
			sortedKeys := append([]string(nil), c.Keys...)
			sort.Strings(sortedKeys)
			require.Equal(t, sortedKeys, keys,
				"cell %s: rule %s: the instance keys in the addresses differ from the declared ones\n%s",
				c.Name(), rule, c.Repro())
		}
	}
	// Every instance appears exactly once: no sibling twice, none missing.
	require.Len(t, fs, len(want)*len(byChain),
		"cell %s: rule %s holds %d findings for %d instances on %d call chains\n%s",
		c.Name(), rule, len(fs), len(want), len(byChain), c.Repro())
}

// addressName returns the block name and instance key an address carries
// ("sink", "sink[0]"), or the address itself when it is not the sink.
func addressName(id string) string {
	i := strings.Index(id, "aws_s3_bucket.sink")
	if i < 0 {
		return id
	}
	return id[i+len("aws_s3_bucket."):]
}

// TestInstancesOfABlockProduceTheSameFindingShape checks, over every
// expansion cell, that every instance of a sink block yields the same
// finding shape as its sibling instances, on the legacy documents: the same
// rules fire, with the same attribute-path structure, and exactly the
// instance keys the cell declares — whether the sink repeats through count,
// for_each, or a module call, and whether it is a resource, a data source or
// an ephemeral block.
func TestInstancesOfABlockProduceTheSameFindingShape(t *testing.T) {
	grid, cells := expansionGrid(t)
	for i, c := range cells {
		byRule := map[string][]tfharness.Finding{}
		for _, f := range grid.findingsOf(i) {
			if strings.HasPrefix(f.Rule, "probe-legacy-") {
				byRule[f.Rule] = append(byRule[f.Rule], f)
			}
		}
		for rule, fs := range byRule {
			checkInstanceGroups(t, c, rule, fs, false)
			if c.WantChains > 0 {
				chains := map[string]bool{}
				for _, f := range fs {
					chains[f.CallChain] = true
				}
				require.Len(t, chains, c.WantChains,
					"cell %s: rule %s evaluated %d module call chains, expected %d\n%s",
					c.Name(), rule, len(chains), c.WantChains, c.Repro())
			}
		}
		// The declared keys must all be covered by the rules that fire.
		if len(byRule) > 0 {
			covered := map[string]bool{}
			for _, fs := range byRule {
				for _, f := range fs {
					covered[addressName(f.ResourceID)] = true
				}
			}
			for _, key := range c.Keys {
				require.True(t, covered[key],
					"cell %s: no rule fires on instance %s\n%s", c.Name(), key, c.Repro())
			}
		}
	}
}

// TestContractInstancesCarryTheirAddress checks the contract side of parity:
// on the contract input, every instance of an expanded resource or module
// sink reports under its own instance key with the same finding shape as its
// siblings. Data and ephemeral sinks are legacy-only, so they are skipped.
func TestContractInstancesCarryTheirAddress(t *testing.T) {
	grid, cells := expansionGrid(t)
	for i, c := range cells {
		if c.SinkKind == "data" || c.SinkKind == "ephemeral" {
			continue
		}
		byRule := map[string][]tfharness.Finding{}
		for _, f := range grid.findingsOf(i) {
			if strings.HasPrefix(f.Rule, "probe-contract-") {
				byRule[f.Rule] = append(byRule[f.Rule], f)
			}
		}
		for rule, fs := range byRule {
			checkInstanceGroups(t, c, rule, fs, true)
		}
	}
}
