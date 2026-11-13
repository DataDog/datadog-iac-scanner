/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfproperties

import (
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/DataDog/datadog-iac-scanner/test/tfharness"
)

// gridResult holds the findings of one grid scan, bucketed by cell
// directory, with the cell directory stripped from file paths so runs from
// different temporary directories compare.
type gridResult struct {
	cells  []tfcorpus.Cell
	names  []string
	byCell map[string][]tfharness.Finding
}

// findingsOf returns the findings of cell i.
func (g *gridResult) findingsOf(i int) []tfharness.Finding {
	return g.byCell[g.names[i]]
}

// scanGrid materializes cells, scans them once, and buckets the findings by
// cell. One scan runs every probe rule, so the result holds the findings of
// the contract input and of the legacy documents together.
func scanGrid(t *testing.T, cells []tfcorpus.Cell, rules, libs string) *gridResult {
	t.Helper()
	dir, names := tfcorpus.Materialize(t, cells)
	run := tfharness.Inspect(t, dir, rules, libs)
	g := &gridResult{cells: cells, names: names, byCell: map[string][]tfharness.Finding{}}
	for _, f := range run.Findings {
		i := strings.Index(f.File, "/")
		if i < 0 {
			continue
		}
		cellDir, rest := f.File[:i], f.File[i+1:]
		f.File = rest
		g.byCell[cellDir] = append(g.byCell[cellDir], f)
	}
	return g
}

// ruleFindings keeps the findings of one rule.
func ruleFindings(fs []tfharness.Finding, rule string) []tfharness.Finding {
	var out []tfharness.Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// instanceKeyInName matches the instance key a block name or search key
// carries when the sink is expanded (sink[0], sink["k"]); moduleInKey
// matches the module call chain a search key may carry.
var (
	instanceKeyInName = regexp.MustCompile(`sink\[[^\]]*\]`)
	moduleInKey       = regexp.MustCompile(`(module\.[A-Za-z0-9_]+(\[[^\]]*\])?\.)+`)
	legacyNameInKey   = regexp.MustCompile(`aws_s3_bucket\[sink([^\]]*)\]`)
)

// normalizeKey strips the instance keys and module call chain a finding
// carries, keeping the finding shape the cell and its oracle share.
func normalizeKey(s string) string {
	s = moduleInKey.ReplaceAllString(s, "")
	// The legacy documents write the block name in brackets, the contract
	// input after a dot; both carry the instance key after the name.
	s = legacyNameInKey.ReplaceAllString(s, "aws_s3_bucket.sink$1")
	return instanceKeyInName.ReplaceAllString(s, "sink")
}

// findingSet renders findings for comparison and for failure messages. The
// instance key, the line and the call chain are normalized out: a cell and
// its oracle may expand the sink differently, and only the finding shape
// they share is the property.
func findingSet(fs []tfharness.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Rule+"|"+f.ResourceType+"|"+normalizeKey(f.ResourceName)+"|"+normalizeKey(f.SearchKey))
	}
	sortStrings(out)
	return out
}

// shapeSet renders findings without their rule id, for comparisons between
// the contract input and the legacy documents, whose probe rules carry
// different names.
func shapeSet(fs []tfharness.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ResourceType+"|"+normalizeKey(f.ResourceName)+"|"+normalizeKey(f.SearchKey))
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// valueCache lazily scans the value grid and its oracle cells once per test
// binary, so the properties share one scan of each. Tests run in sequence,
// so the first caller's t builds the cache.
var valueCache struct {
	once     sync.Once
	grid     *gridResult
	oracle   *gridResult
	cells    []tfcorpus.Cell
	oracleOf map[string]tfcorpus.Cell
}

// valueGrid returns the value grid, its scan, the oracle scan, and the
// oracle of every cell, by cell name.
func valueGrid(t *testing.T) (grid, oracle *gridResult, cells []tfcorpus.Cell, oracleOf map[string]tfcorpus.Cell) {
	t.Helper()
	valueCache.once.Do(func() {
		rules := tfcorpus.WriteRules(t)
		libs := tfharness.LibraryPath(t)
		cells := tfcorpus.ValueGrid()
		valueCache.cells = cells
		valueCache.grid = scanGrid(t, cells, rules, libs)
		seen := map[string]bool{}
		var oracles []tfcorpus.Cell
		oracleOf := map[string]tfcorpus.Cell{}
		for _, c := range cells {
			o := c.Oracle()
			oracleOf[c.Name()] = o
			if !seen[o.Name()] {
				seen[o.Name()] = true
				oracles = append(oracles, o)
			}
		}
		valueCache.oracleOf = oracleOf
		valueCache.oracle = scanGrid(t, oracles, rules, libs)
	})
	return valueCache.grid, valueCache.oracle, valueCache.cells, valueCache.oracleOf
}

// oracleFindings returns the oracle's findings by rule id.
func oracleFindings(oracle *gridResult, o tfcorpus.Cell) map[string][]tfharness.Finding {
	for i, oc := range oracle.cells {
		if oc.Name() == o.Name() {
			fs := oracle.findingsOf(i)
			byRule := map[string][]tfharness.Finding{}
			for _, f := range fs {
				byRule[f.Rule] = append(byRule[f.Rule], f)
			}
			return byRule
		}
	}
	panic("oracle cell not found: " + o.Name())
}
