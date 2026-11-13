package tfproperties

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/DataDog/datadog-iac-scanner/test/tfharness"
	"github.com/stretchr/testify/require"
)

// TestEveryFiringCellProducesItsFindings scans the whole value and pair
// corpus once and requires every firing cell to produce the findings its
// own probe rule declares on every sink, and no non-firing cell to produce
// any. It is the fast whole-grid sanity check behind the per-property
// runs; it is skipped in short mode, where the per-property tests carry
// the coverage.
func TestEveryFiringCellProducesItsFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("the whole-grid scan runs only in the full suite")
	}
	cells := append(tfcorpus.ValueGrid(), tfcorpus.PairGrid()...)
	rules := tfcorpus.WriteRules(t)
	libs := tfharness.LibraryPath(t)
	dir, names := tfcorpus.Materialize(t, cells)
	run := tfharness.Inspect(t, dir, rules, libs)
	byCell := map[string][]tfharness.Finding{}
	for _, f := range run.Findings {
		i := strings.Index(f.File, "/")
		if i < 0 {
			continue
		}
		byCell[f.File[:i]] = append(byCell[f.File[:i]], f)
	}
	knownLost := loadKnownLost(t)
	var missing, falseFire []string
	for i, c := range cells {
		fs := byCell[names[i]]
		sinks := c.Sinks
		if sinks == 0 {
			sinks = 1
		}
		var found int
		for _, f := range fs {
			if f.Rule == c.RuleID(tfcorpus.ProbeContract) && strings.HasPrefix(f.ResourceName, "sink") {
				found++
			}
		}
		switch {
		case c.Fire && found < sinks:
			if _, ok := knownLost[c.Name()]; ok {
				continue
			}
			missing = append(missing, fmt.Sprintf("%s want %d got %d", c.Name(), sinks, found))
		case !c.Fire && found > 0:
			falseFire = append(falseFire, c.Name())
		}
	}
	require.Empty(t, missing, "firing cells without their findings: %v", missing)
	require.Empty(t, falseFire, "non-firing cells with findings: %v", falseFire)
}
