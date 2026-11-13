package tfproperties

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/DataDog/datadog-iac-scanner/test/tfharness"
)

func TestGridProbeAll(t *testing.T) {
	cells := append(tfcorpus.ValueGrid(), tfcorpus.PairGrid()...)
	fmt.Println("cells:", len(cells))
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
	missing, falseFire := 0, 0
	for i, c := range cells {
		fs := byCell[names[i]]
		n := c.Sinks
		if n == 0 {
			n = 1
		}
		var found int
		for _, f := range fs {
			if f.Rule == c.RuleID("contract") && strings.HasPrefix(f.ResourceName, "sink") {
				found++
			}
		}
		switch {
		case c.Fire && found < n:
			missing++
			if missing <= 10 {
				fmt.Println("MISSING:", c.Name(), "want", n, "got", found)
			}
		case !c.Fire && found > 0:
			falseFire++
			if falseFire <= 4 {
				fmt.Println("FALSE FIRE:", c.Name())
			}
		}
	}
	fmt.Println("missing:", missing, "false:", falseFire)
}
