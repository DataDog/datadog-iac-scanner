/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfproperties holds the general properties of the Terraform rule
// engine: they hold over every generated cell of a corpus, not over one
// fixture per past problem. Each test's comment says which behavior it
// guards.
package tfproperties

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/DataDog/datadog-iac-scanner/test/tfharness"
	"github.com/stretchr/testify/require"
)

// TestTheHarnessFindsWhatTheFixturesWrite runs one literal cell through both
// probe inputs: the scan harness, the probe rules and the shared libraries
// all work, and the engine reads a literal attribute on the contract input
// and on the legacy documents.
func TestTheHarnessFindsWhatTheFixturesWrite(t *testing.T) {
	rules := tfcorpus.WriteRules(t)
	libs := tfharness.LibraryPath(t)

	grid := tfcorpus.ValueGrid()
	cells := make([]tfcorpus.Cell, 0, 2)
	for _, c := range grid {
		if c.Indirection == "local" && c.Shape == "scalar" && c.Read == "eq" &&
			c.Source == "written" && c.Neighbor == "none" && c.Fire {
			cells = append(cells, c)
			break
		}
	}
	require.Len(t, cells, 1, "the value grid must hold the literal scalar cell")
	dir, _ := tfcorpus.Materialize(t, cells)

	run := tfharness.Inspect(t, dir, rules, libs)
	contract := run.OnSink(cells[0].RuleID(tfcorpus.ProbeContract))
	legacy := run.OnSink(cells[0].RuleID(tfcorpus.ProbeLegacy))
	require.Len(t, contract, 1, "the contract probe must fire on the literal cell")
	require.Len(t, legacy, 1, "the legacy probe must fire on the literal cell")
	require.Equal(t, "sink", contract[0].ResourceName)
	require.Equal(t, "sink", legacy[0].ResourceName)
}
