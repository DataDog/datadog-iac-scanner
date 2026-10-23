/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfscale

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/stretchr/testify/require"
)

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p)
		require.NoError(t, err)
		rel, _ := filepath.Rel(dir, p)
		out[rel] = string(data)
		return nil
	}))
	return out
}

// A shape always generates the same files.
func TestGenerate_IsDeterministic(t *testing.T) {
	for _, s := range Catalog() {
		a, b := t.TempDir(), t.TempDir()
		ea, err := Generate(a, &s)
		require.NoError(t, err)
		eb, err := Generate(b, &s)
		require.NoError(t, err)
		require.Equal(t, ea, eb)
		require.Equal(t, readTree(t, a), readTree(t, b), s.Name)
		require.Less(t, ea.SourceBytes, int64(4<<20), "%s: fixtures stay small in source", s.Name)
	}
}

// The cardinality a shape expects is what evaluating it yields. Shapes too
// large for a unit test are checked by the stress job instead.
func TestGenerate_ExpectedCardinalityMatchesEvaluation(t *testing.T) {
	for _, s := range Catalog() {
		e := Expect(&s)
		if e.LeafInstances+e.RootResourceInstances > 20000 {
			continue
		}
		t.Run(s.Name, func(t *testing.T) {
			dir := t.TempDir()
			_, err := Generate(dir, &s)
			require.NoError(t, err)
			roots, err := filepath.Glob(filepath.Join(dir, "roots", "*"))
			require.NoError(t, err)
			sort.Strings(roots)
			buckets, moduleResources := 0, 0
			for _, root := range roots {
				ev := tfeval.New()
				resources, _, _, err := ev.EvaluateModule(context.Background(), root, nil)
				require.NoError(t, err)
				for _, r := range resources {
					if r.Type == "aws_s3_bucket" && !r.Data {
						buckets++
					}
					if r.ModuleAddress != "" {
						moduleResources++
					}
				}
			}
			require.Equal(t, e.ACLFindings, buckets, "aws_s3_bucket instances")
			require.Equal(t, e.ModuleResources, moduleResources, "module resource and data instances")
		})
	}
}

func TestCompare(t *testing.T) {
	complete := func(shape string, rss int64, cpu float64, findings int) Run {
		return Run{Shape: shape, Complete: true, PeakRSS: rss, CPUSeconds: cpu, Findings: findings}
	}
	limits := Thresholds{MaxRSSRatio: 1.15, MaxCPURatio: 1.25}
	base := []Run{complete("a", 1000, 10, 5), {Shape: "b", Complete: false, PeakRSS: 1, CPUSeconds: 1}}

	require.Empty(t, Compare(base, []Run{complete("a", 1100, 12, 5), complete("b", 9999, 99, 7)}, limits),
		"within thresholds, and no ratio against an incomplete baseline")
	require.Len(t, Compare(base, []Run{complete("a", 1200, 10, 5)}, limits), 1, "peak RSS regression")
	require.Len(t, Compare(base, []Run{complete("a", 1000, 13, 5)}, limits), 1, "CPU regression")
	require.Len(t, Compare(base, []Run{complete("a", 1000, 10, 4)}, limits), 1, "finding cardinality change")
	require.Len(t, Compare(base, []Run{{Shape: "a", Problems: []string{"truncated"}}}, limits), 1, "incomplete head")
}
