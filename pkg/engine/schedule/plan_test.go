/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package schedule

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	bucket     = TypeKey{Kind: KindResource, Type: "aws_s3_bucket"}
	versioning = TypeKey{Kind: KindResource, Type: "aws_s3_bucket_versioning"}
	instance   = TypeKey{Kind: KindResource, Type: "aws_instance"}
	variable   = TypeKey{Kind: KindVariable}
)

func anchored(id string, types ...TypeKey) Rule {
	return Rule{ID: id, Types: types, Class: Anchored}
}

func relational(id string, types ...TypeKey) Rule {
	return Rule{ID: id, Types: types, Class: Relational, ClassReason: "reads relations", Relations: true}
}

func TestPlanSkipsRootsWithoutTypes(t *testing.T) {
	roots := Roots{
		"a": {bucket: {Blocks: 2, Digest: "d1"}},
		"b": {instance: {Blocks: 1, Digest: "d2"}},
		"c": {},
	}
	rules := []Rule{
		anchored("r1", bucket),
		relational("r2", bucket, versioning),
		{ID: "r3", AlwaysRun: true, Reasons: []string{"reads input directly"}},
	}
	p := NewPlan(rules, roots, PlanOptions{})
	require.Equal(t, []Skip{
		{Rule: "r1", Root: "b"}, {Rule: "r1", Root: "c"},
		{Rule: "r2", Root: "b"}, {Rule: "r2", Root: "c"},
	}, p.Skipped)
	require.Equal(t, []Batch{
		{Rule: "r1", Units: []Unit{{Root: "a", DedupKey: p.Anchored[0].Units[0].DedupKey}}, Blocks: 2},
	}, p.Anchored)
	require.NotEmpty(t, p.Anchored[0].Units[0].DedupKey)
	require.Equal(t, []RootRun{
		{Root: "a", Rules: []string{"r2", "r3"}},
		{Root: "b", Rules: []string{"r3"}},
		{Root: "c", Rules: []string{"r3"}},
	}, p.Relational)
}

// A type with zero blocks counts as absent.
func TestPlanZeroBlocksIsAbsent(t *testing.T) {
	p := NewPlan([]Rule{anchored("r", bucket)}, Roots{"a": {bucket: {Blocks: 0, Digest: "d"}}}, PlanOptions{})
	require.Equal(t, []Skip{{Rule: "r", Root: "a"}}, p.Skipped)
	require.Empty(t, p.Anchored)
}

// An always-run anchored rule is not batched.
func TestPlanAlwaysRunIsPerRoot(t *testing.T) {
	r := anchored("r", bucket)
	r.AlwaysRun = true
	p := NewPlan([]Rule{r}, Roots{"a": {}, "b": {bucket: {Blocks: 1}}}, PlanOptions{})
	require.Empty(t, p.Skipped)
	require.Empty(t, p.Anchored)
	require.Equal(t, []RootRun{{Root: "a", Rules: []string{"r"}}, {Root: "b", Rules: []string{"r"}}}, p.Relational)
}

func TestPlanDedup(t *testing.T) {
	roots := Roots{
		"m1": {bucket: {Blocks: 3, Digest: "same"}, instance: {Blocks: 1, Digest: "x"}},
		"m0": {bucket: {Blocks: 3, Digest: "same"}, instance: {Blocks: 1, Digest: "y"}},
		"m2": {bucket: {Blocks: 3, Digest: "other"}},
		"m3": {bucket: {Blocks: 3, Digest: ""}},
		"m4": {bucket: {Blocks: 3, Digest: ""}},
	}
	p := NewPlan([]Rule{anchored("r", bucket)}, roots, PlanOptions{})
	require.Len(t, p.Anchored, 1)
	units := p.Anchored[0].Units
	require.Len(t, units, 4)
	require.Equal(t, "m0", units[0].Root, "the smallest root represents its duplicates")
	require.Equal(t, []string{"m1"}, units[0].Duplicates, "types the rule does not read do not split duplicates")
	require.Equal(t, "m2", units[1].Root)
	require.NotEqual(t, units[0].DedupKey, units[1].DedupKey)
	for _, u := range units[2:] {
		require.Empty(t, u.DedupKey, "unknown digests are never deduplicated")
		require.Empty(t, u.Duplicates)
	}
	require.Equal(t, 12, p.Anchored[0].Blocks, "duplicates are not evaluated")

	// A second type in the rule splits the roots that differ on it.
	p = NewPlan([]Rule{anchored("r", bucket, instance)}, roots, PlanOptions{})
	require.Len(t, p.Anchored[0].Units, 5)
}

// The key depends on the type of each digest, not only on the digests.
func TestPlanDedupKeyIncludesTypes(t *testing.T) {
	roots := Roots{
		"a": {bucket: {Blocks: 1, Digest: "d"}},
		"b": {versioning: {Blocks: 1, Digest: "d"}},
	}
	p := NewPlan([]Rule{anchored("r", bucket, versioning)}, roots, PlanOptions{})
	require.Len(t, p.Anchored[0].Units, 2)
}

func TestPlanBatchesByBlocks(t *testing.T) {
	roots := Roots{
		"a": {variable: {Blocks: 3}},
		"b": {variable: {Blocks: 3}},
		"c": {variable: {Blocks: 10}},
		"d": {variable: {Blocks: 1}},
	}
	p := NewPlan([]Rule{anchored("r", variable)}, roots, PlanOptions{MaxBatchBlocks: 6})
	var got [][]string
	var blocks []int
	for _, b := range p.Anchored {
		var names []string
		for _, u := range b.Units {
			names = append(names, u.Root)
		}
		got = append(got, names)
		blocks = append(blocks, b.Blocks)
	}
	require.Equal(t, [][]string{{"a", "b"}, {"c"}, {"d"}}, got, "a unit over the bound is a batch of its own")
	require.Equal(t, []int{6, 10, 1}, blocks)
}

func TestPlanIsDeterministic(t *testing.T) {
	roots := Roots{}
	for _, name := range []string{"z", "y", "x", "w"} {
		roots[name] = map[TypeKey]Presence{bucket: {Blocks: 1, Digest: name}, versioning: {Blocks: 1}}
	}
	rules := []Rule{relational("c", versioning), anchored("b", bucket), anchored("a", versioning)}
	want := NewPlan(rules, roots, PlanOptions{MaxBatchBlocks: 2})
	for range 20 {
		require.Equal(t, want, NewPlan([]Rule{rules[2], rules[0], rules[1]}, roots, PlanOptions{MaxBatchBlocks: 2}))
	}
	require.Equal(t, "a", want.Anchored[0].Rule)
	require.Equal(t, []string{"w", "x"}, []string{want.Anchored[0].Units[0].Root, want.Anchored[0].Units[1].Root})
}
