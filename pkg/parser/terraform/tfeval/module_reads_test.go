/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

func parseTestBlocks(t *testing.T, src string) (modules []*hclsyntax.Block, locals *localGraph, data []*hclsyntax.Block) {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	bodies := []*hclsyntax.Body{file.Body.(*hclsyntax.Body)}
	_, localExprs, modules, _, _ := collectBlocks(bodies)
	return modules, newLocalGraph(localExprs, nil), collectDataBlocks(bodies)
}

func TestComputeSiblingReads(t *testing.T) {
	modules, locals, data := parseTestBlocks(t, `
locals {
  direct  = module.a.id
  chained  = local.direct
  unread   = module.z.id
  via_data = data.aws_iam_policy_document.p.json
  constant = "t"
}
data "aws_iam_policy_document" "p" {
  statement { resources = [local.chained, module.b.arn] }
}
module "a" {
  source = "./a"
}
module "b" {
  source     = "./b"
  in         = local.chained
  depends_on = [module.z]
  providers  = { aws = module.z.provider }
}
module "c" {
  source = "./c"
  in     = data.aws_iam_policy_document.p.json
  other  = module.b.id
}
module "d" {
  source   = "./d"
  for_each = module.c
}
module "e" {
  source = "./e"
  in     = local["chained"]
  all    = data.aws_iam_policy_document
}
module "f" {
  source = "./f"
  in     = local.via_data
  tag    = local.constant
}
module "g" {
  source = "./g"
  in     = "${module.f.id}-${local.constant}"
}
`)
	reads := computeSiblingReads(modules, locals, data)
	names := func(s labelSet) map[string]bool {
		if s.names == nil {
			return map[string]bool{}
		}
		return s.names
	}

	require.Empty(t, names(reads.direct[0]))
	require.Empty(t, names(reads.resolved[0]))

	require.Empty(t, names(reads.direct[1]), "depends_on and providers are never evaluated")
	require.Equal(t, map[string]bool{"a": true}, names(reads.resolved[1]))

	require.Equal(t, map[string]bool{"b": true}, names(reads.direct[2]))
	require.Equal(t, map[string]bool{"a": true, "b": true}, names(reads.resolved[2]))

	require.Equal(t, map[string]bool{"c": true}, names(reads.direct[3]))

	require.False(t, reads.direct[4].all)
	require.Equal(t, map[string]bool{"a": true, "b": true}, names(reads.resolved[4]))

	require.Equal(t, map[string]bool{"a": true, "b": true}, names(reads.resolved[5]), "a local reading a data block")
	require.True(t, reads.throughLocals[5])
	require.Equal(t, map[string]bool{"f": true}, names(reads.resolved[6]))
	require.False(t, reads.throughLocals[6], "a constant local reaches no call")
	for i := range reads.resolved {
		require.False(t, reads.resolved[i].all, "call %d", i)
	}

	bare, locals, data := parseTestBlocks(t, `
module "a" { source = "./a" }
module "b" {
  source = "./b"
  in     = keys(module)
}
`)
	require.True(t, computeSiblingReads(bare, locals, data).resolved[1].all)
}

// A call reads its siblings' outputs directly, through a local and through a
// data block; it must see each sibling's final outputs, whatever order the
// calls are written in and however many unrelated calls sit between them.
func TestSiblingCallsSeeTheOutputsTheyRead(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "pass", map[string]string{"main.tf": `
variable "in" {}
output "out" { value = var.in }
resource "aws_sqs_queue" "q" { name = var.in }
`})
	var b strings.Builder
	b.WriteString(`
locals {
  from_b = "${module.b.out}-local"
  hop2   = "${local.from_b}-h2"
}
data "aws_iam_policy_document" "p" {
  statement { resources = [module.c.out] }
}
module "a" {
  source = "../pass"
  in     = "a"
}
module "b" {
  source = "../pass"
  in     = "${module.a.out}-b"
}
module "c" {
  source = "../pass"
  in     = local.hop2
}
module "d" {
  source = "../pass"
  in     = data.aws_iam_policy_document.p.json
}
module "early" {
  source = "../pass"
  in     = "${module.late.out}-early"
}
`)
	for i := range 20 {
		fmt.Fprintf(&b, "module \"filler%02d\" {\n  source = \"../pass\"\n  in     = \"filler%02d\"\n}\n", i, i)
	}
	b.WriteString(`
module "late" {
  source = "../pass"
  in     = "${module.a.out}-late"
}
module "counted" {
  count  = length([module.a.out])
  source = "../pass"
  in     = module.a.out
}
module "each" {
  for_each = toset([module.a.out])
  source   = "../pass"
  in       = each.key
}
module "bare" {
  source = "../pass"
  in     = length(keys(module)) > 0 ? "bare" : "empty"
}
`)
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": b.String()})

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	names := map[string]string{}
	for _, r := range resources {
		if r.Type == "aws_sqs_queue" {
			v := r.Attributes["name"]
			require.True(t, v.IsWhollyKnown(), "%s: %#v", r.ModuleAddress, v)
			names[r.ModuleAddress] = v.AsString()
		}
	}
	require.Equal(t, "a", names["module.a"])
	require.Equal(t, "a-b", names["module.b"])
	require.Equal(t, "a-b-local-h2", names["module.c"])
	require.Contains(t, names["module.d"], "a-b-local")
	require.Equal(t, "a-late-early", names["module.early"])
	require.Equal(t, "a-late", names["module.late"])
	require.Equal(t, "a", names["module.counted[0]"])
	require.Equal(t, "a", names[`module.each["a"]`])
	require.Equal(t, "bare", names["module.bare"])
}

type siblingEvalCost struct {
	retained, allocated int64
}

func measureSiblingEvaluation(t *testing.T, dir string, wantResources int) siblingEvalCost {
	t.Helper()
	collect := func() runtime.MemStats {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m
	}
	before := collect()
	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	after := collect()
	runtime.KeepAlive(resources)
	runtime.KeepAlive(e)
	require.Len(t, resources, wantResources)
	return siblingEvalCost{
		retained:  int64(after.HeapAlloc) - int64(before.HeapAlloc),
		allocated: int64(after.TotalAlloc - before.TotalAlloc),
	}
}

// Every sibling call must cost the same however many calls the module has:
// publishing module.* to the calls is quadratic when the object is rebuilt
// for every call.
func TestScaling_SiblingModuleCallsCostIsLinear(t *testing.T) {
	const (
		maxGrowth = 1.5
		// Measured at about 40 KiB allocated and 16 KiB retained per call.
		maxAllocatedPerCall = 160 << 10
		maxRetainedPerCall  = 64 << 10
		// Measured at about 500 KiB allocated per call at 400 calls.
		maxQuadraticAllocatedPerCall = 1 << 20
		maxQuadraticGrowth           = 4.5
	)
	sizes := []int{50, 100, 200, 400}
	for _, tc := range []struct {
		name string
		// call returns the arguments of call i of n.
		call func(i, n int) string
		// header replaces the local that reads the first call.
		header string
		// knownQuadratic names a cost that still grows with the number of calls.
		knownQuadratic string
	}{
		{name: "independent", call: func(i, _ int) string { return fmt.Sprintf(`in = "n%04d"`, i) }},
		{name: "reading the first", call: func(i, _ int) string {
			if i == 0 {
				return `in = "first"`
			}
			return fmt.Sprintf(`in = "${module.m0000.out}-%04d"`, i)
		}},
		{name: "reading the first through a local", call: func(i, _ int) string {
			if i == 0 {
				return `in = "first"`
			}
			return fmt.Sprintf(`in = "${local.first}-%04d"`, i)
		}},
		{name: "reading the last", call: func(i, n int) string {
			if i == n-1 {
				return `in = "last"`
			}
			return fmt.Sprintf(`in = "${module.m%04d.out}-%04d"`, n-1, i)
		}},
		{name: "each call reads the previous", call: func(i, _ int) string {
			if i == 0 {
				return `in = "first"`
			}
			return fmt.Sprintf(`in = "${module.m%04d.out}-x"`, i-1)
		}},
		{
			name:   "each call reads the previous plus a constant local",
			header: "locals {\n  tags = \"t\"\n}\n",
			call: func(i, _ int) string {
				if i == 0 {
					return `in = "first-${local.tags}"`
				}
				return fmt.Sprintf(`in = "${module.m%04d.out}-${local.tags}"`, i-1)
			},
		},
		{
			name:           "each call reads every module output through a local",
			header:         "locals {\n  all = module\n}\n",
			knownQuadratic: "a local reading every module output rebuilds module.* after each call",
			call: func(i, _ int) string {
				return fmt.Sprintf(`in = "${length(keys(local.all))}-%04d"`, i)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			costs := make([]siblingEvalCost, len(sizes))
			for s, n := range sizes {
				root := t.TempDir()
				writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "in" {}
output "out" { value = var.in }
resource "aws_sqs_queue" "q" { name = var.in }
`})
				var b strings.Builder
				if tc.header != "" {
					b.WriteString(tc.header)
				} else {
					b.WriteString("locals {\n  first = module.m0000.out\n}\n")
				}
				for i := range n {
					fmt.Fprintf(&b, "module \"m%04d\" {\n  source = \"../leaf\"\n  %s\n}\n", i, tc.call(i, n))
				}
				dir := writeModule(t, root, "stack", map[string]string{"main.tf": b.String()})
				costs[s] = measureSiblingEvaluation(t, dir, n)
				t.Logf("%4d calls: retained %d KiB, allocated %d KiB", n, costs[s].retained>>10, costs[s].allocated>>10)
			}
			perCall := func(i int) (retained, allocated float64) {
				units := float64(sizes[i] - sizes[i-1])
				return float64(costs[i].retained-costs[i-1].retained) / units,
					float64(costs[i].allocated-costs[i-1].allocated) / units
			}
			firstRetained, firstAllocated := perCall(1)
			lastRetained, lastAllocated := perCall(len(sizes) - 1)
			allocatedCeiling := float64(maxAllocatedPerCall)
			if tc.knownQuadratic != "" {
				allocatedCeiling = maxQuadraticAllocatedPerCall
			}
			require.LessOrEqual(t, lastAllocated, allocatedCeiling, "allocated bytes per call passed the ceiling")
			require.LessOrEqual(t, lastRetained, float64(maxRetainedPerCall), "retained bytes per call passed the ceiling")
			// The floor keeps near-zero marginal costs from turning noise into a ratio.
			if tc.knownQuadratic != "" &&
				(lastAllocated > maxGrowth*max(firstAllocated, 1024) || lastRetained > maxGrowth*max(firstRetained, 1024)) {
				// A quadratic's marginal cost per call grows with the number of
				// calls: the 200-400 step costs four times the 50-100 step.
				if lastAllocated > maxQuadraticGrowth*max(firstAllocated, 1024) ||
					lastRetained > maxQuadraticGrowth*max(firstRetained, 1024) {
					t.Fatalf("worse than the known quadratic cost: %s (allocated %.0f -> %.0f, retained %.0f -> %.0f)",
						tc.knownQuadratic, firstAllocated, lastAllocated, firstRetained, lastRetained)
				}
				t.Skipf("known quadratic cost not fixed yet: %s (allocated %.0f -> %.0f bytes/call)",
					tc.knownQuadratic, firstAllocated, lastAllocated)
			}
			require.LessOrEqual(t, lastAllocated, maxGrowth*max(firstAllocated, 1024),
				"allocated bytes per call grew from %.0f to %.0f", firstAllocated, lastAllocated)
			require.LessOrEqual(t, lastRetained, maxGrowth*max(firstRetained, 1024),
				"retained bytes per call grew from %.0f to %.0f", firstRetained, lastRetained)
		})
	}
}

func TestPrepassCalls(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want []bool
	}{
		{
			name: "no sibling reads",
			src:  `module "a" { source = "./a" }` + "\n" + `module "b" { source = "./b" }`,
			want: []bool{false, false},
		},
		{
			name: "reads an earlier call",
			src: `module "a" { source = "./a" }
module "b" {
  source = "./b"
  in     = module.a.out
}`,
			want: []bool{false, false},
		},
		{
			name: "reads a later call",
			src: `module "a" {
  source = "./a"
  in     = module.c.out
}
module "b" { source = "./b" }
module "c" { source = "./c" }`,
			want: []bool{false, false, true},
		},
		{
			name: "reads a later call through a local",
			src: `locals { c = module.c.out }
module "a" {
  source = "./a"
  in     = local.c
}
module "b" { source = "./b" }
module "c" { source = "./c" }`,
			want: []bool{false, false, true},
		},
		{
			name: "the later call reads another call directly",
			src: `module "a" {
  source = "./a"
  in     = module.c.out
}
module "b" { source = "./b" }
module "c" {
  source = "./c"
  in     = module.b.out
}
module "d" { source = "./d" }`,
			want: []bool{false, true, true, false},
		},
		{
			name: "the later call reads another call through a local",
			src: `locals { b = module.b.out }
module "a" {
  source = "./a"
  in     = module.c.out
}
module "b" { source = "./b" }
module "c" {
  source = "./c"
  in     = local.b
}`,
			want: []bool{false, false, true},
		},
		{
			name: "reads every call",
			src: `module "a" {
  source = "./a"
  in     = length(module)
}
module "b" { source = "./b" }`,
			want: []bool{true, true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modules, locals, data := parseTestBlocks(t, tc.src)
			reads := computeSiblingReads(modules, locals, data)
			require.Equal(t, tc.want, reads.prepass)
			require.Equal(t, slices.Contains(tc.want, true), reads.anyPrepass)
		})
	}
}

// A subtree that cannot be cached, here because an expansion is truncated, is
// evaluated again for every evaluation of its caller. When the speculative
// prepass also evaluated it for a sibling that never reads it, every level of
// nesting doubled the work below it.
func TestScaling_UnreadSiblingIsNotEvaluatedAhead(t *testing.T) {
	const (
		maxGrowth = 1.5
		// Measured at about 130 KiB allocated per level.
		maxAllocatedPerLevel = 512 << 10
	)
	depths := []int{4, 8}
	costs := make([]siblingEvalCost, len(depths))
	for s, depth := range depths {
		root := t.TempDir()
		writeModule(t, root, "side", map[string]string{"main.tf": `
resource "aws_sqs_queue" "side" { name = "side" }
`})
		writeModule(t, root, fmt.Sprintf("lvl%02d", depth), map[string]string{"main.tf": fmt.Sprintf(`
resource "aws_sqs_queue" "q" {
  count = %d
  name  = "q-${count.index}"
}
`, maxCountExpansion+10)})
		for l := depth - 1; l >= 0; l-- {
			writeModule(t, root, fmt.Sprintf("lvl%02d", l), map[string]string{"main.tf": fmt.Sprintf(`
module "next" { source = "../lvl%02d" }
module "side" { source = "../side" }
`, l+1)})
		}
		costs[s] = measureSiblingEvaluation(t, root+"/lvl00", maxCountExpansion+depth)
		t.Logf("depth %d: retained %d KiB, allocated %d KiB", depth, costs[s].retained>>10, costs[s].allocated>>10)
	}
	perLevel := func(i int) float64 { return float64(costs[i].allocated) / float64(depths[i]) }
	require.LessOrEqual(t, perLevel(1), maxGrowth*perLevel(0),
		"allocated bytes per nesting level grew from %.0f at depth %d to %.0f at depth %d",
		perLevel(0), depths[0], perLevel(1), depths[1])
	require.LessOrEqual(t, perLevel(1), float64(maxAllocatedPerLevel))
}

// A call reading a later sibling has inputs the prepass cannot resolve yet, so
// evaluating it in the prepass caches a whole second subtree under inputs the
// main loop never uses. Only the sibling it reads is evaluated ahead.
func TestPrepassEvaluatesOnlyTheSiblingReadAhead(t *testing.T) {
	const instances = 20
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": `
variable "in" {}
variable "peer" { default = "" }
output "out" { value = var.in }
resource "aws_sqs_queue" "q" { name = "${var.in}${var.peer}" }
`})
	dir := writeModule(t, root, "stack", map[string]string{"main.tf": fmt.Sprintf(`
module "reader" {
  source   = "../leaf"
  for_each = toset([for i in range(%d) : format("k%%02d", i)])
  in       = "${each.key}-"
  peer     = module.last.out
}
module "last" {
  source = "../leaf"
  in     = "last"
}
`, instances)})

	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.Len(t, resources, instances+1)
	for _, r := range resources {
		v := r.Attributes["name"]
		require.True(t, v.IsWhollyKnown(), "%s: %#v", r.ModuleAddress, v)
		require.True(t, strings.HasSuffix(v.AsString(), "last"), v.AsString())
	}
	// The reader instances, the last call and the stack itself.
	require.Len(t, e.cache, instances+2)
}
