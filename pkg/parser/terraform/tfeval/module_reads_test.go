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
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

func parseTestBlocks(t *testing.T, src string) (modules []*hclsyntax.Block, locals map[string]hclsyntax.Expression, data []*hclsyntax.Block) {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	bodies := []*hclsyntax.Body{file.Body.(*hclsyntax.Body)}
	_, locals, modules, _, _ = collectBlocks(bodies)
	return modules, locals, collectDataBlocks(bodies)
}

func TestComputeSiblingReads(t *testing.T) {
	modules, locals, data := parseTestBlocks(t, `
locals {
  direct  = module.a.id
  chained = local.direct
  unread  = module.z.id
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
  in     = local.from_b
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
	require.Equal(t, "a-b-local", names["module.c"])
	require.Contains(t, names["module.d"], "a-b-local")
	require.Equal(t, "a-late-early", names["module.early"])
	require.Equal(t, "a-late", names["module.late"])
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
	)
	sizes := []int{50, 100, 200, 400}
	for _, tc := range []struct {
		name string
		// call returns the arguments of call i of n.
		call func(i, n int) string
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
				b.WriteString("locals {\n  first = module.m0000.out\n}\n")
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
			// The floor keeps near-zero marginal costs from turning noise into a ratio.
			require.LessOrEqual(t, lastAllocated, maxGrowth*max(firstAllocated, 1024),
				"allocated bytes per call grew from %.0f to %.0f", firstAllocated, lastAllocated)
			require.LessOrEqual(t, lastRetained, maxGrowth*max(firstRetained, 1024),
				"retained bytes per call grew from %.0f to %.0f", firstRetained, lastRetained)
			require.LessOrEqual(t, lastAllocated, float64(maxAllocatedPerCall))
			require.LessOrEqual(t, lastRetained, float64(maxRetainedPerCall))
		})
	}
}
