/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// This file is the inventory of the Terraform expansion and module-resolution
// patterns evaluation supports. Every case pins the exact instances a pattern
// produces, by address, and the outputs Terraform would compute where they
// are knowable from the configuration. A finite known expansion yields every
// instance; one that is not knowable, or that Terraform rejects, is evaluated
// once with an unknown iteration, as Terraform plans an unknown one.

// instanceAddress is the Terraform address of a resolved instance.
func instanceAddress(r *ResolvedResource) string {
	local := r.Type + "." + r.Name
	if r.Data {
		local = "data." + local
	}
	return joinAddr(r.ModuleAddress, local)
}

func addresses(resources []ResolvedResource) []string {
	out := make([]string, len(resources))
	if len(out) == 0 {
		return []string{}
	}
	for i, r := range resources {
		out[i] = instanceAddress(&r)
	}
	sort.Strings(out)
	return out
}

// expand returns the addresses of n instances of base, indexed by count.
func expand(base string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(base, i)
	}
	return out
}

// cross returns every address formed by substituting one element of each
// list for the %s of format, in order.
func cross(format string, lists ...[]string) []string {
	out := []string{format}
	for _, list := range lists {
		var next []string
		for _, partial := range out {
			for _, item := range list {
				next = append(next, strings.Replace(partial, "%s", item, 1))
			}
		}
		out = next
	}
	sort.Strings(out)
	return out
}

func indexes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprint(i)
	}
	return out
}

func keys(names ...string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = fmt.Sprintf("%q", n)
	}
	return out
}

func sorted(list []string) []string {
	out := append([]string{}, list...)
	sort.Strings(out)
	return out
}

// jsonOf renders a value for comparison with an expected JSON text.
func jsonOf(t *testing.T, v cty.Value) string {
	t.Helper()
	if !v.IsWhollyKnown() {
		return "<unknown>"
	}
	b, err := ctyjson.Marshal(v, v.Type())
	require.NoError(t, err)
	return string(b)
}

type patternCase struct {
	name string
	// modules are written under the fixture root by directory name; the root
	// module is "stack".
	modules map[string]string
	want    []string
	outputs map[string]string
}

func runPattern(t *testing.T, c patternCase) []ResolvedResource {
	t.Helper()
	root := t.TempDir()
	for dir, src := range c.modules {
		writeModule(t, root, dir, map[string]string{"main.tf": src})
	}
	resources, outputs := evaluateBothWays(t, filepath.Join(root, "stack"))
	got := addresses(resources)
	require.Equal(t, sorted(c.want), got, "instance addresses")
	require.Len(t, got, len(c.want), "instance count")
	for name, want := range c.outputs {
		require.Equal(t, want, jsonOf(t, outputs[name]), "output %s", name)
	}
	return resources
}

// evaluateBothWays evaluates stack with every module call's instances in
// order, then with every call of two instances or more evaluated
// concurrently, and checks both give the same instances, values and outputs.
func evaluateBothWays(t *testing.T, stack string) ([]ResolvedResource, map[string]cty.Value) {
	t.Helper()
	previous := parallelInstancesMin
	defer func() { parallelInstancesMin = previous }()
	parallelInstancesMin = math.MaxInt
	serial, serialOutputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	parallelInstancesMin = 2
	concurrent, concurrentOutputs, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Equal(t, describe(t, serial), describe(t, concurrent), "concurrent evaluation differs from serial")
	require.Equal(t, len(serialOutputs), len(concurrentOutputs))
	for name, v := range serialOutputs {
		require.Equal(t, jsonOf(t, v), jsonOf(t, concurrentOutputs[name]), "output %s", name)
	}
	return serial, serialOutputs
}

// describe renders instances in order with their address, call chain and
// documents, for comparing evaluations.
func describe(t *testing.T, resources []ResolvedResource) []string {
	t.Helper()
	out := make([]string, len(resources))
	for i := range resources {
		r := &resources[i]
		doc, err := json.Marshal(AttributesToDocument(r))
		require.NoError(t, err)
		out[i] = fmt.Sprintf("%s chain=%d %s", instanceAddress(r), len(r.CallChain), doc)
	}
	return out
}

const passthroughLeaf = `
variable "name" {}
resource "aws_s3_bucket" "b" { bucket = var.name }
output "name" { value = aws_s3_bucket.b.bucket }
`

func TestPatterns_ResourceExpansion(t *testing.T) {
	for _, c := range []patternCase{
		{
			name: "count",
			modules: map[string]string{"stack": `
resource "aws_s3_bucket" "b" {
  count  = 3
  bucket = "b-${count.index}"
}
output "names" { value = aws_s3_bucket.b[*].bucket }
`},
			want:    expand("aws_s3_bucket.b[%d]", 3),
			outputs: map[string]string{"names": `["b-0","b-1","b-2"]`},
		},
		{
			name: "count from a string",
			modules: map[string]string{"stack": `
resource "aws_s3_bucket" "b" { count = "2" }
`},
			want: expand("aws_s3_bucket.b[%d]", 2),
		},
		{
			name: "for_each over a map",
			modules: map[string]string{"stack": `
resource "aws_s3_bucket" "b" {
  for_each = { x = "1", y = "2" }
  bucket   = "${each.key}-${each.value}"
}
output "names" { value = { for k, b in aws_s3_bucket.b : k => b.bucket } }
`},
			want:    []string{`aws_s3_bucket.b["x"]`, `aws_s3_bucket.b["y"]`},
			outputs: map[string]string{"names": `{"x":"x-1","y":"y-2"}`},
		},
		{
			name: "for_each over a set",
			modules: map[string]string{"stack": `
resource "aws_s3_bucket" "b" {
  for_each = toset(["p", "q", "p"])
  bucket   = each.value
}
`},
			want: []string{`aws_s3_bucket.b["p"]`, `aws_s3_bucket.b["q"]`},
		},
		{
			name: "empty count and for_each",
			modules: map[string]string{"stack": `
resource "aws_s3_bucket" "zero" { count = 0 }
resource "aws_s3_bucket" "none" { for_each = {} }
output "n" { value = length(aws_s3_bucket.zero) + length(aws_s3_bucket.none) }
`},
			want:    nil,
			outputs: map[string]string{"n": `0`},
		},
		{
			name: "unknown count",
			modules: map[string]string{"stack": `
variable "n" {}
resource "aws_s3_bucket" "b" { count = var.n }
`},
			want: []string{"aws_s3_bucket.b"},
		},
		{
			name: "unknown for_each",
			modules: map[string]string{"stack": `
variable "m" {}
resource "aws_s3_bucket" "b" { for_each = var.m }
`},
			want: []string{"aws_s3_bucket.b"},
		},
		{
			name:    "null count",
			modules: map[string]string{"stack": `resource "aws_s3_bucket" "b" { count = null }`},
			want:    []string{"aws_s3_bucket.b"},
		},
		{
			name:    "negative count",
			modules: map[string]string{"stack": `resource "aws_s3_bucket" "b" { count = -1 }`},
			want:    []string{"aws_s3_bucket.b"},
		},
		{
			name:    "fractional count",
			modules: map[string]string{"stack": `resource "aws_s3_bucket" "b" { count = 1.5 }`},
			want:    []string{"aws_s3_bucket.b"},
		},
		{
			name:    "for_each over a list",
			modules: map[string]string{"stack": `resource "aws_s3_bucket" "b" { for_each = ["a"] }`},
			want:    []string{"aws_s3_bucket.b"},
		},
		{
			name:    "for_each over a set of numbers",
			modules: map[string]string{"stack": `resource "aws_s3_bucket" "b" { for_each = toset([1, 2]) }`},
			want:    []string{"aws_s3_bucket.b"},
		},
		{
			name:    "null for_each",
			modules: map[string]string{"stack": `resource "aws_s3_bucket" "b" { for_each = null }`},
			want:    []string{"aws_s3_bucket.b"},
		},
		{
			name: "references between expanded resources",
			modules: map[string]string{"stack": `
resource "aws_s3_bucket" "a" {
  count  = 2
  bucket = "a-${count.index}"
}
resource "aws_s3_bucket_policy" "p" {
  count  = 2
  bucket = aws_s3_bucket.a[count.index].bucket
}
resource "aws_s3_bucket" "k" {
  for_each = { x = 1 }
  bucket   = "k-${each.key}"
}
resource "aws_s3_bucket_policy" "kp" {
  for_each = aws_s3_bucket.k
  bucket   = each.value.bucket
}
output "policies" { value = concat(aws_s3_bucket_policy.p[*].bucket, [for p in aws_s3_bucket_policy.kp : p.bucket]) }
`},
			want: append(append(expand("aws_s3_bucket.a[%d]", 2), expand("aws_s3_bucket_policy.p[%d]", 2)...),
				`aws_s3_bucket.k["x"]`, `aws_s3_bucket_policy.kp["x"]`),
			outputs: map[string]string{"policies": `["a-0","a-1","k-x"]`},
		},
		{
			name: "data blocks with count and for_each",
			modules: map[string]string{"stack": `
data "aws_iam_policy_document" "c" {
  count = 2
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::b${count.index}/*"]
  }
}
data "aws_region" "r" {
  for_each = toset(["us-east-1", "eu-west-1"])
  name     = each.key
}
output "regions" { value = sort([for r in data.aws_region.r : r.name]) }
`},
			want: append(expand("data.aws_iam_policy_document.c[%d]", 2),
				`data.aws_region.r["eu-west-1"]`, `data.aws_region.r["us-east-1"]`),
			outputs: map[string]string{"regions": `["eu-west-1","us-east-1"]`},
		},
	} {
		t.Run(c.name, func(t *testing.T) { runPattern(t, c) })
	}
}

func TestPatterns_ModuleExpansion(t *testing.T) {
	for _, c := range []patternCase{
		{
			name: "module count",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "m" {
  source = "../leaf"
  count  = 3
  name   = "n${count.index}"
}
output "names" { value = module.m[*].name }
`},
			want:    expand("module.m[%d].aws_s3_bucket.b", 3),
			outputs: map[string]string{"names": `["n0","n1","n2"]`},
		},
		{
			name: "module for_each over a map",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "m" {
  source   = "../leaf"
  for_each = { a = "x", b = "y" }
  name     = each.value
}
output "names" { value = { for k, m in module.m : k => m.name } }
`},
			want:    []string{`module.m["a"].aws_s3_bucket.b`, `module.m["b"].aws_s3_bucket.b`},
			outputs: map[string]string{"names": `{"a":"x","b":"y"}`},
		},
		{
			name: "module for_each over a set",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "m" {
  source   = "../leaf"
  for_each = toset(["a", "b"])
  name     = each.key
}
`},
			want: []string{`module.m["a"].aws_s3_bucket.b`, `module.m["b"].aws_s3_bucket.b`},
		},
		{
			name: "module with zero instances",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "m" {
  source = "../leaf"
  count  = 0
  name   = "x"
}
output "n" { value = length(module.m) }
`},
			want:    nil,
			outputs: map[string]string{"n": `0`},
		},
		{
			name: "unknown module count",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
variable "n" {}
module "m" {
  source = "../leaf"
  count  = var.n
  name   = "x"
}
`},
			want: []string{"module.m.aws_s3_bucket.b"},
		},
		{
			name: "invalid module for_each",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "m" {
  source   = "../leaf"
  for_each = ["a"]
  name     = "x"
}
`},
			want: []string{"module.m.aws_s3_bucket.b"},
		},
		{
			name: "resource count inside an expanded module",
			modules: map[string]string{
				"leaf": `
variable "name" {}
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "${var.name}-${count.index}"
}
output "names" { value = aws_s3_bucket.b[*].bucket }
`, "stack": `
module "m" {
  source   = "../leaf"
  for_each = toset(["x", "y"])
  name     = each.key
}
output "names" { value = flatten([for m in module.m : m.names]) }
`},
			want:    cross(`module.m[%s].aws_s3_bucket.b[%s]`, keys("x", "y"), indexes(2)),
			outputs: map[string]string{"names": `["x-0","x-1","y-0","y-1"]`},
		},
	} {
		t.Run(c.name, func(t *testing.T) { runPattern(t, c) })
	}
}

// nestedModules builds a chain root -> l0 -> l1 -> ... where each level i
// expands its child with exprs[i] and passes the instance path down; the last
// level declares the resource.
func nestedModules(exprs []string, indexOf []string) map[string]string {
	mods := map[string]string{}
	depth := len(exprs)
	for i := 0; i < depth; i++ {
		var src string
		if i > 0 {
			src = "variable \"path\" {}\n"
		}
		path := `"${var.path}/${` + indexOf[i] + `}"`
		if i == 0 {
			path = `"${` + indexOf[i] + `}"`
		}
		src += fmt.Sprintf("module \"next\" {\n  source = \"../l%d\"\n  %s\n  path = %s\n}\n", i, exprs[i], path)
		src += "output \"paths\" { value = flatten([for m in module.next : m.paths]) }\n"
		if i == 0 {
			mods["stack"] = strings.Replace(src, "variable \"path\" {}\n", "", 1)
		} else {
			mods[fmt.Sprintf("l%d", i-1)] = src
		}
	}
	mods[fmt.Sprintf("l%d", depth-1)] = `
variable "path" {}
resource "aws_s3_bucket" "b" { bucket = var.path }
output "paths" { value = [aws_s3_bucket.b.bucket] }
`
	return mods
}

func TestPatterns_NestedModuleExpansion(t *testing.T) {
	const (
		count2 = "count = 2"
		count3 = "count = 3"
		feAB   = `for_each = toset(["a", "b"])`
		feXY   = `for_each = { x = 1, y = 2 }`
	)
	for _, c := range []struct {
		name    string
		exprs   []string
		indexOf []string
		want    []string
		paths   string
	}{
		{
			name: "count -> count", exprs: []string{count2, count3}, indexOf: []string{"count.index", "count.index"},
			want:  cross(`module.next[%s].module.next[%s].aws_s3_bucket.b`, indexes(2), indexes(3)),
			paths: `["0/0","0/1","0/2","1/0","1/1","1/2"]`,
		},
		{
			name: "for_each -> for_each", exprs: []string{feAB, feXY}, indexOf: []string{"each.key", "each.key"},
			want:  cross(`module.next[%s].module.next[%s].aws_s3_bucket.b`, keys("a", "b"), keys("x", "y")),
			paths: `["a/x","a/y","b/x","b/y"]`,
		},
		{
			name: "count -> for_each", exprs: []string{count2, feXY}, indexOf: []string{"count.index", "each.key"},
			want:  cross(`module.next[%s].module.next[%s].aws_s3_bucket.b`, indexes(2), keys("x", "y")),
			paths: `["0/x","0/y","1/x","1/y"]`,
		},
		{
			name: "for_each -> count", exprs: []string{feAB, count2}, indexOf: []string{"each.key", "count.index"},
			want:  cross(`module.next[%s].module.next[%s].aws_s3_bucket.b`, keys("a", "b"), indexes(2)),
			paths: `["a/0","a/1","b/0","b/1"]`,
		},
		{
			name: "three levels", exprs: []string{feAB, count2, feXY}, indexOf: []string{"each.key", "count.index", "each.key"},
			want: cross(`module.next[%s].module.next[%s].module.next[%s].aws_s3_bucket.b`,
				keys("a", "b"), indexes(2), keys("x", "y")),
			paths: `["a/0/x","a/0/y","a/1/x","a/1/y","b/0/x","b/0/y","b/1/x","b/1/y"]`,
		},
		{
			name: "four levels", exprs: []string{count2, feAB, count2, feXY},
			indexOf: []string{"count.index", "each.key", "count.index", "each.key"},
			want: cross(`module.next[%s].module.next[%s].module.next[%s].module.next[%s].aws_s3_bucket.b`,
				indexes(2), keys("a", "b"), indexes(2), keys("x", "y")),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			outputs := map[string]string{}
			if c.paths != "" {
				outputs["paths"] = c.paths
			}
			resources := runPattern(t, patternCase{
				modules: nestedModules(c.exprs, c.indexOf), want: c.want, outputs: outputs,
			})
			// Every instance holds its own path, so no instance is a copy of another.
			seen := map[string]bool{}
			for _, r := range resources {
				seen[r.Attributes["bucket"].AsString()] = true
			}
			require.Len(t, seen, len(c.want))
		})
	}
}

func TestPatterns_ModuleReferences(t *testing.T) {
	for _, c := range []patternCase{
		{
			name: "sibling module reads an earlier sibling",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "a" {
  source = "../leaf"
  name   = "first"
}
module "b" {
  source = "../leaf"
  name   = "${module.a.name}-second"
}
output "b" { value = module.b.name }
`},
			want:    []string{"module.a.aws_s3_bucket.b", "module.b.aws_s3_bucket.b"},
			outputs: map[string]string{"b": `"first-second"`},
		},
		{
			name: "sibling module reads a later sibling",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "b" {
  source = "../leaf"
  name   = "${module.a.name}-second"
}
module "a" {
  source = "../leaf"
  name   = "first"
}
output "b" { value = module.b.name }
`},
			want:    []string{"module.a.aws_s3_bucket.b", "module.b.aws_s3_bucket.b"},
			outputs: map[string]string{"b": `"first-second"`},
		},
		{
			name: "module outputs indexed by count.index",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "a" {
  source = "../leaf"
  count  = 2
  name   = "a${count.index}"
}
module "b" {
  source = "../leaf"
  count  = 2
  name   = "${module.a[count.index].name}-b"
}
output "b" { value = module.b[*].name }
`},
			want:    append(expand("module.a[%d].aws_s3_bucket.b", 2), expand("module.b[%d].aws_s3_bucket.b", 2)...),
			outputs: map[string]string{"b": `["a0-b","a1-b"]`},
		},
		{
			name: "module outputs indexed by each.key",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
module "a" {
  source   = "../leaf"
  for_each = toset(["x", "y"])
  name     = "a-${each.key}"
}
module "b" {
  source   = "../leaf"
  for_each = module.a
  name     = "${module.a[each.key].name}-${each.value.name}"
}
output "b" { value = { for k, m in module.b : k => m.name } }
`},
			want: []string{`module.a["x"].aws_s3_bucket.b`, `module.a["y"].aws_s3_bucket.b`,
				`module.b["x"].aws_s3_bucket.b`, `module.b["y"].aws_s3_bucket.b`},
			outputs: map[string]string{"b": `{"x":"a-x-a-x","y":"a-y-a-y"}`},
		},
		{
			name: "locals, variables and outputs reading expanded siblings",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
locals {
  first = module.a[*].name
}
variable "suffix" { default = "s" }
module "a" {
  source = "../leaf"
  count  = 2
  name   = "a${count.index}"
}
module "b" {
  source = "../leaf"
  name   = "${join("+", local.first)}-${var.suffix}"
}
output "first" { value = local.first }
output "b" { value = module.b.name }
`},
			want:    append(expand("module.a[%d].aws_s3_bucket.b", 2), "module.b.aws_s3_bucket.b"),
			outputs: map[string]string{"first": `["a0","a1"]`, "b": `"a0+a1-s"`},
		},
		{
			name: "parent inputs forwarded unchanged through several levels",
			modules: map[string]string{
				"leaf": `
variable "cfg" {}
resource "aws_s3_bucket" "b" {
  bucket = var.cfg.name
  tags   = var.cfg.tags
}
output "cfg" { value = var.cfg }
`,
				"mid2": "variable \"cfg\" {}\nmodule \"leaf\" {\n  source = \"../leaf\"\n  cfg = var.cfg\n}\noutput \"cfg\" { value = module.leaf.cfg }\n",
				"mid1": "variable \"cfg\" {}\nmodule \"mid2\" {\n  source = \"../mid2\"\n  cfg = var.cfg\n}\noutput \"cfg\" { value = module.mid2.cfg }\n",
				"stack": `
locals {
  cfg = { name = "deep", tags = { team = "t" } }
}
module "mid1" {
  source = "../mid1"
  cfg    = local.cfg
}
output "same" { value = module.mid1.cfg == local.cfg }
`},
			want:    []string{"module.mid1.module.mid2.module.leaf.aws_s3_bucket.b"},
			outputs: map[string]string{"same": `true`},
		},
		{
			name: "mixed resources, data and modules",
			modules: map[string]string{"leaf": passthroughLeaf, "stack": `
resource "aws_s3_bucket" "own" {
  count  = 2
  bucket = "own${count.index}"
}
data "aws_region" "r" {
  for_each = toset(["r1"])
  name     = each.key
}
module "m" {
  source   = "../leaf"
  for_each = toset(aws_s3_bucket.own[*].bucket)
  name     = "${each.key}-${data.aws_region.r["r1"].name}"
}
output "names" { value = sort([for m in module.m : m.name]) }
`},
			want: append(expand("aws_s3_bucket.own[%d]", 2), `data.aws_region.r["r1"]`,
				`module.m["own0"].aws_s3_bucket.b`, `module.m["own1"].aws_s3_bucket.b`),
			outputs: map[string]string{"names": `["own0-r1","own1-r1"]`},
		},
	} {
		t.Run(c.name, func(t *testing.T) { runPattern(t, c) })
	}
}

func TestPatterns_ModulePaths(t *testing.T) {
	for _, c := range []patternCase{
		{
			name: "missing local module path",
			modules: map[string]string{"stack": `
module "gone" { source = "./does-not-exist" }
resource "aws_s3_bucket" "own" {}
`},
			want: []string{"aws_s3_bucket.own"},
		},
		{
			name: "unresolved remote module",
			modules: map[string]string{"stack": `
module "remote" { source = "terraform-aws-modules/s3-bucket/aws" }
`},
			want: nil,
		},
		{
			name: "cyclic module path",
			modules: map[string]string{
				"a":     "module \"b\" { source = \"../b\" }\nresource \"aws_s3_bucket\" \"a\" {}\n",
				"b":     "module \"a\" { source = \"../a\" }\nresource \"aws_s3_bucket\" \"b\" {}\n",
				"stack": `module "a" { source = "../a" }`,
			},
			// The instances outside the cycle resolve; the call closing it is
			// left as written.
			want: []string{"module.a.aws_s3_bucket.a", "module.a.module.b.aws_s3_bucket.b"},
		},
	} {
		t.Run(c.name, func(t *testing.T) { runPattern(t, c) })
	}
}

// Many roots calling one module each get their own instances. Identical
// inputs share one cached evaluation within a root but never an address.
func TestPatterns_RootsSharingAModule(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "leaf", map[string]string{"main.tf": passthroughLeaf})
	const roots = 20
	e := New()
	all := map[string]bool{}
	for i := range roots {
		dir := writeModule(t, root, fmt.Sprintf("r%02d", i), map[string]string{"main.tf": fmt.Sprintf(`
module "same" {
  source = "../leaf"
  count  = 3
  name   = "shared"
}
module "distinct" {
  source = "../leaf"
  name   = "root-%d"
}
`, i)})
		resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
		require.NoError(t, err)
		require.Len(t, resources, 4)
		for _, r := range resources {
			all[fmt.Sprintf("r%02d/%s", i, instanceAddress(&r))] = true
		}
		e.ReleaseEvalCache()
	}
	require.Len(t, all, roots*4)
	// Per root: the three identical instances share one entry, the distinct
	// call has its own, and the root module itself is one more.
	require.Equal(t, roots*3, e.Report().CacheEntries)
	require.Equal(t, roots*2, e.Report().CacheHits)
}
