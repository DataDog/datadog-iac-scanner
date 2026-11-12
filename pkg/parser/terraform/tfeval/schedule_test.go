/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// passThrough is a module returning its input, which a leaf call sets.
const passThrough = `
variable "in" {
  default = "unset"
}
output "out" {
  value = var.in
}
`

// scheduleRoot lays down the pass-through child as c0..c2 and a leaf c3
// returning "secure", then the root module with main.tf, and evaluates it.
func scheduleRoot(t *testing.T, main string) []ResolvedResource {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"c0", "c1", "c2"} {
		writeModule(t, root, name, map[string]string{"main.tf": passThrough})
	}
	writeModule(t, root, "leaf", map[string]string{"main.tf": "output \"out\" {\n  value = \"secure\"\n}\n"})
	dir := writeModule(t, root, "root", map[string]string{"main.tf": main})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	return resources
}

func requireAttrValue(t *testing.T, resources []ResolvedResource, typ, name, attr string, want cty.Value) {
	t.Helper()
	got := findResource(t, resources, typ, name).Attributes[attr]
	require.True(t, got.RawEquals(want), "%s.%s.%s = %#v, want %#v", typ, name, attr, got, want)
}

func requireAttrUnknown(t *testing.T, resources []ResolvedResource, typ, name, attr string) {
	t.Helper()
	got := findResource(t, resources, typ, name).Attributes[attr]
	require.False(t, got.IsKnown(), "%s.%s.%s = %#v, want unknown", typ, name, attr, got)
}

// A block runs after the blocks it reads, whatever the file order and the
// length of the chain: three module calls, each reading the next, resolve the
// same declared in either direction and through try.
func TestEvaluateModule_ModuleChainResolvesInAnyDeclarationOrder(t *testing.T) {
	forward := func(read string) string {
		return fmt.Sprintf(`
module "m0" {
  source = "../c0"
  in     = %[1]s
}
module "m1" {
  source = "../c1"
  in     = %[2]s
}
module "m2" {
  source = "../leaf"
}
resource "r" "x" {
  v = module.m0.out
}
`, fmt.Sprintf(read, "m1"), fmt.Sprintf(read, "m2"))
	}
	reverse := `
module "m2" {
  source = "../leaf"
}
module "m1" {
  source = "../c1"
  in     = module.m2.out
}
module "m0" {
  source = "../c0"
  in     = module.m1.out
}
resource "r" "x" {
  v = module.m0.out
}
`
	for name, main := range map[string]string{
		"forward":         forward("module.%s.out"),
		"forward in try":  forward(`try(module.%s.out, "fallback")`),
		"reverse":         reverse,
		"resource first":  "resource \"r\" \"x\" {\n  v = module.m0.out\n}\n" + forward("module.%s.out"),
		"forward through": forward(`"${module.%s.out}"`),
	} {
		t.Run(name, func(t *testing.T) {
			resources := scheduleRoot(t, main)
			requireAttrValue(t, resources, "r", "x", "v", cty.StringVal("secure"))
		})
	}
}

// Chains longer than any fixed number of passes resolve, forward and reverse.
func TestEvaluateModule_ResourceChainsOfAnyLengthResolve(t *testing.T) {
	const length = 12
	var forward, reverse []string
	for i := 0; i < length; i++ {
		value := fmt.Sprintf("r.n%d.v", i+1)
		if i == length-1 {
			value = `"secure"`
		}
		forward = append(forward, fmt.Sprintf("resource \"r\" \"n%d\" {\n  v = %s\n}\n", i, value))
	}
	for i := len(forward) - 1; i >= 0; i-- {
		reverse = append(reverse, forward[i])
	}
	for name, blocks := range map[string][]string{"forward": forward, "reverse": reverse} {
		t.Run(name, func(t *testing.T) {
			main := strings.Join(blocks, "") + "resource \"q\" \"z\" {\n  v = r.n0.v\n}\n"
			resources := scheduleRoot(t, main)
			requireAttrValue(t, resources, "q", "z", "v", cty.StringVal("secure"))
			requireAttrValue(t, resources, "r", "n0", "v", cty.StringVal("secure"))
		})
	}
}

// Resources and module calls depend on each other in both directions, and
// through locals and data blocks.
func TestEvaluateModule_DependenciesCrossResourcesModulesLocalsAndData(t *testing.T) {
	main := `
module "m0" {
  source = "../c0"
  in     = r.mid.v
}
resource "q" "z" {
  v = module.m0.out
}
resource "r" "mid" {
  v = local.from_module
}
locals {
  from_module = module.m1.out
}
module "m1" {
  source = "../c1"
  in     = local.late
}
locals {
  late = r.last.v
}
resource "r" "last" {
  v = data.d.x.v
}
data "d" "x" {
  v = "secure"
}
`
	resources := scheduleRoot(t, main)
	requireAttrValue(t, resources, "q", "z", "v", cty.StringVal("secure"))
	requireAttrValue(t, resources, "r", "mid", "v", cty.StringVal("secure"))
	requireAttrValue(t, resources, "r", "last", "v", cty.StringVal("secure"))
}

// A local refreshed for one block must not hide from a later block the
// resources evaluated since: the locals are refreshed against what was
// published, not against what was evaluated.
func TestEvaluateModule_LocalsFollowResourcesEvaluatedBetweenRefreshes(t *testing.T) {
	main := `
resource "r" "n4" {
  v = r.n2.v
}
resource "r" "n5" {
  v = local.n0
}
locals {
  n3 = "${r.n2.v}-${r.n2.v}"
}
resource "r" "n1" {
  v = local.n3
}
resource "r" "n2" {
  v = "b"
}
locals {
  n0 = "${r.n4.v}-x"
}
`
	resources := scheduleRoot(t, main)
	requireAttrValue(t, resources, "r", "n5", "v", cty.StringVal("b-x"))
	requireAttrValue(t, resources, "r", "n1", "v", cty.StringVal("b-b"))
}

// Results come back in file order, not in the order the blocks were run.
func TestEvaluateModule_ResultsKeepFileOrder(t *testing.T) {
	main := `
resource "r" "a" {
  v = r.c.v
}
resource "r" "b" {
  v = "b"
}
resource "r" "c" {
  v = r.b.v
}
`
	resources := scheduleRoot(t, main)
	var names []string
	for _, r := range resources {
		names = append(names, r.Name)
	}
	require.Equal(t, []string{"a", "b", "c"}, names)
}

// Blocks reading each other, which Terraform rejects, still evaluate and stop.
func TestEvaluateModule_CyclesTerminate(t *testing.T) {
	main := `
resource "r" "a" {
  v = r.b.v
}
resource "r" "b" {
  v = r.a.v
}
module "m0" {
  source = "../c0"
  in     = module.m1.out
}
module "m1" {
  source = "../c1"
  in     = module.m0.out
}
resource "r" "ok" {
  v = "ok"
}
`
	resources := scheduleRoot(t, main)
	requireAttrValue(t, resources, "r", "ok", "v", cty.StringVal("ok"))
	for _, name := range []string{"a", "b"} {
		requireAttrUnknown(t, resources, "r", name, "v")
	}
	require.Len(t, resources, 3, "a cycle must not duplicate the resources of its module calls")
}

// A module declaring an address twice, which Terraform rejects, is read as its
// first declaration, as it always was.
func TestEvaluateModule_DuplicateAddressReadsFirstDeclaration(t *testing.T) {
	main := `
resource "r" "dup" {
  v = "first"
}
resource "q" "z" {
  v = r.dup.v
}
resource "r" "dup" {
  v = "second"
}
`
	resources := scheduleRoot(t, main)
	requireAttrValue(t, resources, "q", "z", "v", cty.StringVal("first"))
}

// The first declaration is the one read even when it runs after the second.
func TestEvaluateModule_DuplicateAddressReadsFirstDeclarationWhateverTheOrderRun(t *testing.T) {
	main := `
resource "r" "dup" {
  v = q.late.v
}
resource "q" "late" {
  v = "first"
}
resource "r" "dup" {
  v = "second"
}
resource "q" "z" {
  v = r.dup.v
}
`
	resources := scheduleRoot(t, main)
	requireAttrValue(t, resources, "q", "z", "v", cty.StringVal("first"))
}

func TestUnitGraph_OrdersByWhatBlocksRead(t *testing.T) {
	src := `
module "m0" {
  source = "./c0"
  in     = r.b.v
}
resource "r" "a" {
  v = module.m0.out
}
resource "r" "b" {
  v = local.l
}
locals {
  l = r.c.v
}
resource "r" "c" {
  v = "c"
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	_, localExprs, modules, resources, _ := collectBlocks([]*hclsyntax.Body{file.Body.(*hclsyntax.Body)})
	g := newLocalGraph(localExprs, declaredResourceTypes(resources), nil)
	units := newUnitGraph(resources, modules, g)

	label := func(unit int) string {
		if unit < len(resources) {
			return resources[unit].Labels[1]
		}
		return blockLabel(modules[unit-len(resources)])
	}
	var order []string
	for i, component := range units.components {
		require.False(t, units.cyclic[i])
		order = append(order, label(component[0]))
	}
	require.Equal(t, []string{"c", "b", "m0", "a"}, order)
}

func TestUnitGraph_ReportsCycles(t *testing.T) {
	src := `
resource "r" "a" {
  v = r.b.v
}
resource "r" "b" {
  v = r.a.v
}
resource "r" "self" {
  v = r.self.v
}
resource "r" "free" {}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	_, localExprs, modules, resources, _ := collectBlocks([]*hclsyntax.Body{file.Body.(*hclsyntax.Body)})
	units := newUnitGraph(resources, modules, newLocalGraph(localExprs, declaredResourceTypes(resources), nil))
	cyclic := 0
	for i, component := range units.components {
		if units.cyclic[i] {
			cyclic += len(component)
		}
	}
	require.Equal(t, 3, cyclic)
}

// With a count of zero a block still denotes the empty collection, so what
// reads its length sees zero rather than a reference it cannot resolve.
func TestEvaluateModule_ZeroInstanceBlocksKeepTheirCollection(t *testing.T) {
	main := `
resource "r" "none" {
  count = 0
}
resource "r" "no_keys" {
  for_each = {}
}
resource "q" "z" {
  len_count = length(r.none)
  len_keys  = length(r.no_keys)
  can_len   = can(length(r.none))
  try_len   = try(length(r.none), 1)
  splat     = r.none[*].id
}
resource "d" "dependent" {
  count = try(length(r.none), 1)
}
resource "d" "dependent_each" {
  for_each = r.no_keys
}
`
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{"main.tf": main})
	e := New()
	resources, _, _, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	q := findResource(t, resources, "q", "z").Attributes
	require.True(t, q["len_count"].RawEquals(cty.NumberIntVal(0)), "%#v", q["len_count"])
	require.True(t, q["len_keys"].RawEquals(cty.NumberIntVal(0)), "%#v", q["len_keys"])
	require.True(t, q["can_len"].RawEquals(cty.True), "%#v", q["can_len"])
	require.True(t, q["try_len"].RawEquals(cty.NumberIntVal(0)), "%#v", q["try_len"])
	for _, r := range resources {
		require.NotEqual(t, "d", r.Type, "a block counting an empty block must expand to nothing, got %s", r.Name)
	}
	var names []string
	for _, b := range e.TakeEmptyBlocks() {
		names = append(names, b.Name)
	}
	require.ElementsMatch(t, []string{"none", "no_keys", "dependent", "dependent_each"}, names)
}

func TestEvaluateModule_ZeroInstanceDataKeepsItsCollection(t *testing.T) {
	main := `
data "d" "none" {
  count = 0
}
resource "q" "z" {
  len = length(data.d.none)
}
`
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{"main.tf": main})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	requireAttrValue(t, resources, "q", "z", "len", cty.NumberIntVal(0))
}

// An attribute a block does not set and that try, can, count or for_each read
// is unknown, as a computed attribute is, where a missing key falls through.
func TestEvaluateModule_UnsetResourceAttributesAreUnknownNotMissing(t *testing.T) {
	main := `
variable "cfg" {
  default = {}
}
resource "terraform_data" "src" {
  input = "in"
  tags  = { env = "prod" }
}
resource "q" "z" {
  try_attr    = try(terraform_data.src.output, "fallback")
  can_attr    = can(terraform_data.src.output)
  try_splat   = try(terraform_data.src[*].output, "fallback")
  set_attr    = try(terraform_data.src.input, "fallback")
  missing_key = try(terraform_data.src.tags.team, "fallback")
  missing_var = try(var.cfg.key, "fallback")
  can_var     = can(var.cfg.key)
}
resource "x" "each" {
  for_each = {
    a = terraform_data.src.output
    b = terraform_data.src.id
  }
}
resource "x" "counted" {
  count = length([terraform_data.src.output, terraform_data.src.id])
}
`
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{"main.tf": main})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)

	requireAttrUnknown(t, resources, "q", "z", "try_attr")
	requireAttrUnknown(t, resources, "q", "z", "can_attr")
	requireAttrUnknown(t, resources, "q", "z", "try_splat")
	requireAttrValue(t, resources, "q", "z", "set_attr", cty.StringVal("in"))
	requireAttrValue(t, resources, "q", "z", "missing_key", cty.StringVal("fallback"))
	requireAttrValue(t, resources, "q", "z", "missing_var", cty.StringVal("fallback"))
	requireAttrValue(t, resources, "q", "z", "can_var", cty.False)

	var each, counted []string
	for _, r := range resources {
		switch r.Type + "." + r.Label {
		case "x.each":
			each = append(each, r.Name)
		case "x.counted":
			counted = append(counted, r.Name)
		}
	}
	require.ElementsMatch(t, []string{`each["a"]`, `each["b"]`}, each,
		"keys that are known must expand even when their values are not")
	require.ElementsMatch(t, []string{"counted[0]", "counted[1]"}, counted)
}

// Reading an unset attribute outside try, can, count and for_each is not
// changed by the placeholders: the value is unknown there as it was.
func TestEvaluateModule_UnsetAttributeReadsOutsideTryStayUnresolved(t *testing.T) {
	main := `
resource "terraform_data" "src" {
  input = "in"
}
resource "q" "z" {
  plain = terraform_data.src.id
  tmpl  = "x-${terraform_data.src.id}"
  obj   = { known = "k", comp = terraform_data.src.id }
}
`
	root := t.TempDir()
	dir := writeModule(t, root, "root", map[string]string{"main.tf": main})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	z := findResource(t, resources, "q", "z")
	require.False(t, z.Attributes["plain"].IsKnown())
	require.False(t, z.Attributes["tmpl"].IsKnown())
	obj := z.Attributes["obj"]
	require.True(t, obj.GetAttr("known").RawEquals(cty.StringVal("k")))
	require.False(t, obj.GetAttr("comp").IsKnown())
}

func TestCollectReferencedAttrs(t *testing.T) {
	src := `
resource "a" "x" {
  count = length(b.y[*].id)
}
resource "a" "z" {
  for_each = { k = c.w.arn }
  v        = d.plain.not_recorded
  t        = try(e.f[0].name, can(data.g.h.value), module.m.out, ephemeral.i.j.secret)
}
`
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	got := collectReferencedAttrs([]*hclsyntax.Body{file.Body.(*hclsyntax.Body)})
	require.Equal(t, referencedAttrs{
		{refManaged, "b", "y"}:   {"id"},
		{refManaged, "c", "w"}:   {"arn"},
		{refManaged, "e", "f"}:   {"name"},
		{refData, "g", "h"}:      {"value"},
		{refEphemeral, "i", "j"}: {"secret"},
	}, got)
}
