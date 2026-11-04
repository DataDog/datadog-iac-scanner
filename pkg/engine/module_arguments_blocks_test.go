/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// moduleWithBlocks is a module scope whose files declare the given blocks.
func moduleWithBlocks(t *testing.T, vars map[string]cty.Value, files ...string) *tfeval.ModuleScope {
	t.Helper()
	scope := evaluatedScope(t, vars, "")
	for _, src := range files {
		file, diags := hclsyntax.ParseConfig([]byte(src), "module.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), diags.Error())
		body, ok := file.Body.(*hclsyntax.Body)
		require.True(t, ok)
		scope.Bodies = append(scope.Bodies, body)
	}
	return scope
}

// referencingResource reads the given expression on line 2 and is called with
// each argument on its own line after the source.
func referencingResource(t *testing.T, scope *tfeval.ModuleScope, expr, callArgs string) []model.ModuleArgument {
	t.Helper()
	return newModuleAttributionCache().resourceArguments(&tfeval.ResolvedResource{
		Body:      parseBlockBody(t, "resource \"t\" \"r\" {\n  attr = "+expr+"\n}"),
		Scope:     scope,
		CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n"+callArgs+"}"),
	}, "main.tf")
}

func TestModuleArgumentsFollowReferencesToOtherResources(t *testing.T) {
	scope := moduleWithBlocks(t,
		map[string]cty.Value{"acl": cty.StringVal("public-read"), "name": cty.StringVal("b")},
		`resource "aws_s3_bucket" "a" {
  acl    = var.acl
  bucket = "fixed"
}`)
	const call = "  acl  = \"public-read\"\n  name = \"b\"\n"

	t.Run("an attribute the block sets from an input is the caller's", func(t *testing.T) {
		requireCallerAt(t, referencingResource(t, scope, "aws_s3_bucket.a.acl", call), 2, 3)
	})
	t.Run("through an index of the block", func(t *testing.T) {
		requireCallerAt(t, referencingResource(t, scope, "aws_s3_bucket.a[0].acl", call), 2, 3)
		requireCallerAt(t, referencingResource(t, scope, `aws_s3_bucket.a["k"].acl`, call), 2, 3)
	})
	t.Run("an attribute the block sets itself is the module's", func(t *testing.T) {
		requireControlAt(t, referencingResource(t, scope, "aws_s3_bucket.a.bucket", call), 2, model.ArgumentControlModule)
	})
	t.Run("an attribute the block computes is the module's", func(t *testing.T) {
		requireControlAt(t, referencingResource(t, scope, "aws_s3_bucket.a.id", call), 2, model.ArgumentControlModule)
	})
	t.Run("a block of another name is not read", func(t *testing.T) {
		requireControlAt(t, referencingResource(t, scope, "aws_s3_bucket.other.acl", call), 2, model.ArgumentControlModule)
	})
	t.Run("mixed with an input of its own", func(t *testing.T) {
		requireControlAt(t, referencingResource(t, scope, `"${var.name}-${aws_s3_bucket.a.acl}"`, call), 2, model.ArgumentControlUnknown)
	})
}

func TestModuleArgumentsFollowNestedAndDynamicBlocks(t *testing.T) {
	scope := moduleWithBlocks(t,
		map[string]cty.Value{"cidrs": cty.ListVal([]cty.Value{cty.StringVal("10.0.0.0/8")}), "n": cty.NumberIntVal(1)},
		`resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = var.cidrs
  }
}
resource "aws_security_group" "dyn" {
  dynamic "egress" {
    for_each = var.cidrs
    content {
      cidr_blocks = [egress.value]
    }
  }
}
resource "aws_instance" "counted" {
  count = var.n
  name  = "x"
}`)
	const call = "  cidrs = [\"10.0.0.0/8\"]\n  n     = 1\n"

	requireCallerAt(t, referencingResource(t, scope, "aws_security_group.sg.ingress", call), 2, 3)
	requireCallerAt(t, referencingResource(t, scope, "aws_security_group.dyn.egress", call), 2, 3)
	t.Run("what expands the block is read too", func(t *testing.T) {
		requireCallerAt(t, referencingResource(t, scope, "aws_instance.counted[0].name", call), 2, 4)
	})
}

func TestModuleArgumentsFollowDataSourcesThroughComputedAttributes(t *testing.T) {
	scope := moduleWithBlocks(t,
		map[string]cty.Value{"actions": cty.ListVal([]cty.Value{cty.StringVal("s3:*")})},
		`data "aws_iam_policy_document" "doc" {
  statement {
    actions = var.actions
  }
}`)
	const call = "  actions = [\"s3:*\"]\n"
	requireCallerAt(t, referencingResource(t, scope, "data.aws_iam_policy_document.doc.json", call), 2, 3)
	requireControlAt(t, referencingResource(t, scope, "data.aws_iam_policy_document.missing.json", call), 2, model.ArgumentControlModule)
}

func TestModuleArgumentsReferencesBetweenBlocksTerminate(t *testing.T) {
	scope := moduleWithBlocks(t,
		map[string]cty.Value{"x": cty.StringVal("v")},
		`resource "aws_a" "a" {
  attr = aws_b.b.attr
}
resource "aws_b" "b" {
  attr = "${aws_a.a.attr}${var.x}"
}
resource "aws_c" "self" {
  attr = aws_c.self.attr
}`)
	const call = "  x = \"v\"\n"
	require.NotPanics(t, func() {
		requireCallerAt(t, referencingResource(t, scope, "aws_a.a.attr", call), 2, 3)
		referencingResource(t, scope, "aws_c.self.attr", call)
	})
}

func TestModuleArgumentsFollowBracketAttributeAccess(t *testing.T) {
	scope := moduleWithBlocks(t,
		map[string]cty.Value{"acl": cty.StringVal("public-read"), "n": cty.NumberIntVal(1)},
		`resource "aws_s3_bucket" "a" {
  acl    = var.acl
  bucket = "fixed"
}
resource "aws_s3_bucket" "many" {
  count = var.n
  acl   = "private"
}`)
	const call = "  acl = \"public-read\"\n  n   = 1\n"

	t.Run("a bracketed computed attribute is not the caller's", func(t *testing.T) {
		requireControlAt(t, referencingResource(t, scope, `aws_s3_bucket.a["id"]`, call), 2, model.ArgumentControlModule)
		requireControlAt(t, referencingResource(t, scope, `aws_s3_bucket.a[0]["id"]`, call), 2, model.ArgumentControlModule)
	})
	t.Run("a bracketed attribute set from an input is the caller's", func(t *testing.T) {
		requireCallerAt(t, referencingResource(t, scope, `aws_s3_bucket.a["acl"]`, call), 2, 3)
	})
	t.Run("an expanded block reads what expands it", func(t *testing.T) {
		requireCallerAt(t, referencingResource(t, scope, `aws_s3_bucket.many[0]["acl"]`, call), 2, 4)
	})
}

func evaluateReferences(t *testing.T, files map[string]string) []tfeval.ResolvedResource {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		writeFile(t, filepath.Join(root, filepath.Dir(name)), filepath.Base(name), content)
	}
	resources, _, _, err := tfeval.New().EvaluateModule(context.Background(), root, nil)
	require.NoError(t, err)
	return resources
}

func resolvedAddress(r *tfeval.ResolvedResource) string {
	kind := address.KindResource
	switch {
	case r.Data:
		kind = address.KindData
	case r.Ephemeral:
		kind = address.KindEphemeral
	}
	return address.Instance(r.ModuleAddress, address.Block{Kind: kind, Type: r.Type, Name: r.BaseName}, r.Key.String())
}

// referencesOf returns the references of the instance at addr, checking that
// every address it lists is one of an evaluated instance.
func referencesOf(t *testing.T, resources []tfeval.ResolvedResource, addr string) map[string]interface{} {
	t.Helper()
	addresses := map[string]bool{}
	for i := range resources {
		addresses[resolvedAddress(&resources[i])] = true
	}
	for i := range resources {
		r := &resources[i]
		if resolvedAddress(r) != addr {
			continue
		}
		refs, _ := staticReferences(r, newModuleAttributionCache().analyzer(r.Scope, r.Iteration))
		var check func(v interface{})
		check = func(v interface{}) {
			switch v := v.(type) {
			case map[string]interface{}:
				for _, item := range v {
					check(item)
				}
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						require.True(t, addresses[s], "%s is not an evaluated instance", s)
						continue
					}
					check(item)
				}
			}
		}
		check(refs)
		return refs
	}
	t.Fatalf("no instance %s", addr)
	return nil
}

// ambiguityOf returns the _dd_meta.ambiguous of the instance at addr.
func ambiguityOf(t *testing.T, resources []tfeval.ResolvedResource, addr string) map[string]interface{} {
	t.Helper()
	for i := range resources {
		r := &resources[i]
		if resolvedAddress(r) == addr {
			_, ambiguous := staticReferences(r, newModuleAttributionCache().analyzer(r.Scope, r.Iteration))
			return ambiguous
		}
	}
	t.Fatalf("no instance %s", addr)
	return nil
}

func addrs(a ...string) []interface{} {
	out := make([]interface{}, len(a))
	for i, s := range a {
		out[i] = s
	}
	return out
}

func TestStaticReferencesDirectRead(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_subnet" "s" {
  cidr_block = "10.0.0.0/24"
}
resource "aws_route_table_association" "a" {
  subnet_id = aws_subnet.s.id
  name      = "a"
}
`})
	require.Equal(t, map[string]interface{}{"subnet_id": addrs("aws_subnet.s"), "name": addrs()},
		referencesOf(t, resources, "aws_route_table_association.a"))
}

func TestStaticReferencesCountIndexAndLiteralIndex(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_subnet" "s" {
  count = 3
}
resource "aws_route_table_association" "a" {
  count     = 3
  subnet_id = aws_subnet.s[count.index].id
  fixed     = aws_subnet.s[1].id
}
`})
	require.Equal(t, map[string]interface{}{
		"subnet_id": addrs("aws_subnet.s[2]"),
		"fixed":     addrs("aws_subnet.s[1]"),
	}, referencesOf(t, resources, "aws_route_table_association.a[2]"))
}

func TestStaticReferencesDynamicIndexListsEveryInstance(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
variable "i" {}
variable "j" {
  default = 1
}
resource "aws_subnet" "s" {
  count = 3
}
resource "aws_route_table_association" "a" {
  subnet_id = aws_subnet.s[var.i].id
  all       = aws_subnet.s[*].id
  chosen    = aws_subnet.s[var.j].id
}
`})
	every := addrs("aws_subnet.s[0]", "aws_subnet.s[1]", "aws_subnet.s[2]")
	require.Equal(t, map[string]interface{}{"subnet_id": every, "all": every, "chosen": addrs("aws_subnet.s[1]")},
		referencesOf(t, resources, "aws_route_table_association.a"))
}

func TestStaticReferencesEachAndConditional(t *testing.T) {
	files := func(on string) map[string]string {
		return map[string]string{"main.tf": `
variable "on" {` + on + `}
resource "aws_subnet" "s" {
  for_each = toset(["a", "b"])
}
resource "aws_route_table_association" "each" {
  for_each  = toset(["a", "b"])
  subnet_id = aws_subnet.s[each.key].id
}
resource "aws_route_table_association" "choice" {
  subnet_id = var.on ? aws_subnet.s["a"].id : aws_subnet.s["b"].id
}
`}
	}
	resources := evaluateReferences(t, files("\n  default = true\n"))
	require.Equal(t, map[string]interface{}{"subnet_id": addrs(`aws_subnet.s["a"]`)},
		referencesOf(t, resources, `aws_route_table_association.each["a"]`))
	require.Equal(t, map[string]interface{}{"subnet_id": addrs(`aws_subnet.s["a"]`)},
		referencesOf(t, resources, "aws_route_table_association.choice"))

	resources = evaluateReferences(t, files(""))
	require.Equal(t, map[string]interface{}{"subnet_id": addrs(`aws_subnet.s["a"]`, `aws_subnet.s["b"]`)},
		referencesOf(t, resources, "aws_route_table_association.choice"))
}

func TestStaticReferencesLeaveOutWhatOnlySelectsTheValue(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_subnet" "s" {
  count = 2
}
resource "aws_iam_role" "source" {
  name = "source"
}
resource "aws_iam_role" "other" {
  name = "other"
}
resource "aws_iam_role_policy_attachment" "a" {
  condition = length(aws_iam_role.other.name) > 0 ? aws_iam_role.source.name : aws_iam_role.source.id
  filtered  = [for r in [aws_iam_role.source] : r.name if r.name != aws_iam_role.other.name]
  indexed   = aws_subnet.s[length(aws_iam_role.other.name)].id
}
`})
	require.Equal(t, map[string]interface{}{
		"condition": addrs("aws_iam_role.source"),
		"filtered":  addrs("aws_iam_role.source"),
		"indexed":   addrs("aws_subnet.s[0]", "aws_subnet.s[1]"),
	}, referencesOf(t, resources, "aws_iam_role_policy_attachment.a"))
	require.Equal(t, map[string]interface{}{"indexed": true},
		ambiguityOf(t, resources, "aws_iam_role_policy_attachment.a"))
}

func TestStaticReferencesNestedBlockAndDataEphemeral(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
data "aws_ip_ranges" "r" {
  services = ["ec2"]
}
ephemeral "random_password" "p" {
  length = 8
}
resource "aws_security_group" "g" {
  name = "g"
  egress {
    from_port = 0
  }
  ingress {
    cidr_blocks = data.aws_ip_ranges.r.cidr_blocks
  }
  dynamic "rule" {
    for_each = ["x"]
    content {
      cidr = data.aws_ip_ranges.r.cidr_blocks
      name = rule.value
    }
  }
  password = ephemeral.random_password.p.result
}
`})
	require.Equal(t, map[string]interface{}{
		"name":     addrs(),
		"egress":   []interface{}{map[string]interface{}{"from_port": addrs()}},
		"ingress":  []interface{}{map[string]interface{}{"cidr_blocks": addrs("data.aws_ip_ranges.r")}},
		"rule":     []interface{}{map[string]interface{}{"cidr": addrs("data.aws_ip_ranges.r"), "name": addrs()}},
		"password": addrs("ephemeral.random_password.p"),
	}, referencesOf(t, resources, "aws_security_group.g"))
}

func TestStaticReferencesInModuleCarryItsAddress(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{
		"main.tf": `
module "net" {
  source = "./net"
}
`,
		"net/main.tf": `
resource "aws_subnet" "s" {
  count = 2
}
resource "aws_route_table_association" "a" {
  count     = 2
  subnet_id = aws_subnet.s[count.index].id
}
`,
	})
	require.Equal(t, map[string]interface{}{"subnet_id": addrs("module.net.aws_subnet.s[1]")},
		referencesOf(t, resources, "module.net.aws_route_table_association.a[1]"))
}

func TestStaticReferencesEmptyWithoutReads(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
variable "x" {}
resource "aws_subnet" "literal" {
  cidr_block = "10.0.0.0/24"
}
resource "aws_subnet" "input" {
  cidr_block = var.x
  missing    = aws_vpc.undeclared.id
}
`})
	require.Equal(t, map[string]interface{}{"cidr_block": addrs()}, referencesOf(t, resources, "aws_subnet.literal"))
	require.Equal(t, map[string]interface{}{"cidr_block": addrs()},
		referencesOf(t, resources, "aws_subnet.input"),
		"a read of an undeclared block is untraced, not a read of nothing")
}

func TestStaticReferencesUndeclaredModuleReadsNothing(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "azurerm_subnet_network_security_group_association" "a" {
  subnet_id = module.network.subnet_id
}
`})
	require.Equal(t, map[string]interface{}{"subnet_id": addrs()},
		referencesOf(t, resources, "azurerm_subnet_network_security_group_association.a"))
}

func TestStaticReferencesUnfetchedModuleStaysUntraced(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
module "network" {
  source = "./missing"
}
resource "azurerm_subnet_network_security_group_association" "a" {
  subnet_id = module.network.subnet_id
}
`})
	refs := referencesOf(t, resources, "azurerm_subnet_network_security_group_association.a")
	_, traced := refs["subnet_id"]
	require.False(t, traced, "an unresolved module call is untraced, so its references key is absent")
}

func TestStaticReferencesThroughLocals(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_vpc" "v" {}
resource "aws_subnet" "s" {
  count = 2
}
locals {
  ids   = aws_subnet.s[*].id
  outer = local.inner
  inner = aws_vpc.v.id
}
resource "aws_route_table_association" "a" {
  count     = 2
  subnet_id = local.ids[count.index]
  fixed     = local.ids[0]
  all       = local.ids
  vpc       = local.outer
}
`})
	require.Equal(t, map[string]interface{}{
		"subnet_id": addrs("aws_subnet.s[1]"),
		"fixed":     addrs("aws_subnet.s[0]"),
		"all":       addrs("aws_subnet.s[0]", "aws_subnet.s[1]"),
		"vpc":       addrs("aws_vpc.v"),
	}, referencesOf(t, resources, "aws_route_table_association.a[1]"))
}

func TestStaticReferencesThroughVariables(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{
		"main.tf": `
resource "aws_network_security_group" "g" {}
resource "aws_subnet" "s" {
  count = 2
}
module "net" {
  source  = "./net"
  nsg_id  = aws_network_security_group.g.id
  subnets = aws_subnet.s[*].id
}
`,
		"net/main.tf": `
variable "nsg_id" {}
variable "subnets" {}
resource "aws_network_security_group_association" "a" {
  nsg = var.nsg_id
}
module "leaf" {
  source  = "../leaf"
  nsg     = var.nsg_id
  subnets = var.subnets
}
`,
		"leaf/main.tf": `
variable "nsg" {}
variable "subnets" {}
resource "aws_network_security_group_association" "b" {
  count  = 2
  nsg    = var.nsg
  subnet = var.subnets[count.index]
}
`,
	})
	require.Equal(t, map[string]interface{}{"nsg": addrs("aws_network_security_group.g")},
		referencesOf(t, resources, "module.net.aws_network_security_group_association.a"))
	require.Equal(t, map[string]interface{}{
		"nsg":    addrs("aws_network_security_group.g"),
		"subnet": addrs("aws_subnet.s[0]", "aws_subnet.s[1]"),
	}, referencesOf(t, resources, "module.net.module.leaf.aws_network_security_group_association.b[1]"))
}

func TestStaticReferencesThroughModuleOutputs(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{
		"main.tf": `
variable "i" {}
module "net" {
  count  = 2
  source = "./net"
}
module "a" {
  source = "./net"
}
module "b" {
  source = "./net"
}
resource "aws_route_table_association" "r" {
  first   = module.net[0].subnet_id
  any     = module.net[var.i].subnet_id
  nested  = module.net[1].inner_id
  other   = module.b.subnet_id
}
`,
		"net/main.tf": `
resource "aws_subnet" "s" {}
module "inner" {
  source = "../inner"
}
output "subnet_id" {
  value = aws_subnet.s.id
}
output "inner_id" {
  value = module.inner.id
}
`,
		"inner/main.tf": `
resource "aws_vpc" "v" {}
output "id" {
  value = aws_vpc.v.id
}
`,
	})
	require.Equal(t, map[string]interface{}{
		"first":  addrs("module.net[0].aws_subnet.s"),
		"any":    addrs("module.net[0].aws_subnet.s", "module.net[1].aws_subnet.s"),
		"nested": addrs("module.net[1].module.inner.aws_vpc.v"),
		"other":  addrs("module.b.aws_subnet.s"),
	}, referencesOf(t, resources, "aws_route_table_association.r"))
}

func TestStaticReferencesCyclesTerminate(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{
		"main.tf": `
resource "aws_vpc" "v" {}
locals {
  a = [local.b, aws_vpc.v.id]
  b = local.a
}
module "m" {
  source = "./m"
  x      = module.m.out
}
resource "aws_route_table_association" "r" {
  vpc = local.b
  out = module.m.out
}
`,
		"m/main.tf": `
variable "x" {
  default = null
}
resource "aws_subnet" "s" {}
output "out" {
  value = [var.x, aws_subnet.s.id]
}
`,
	})
	require.Equal(t, map[string]interface{}{
		"vpc": addrs("aws_vpc.v"),
		"out": addrs("module.m.aws_subnet.s"),
	}, referencesOf(t, resources, "aws_route_table_association.r"))
}

func TestStaticReferencesOmitPartlyTracedAttributes(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
variable "unset" {}
variable "given" {
  default = "subnet-1"
}
resource "aws_subnet" "a" {}
module "empty" {
  source = "./missing"
}
locals {
  partial = coalesce(var.unset, aws_subnet.a.id)
}
resource "aws_route_table_association" "r" {
  via     = local.partial
  unset   = coalesce(var.unset, aws_subnet.a.id)
  output  = concat([aws_subnet.a.id], module.empty.ids)
  local   = concat([aws_subnet.a.id], local.missing)
  given   = concat([aws_subnet.a.id], [var.given])
  literal = "x"
  traced  = aws_subnet.a.id
}
`})
	require.Equal(t, map[string]interface{}{
		"via":     addrs("aws_subnet.a"),
		"unset":   addrs("aws_subnet.a"),
		"given":   addrs("aws_subnet.a"),
		"literal": addrs(),
		"traced":  addrs("aws_subnet.a"),
	}, referencesOf(t, resources, "aws_route_table_association.r"))
	require.Equal(t, map[string]interface{}{"via": true, "unset": true},
		ambiguityOf(t, resources, "aws_route_table_association.r"))
}

func TestStaticReferencesIndexOnComputedCollectionListsEveryInstance(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
variable "on" {
  default = true
}
variable "k" {
  default = 1
}
resource "aws_subnet" "a" {
  count = 2
}
resource "aws_subnet" "b" {
  count = 3
}
resource "aws_route_table_association" "r" {
  concat      = concat(aws_subnet.b[*].id, aws_subnet.a[*].id)[var.k]
  reverse     = reverse(aws_subnet.a[*].id)[var.k]
  for         = [for s in aws_subnet.a : s.id][var.k]
  conditional = (var.on ? aws_subnet.a : aws_subnet.b)[var.k].id
  direct      = (aws_subnet.b)[var.k].id
  splat       = (aws_subnet.b[*].id)[var.k]
}
`})
	allA := addrs("aws_subnet.a[0]", "aws_subnet.a[1]")
	require.Equal(t, map[string]interface{}{
		"concat":      addrs("aws_subnet.a[0]", "aws_subnet.a[1]", "aws_subnet.b[0]", "aws_subnet.b[1]", "aws_subnet.b[2]"),
		"reverse":     allA,
		"for":         allA,
		"conditional": allA,
		"direct":      addrs("aws_subnet.b[1]"),
		"splat":       addrs("aws_subnet.b[1]"),
	}, referencesOf(t, resources, "aws_route_table_association.r"))
}

func TestStaticReferencesSelectOnlyExistingInstances(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
variable "i" {
  default = "1"
}
variable "k" {
  default = "a"
}
variable "z" {
  default = "z"
}
resource "aws_subnet" "s" {
  count = 3
}
resource "aws_subnet" "f" {
  for_each = toset(["a", "b"])
}
locals {
  ids = aws_subnet.s[*].id
}
resource "aws_route_table_association" "r" {
  string_number = aws_subnet.s[var.i].id
  through_local = local.ids[var.i]
  missing       = aws_subnet.s[7].id
  key           = aws_subnet.f[var.k].id
  missing_key   = aws_subnet.f[var.z].id
}
`})
	require.Equal(t, map[string]interface{}{
		"string_number": addrs("aws_subnet.s[1]"),
		"through_local": addrs("aws_subnet.s[1]"),
		"missing":       addrs("aws_subnet.s[0]", "aws_subnet.s[1]", "aws_subnet.s[2]"),
		"key":           addrs(`aws_subnet.f["a"]`),
		"missing_key":   addrs(`aws_subnet.f["a"]`, `aws_subnet.f["b"]`),
	}, referencesOf(t, resources, "aws_route_table_association.r"))
}

func TestStaticReferencesThroughEachValue(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{
		"main.tf": `
variable "unset" {}
resource "aws_vpc" "v" {}
resource "aws_subnet" "s" {
  for_each = toset(["a", "b", "c"])
}
resource "aws_route_table_association" "unknown" {
  for_each = var.unset
  vpc      = concat([aws_vpc.v.id], [each.value])
}
locals {
  cidrs = { x = "10.0.0.0/24" }
}
resource "aws_route_table_association" "each" {
  for_each  = aws_subnet.s
  subnet_id = each.value.id
}
resource "aws_route_table_association" "built" {
  for_each  = { for k, s in aws_subnet.s : k => s }
  subnet_id = each.value.id
}
resource "aws_route_table_association" "literal" {
  for_each = local.cidrs
  vpc      = concat([aws_vpc.v.id], [each.value])
  cidr     = each.value
}
module "m" {
  for_each = aws_subnet.s
  source   = "./m"
  subnet   = each.value.id
}
`,
		"m/main.tf": `
variable "subnet" {}
resource "aws_route_table_association" "a" {
  subnet_id = var.subnet
}
`,
	})
	every := addrs(`aws_subnet.s["a"]`, `aws_subnet.s["b"]`, `aws_subnet.s["c"]`)
	for _, key := range []string{"a", "b", "c"} {
		require.Equal(t, map[string]interface{}{"subnet_id": addrs(`aws_subnet.s["` + key + `"]`)},
			referencesOf(t, resources, `aws_route_table_association.each["`+key+`"]`))
		require.Equal(t, map[string]interface{}{"subnet_id": addrs(`aws_subnet.s["` + key + `"]`)},
			referencesOf(t, resources, `module.m["`+key+`"].aws_route_table_association.a`))
	}
	require.Equal(t, map[string]interface{}{"subnet_id": every},
		referencesOf(t, resources, `aws_route_table_association.built["b"]`))
	require.Equal(t, map[string]interface{}{"subnet_id": true},
		ambiguityOf(t, resources, `aws_route_table_association.built["b"]`))
	require.Nil(t, ambiguityOf(t, resources, `aws_route_table_association.each["b"]`))
	require.Equal(t, map[string]interface{}{"vpc": addrs("aws_vpc.v"), "cidr": addrs()},
		referencesOf(t, resources, `aws_route_table_association.literal["x"]`))
	require.Equal(t, map[string]interface{}{"vpc": addrs("aws_vpc.v")},
		referencesOf(t, resources, "aws_route_table_association.unknown"))
}

func TestStaticReferencesResolveInstancesOncePerBlock(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
variable "i" {}
resource "aws_subnet" "s" {
  count = 2
}
resource "aws_route_table_association" "a" {
  count     = 2
  subnet_id = aws_subnet.s[var.i].id
  all       = aws_subnet.s[*].id
}
`})
	c := newModuleAttributionCache()
	for i := range resources {
		c.resourceReferences(&resources[i])
	}
	require.Len(t, c.blockInstances, 1)
	for _, instances := range c.blockInstances {
		require.Equal(t, []string{"[0]", "[1]"}, instances.suffixes)
	}
}

func TestStaticReferencesPartialCallChainNotReused(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{
		"main.tf": `
resource "aws_network_security_group" "g" {}
resource "aws_vpc" "v" {
  cidr_block = "10.0.0.0/16"
}
module "net" {
  source = "./net"
  nsg_id = aws_network_security_group.g.id
  cidr   = aws_vpc.v.cidr_block
}
`,
		"net/main.tf": `
variable "nsg_id" {}
variable "cidr" {}
locals {
  nsg = var.nsg_id
}
resource "aws_network_security_group_association" "a" {
  nsg = local.nsg
}
resource "aws_subnet" "s" {}
resource "aws_route" "r" {
  known = concat([aws_subnet.s.id], [var.cidr])
}
`,
	})
	c := newModuleAttributionCache()
	for _, tc := range []struct {
		typ  string
		want map[string]interface{}
	}{
		{"aws_network_security_group_association", map[string]interface{}{"nsg": addrs("aws_network_security_group.g")}},
		{"aws_route", map[string]interface{}{"known": addrs("aws_vpc.v", "module.net.aws_subnet.s")}},
	} {
		i := slices.IndexFunc(resources, func(r tfeval.ResolvedResource) bool { return r.Type == tc.typ })
		require.GreaterOrEqual(t, i, 0)
		partial := resources[i]
		partial.CallChain = nil
		partialRefs, _ := c.resourceReferences(&partial)
		require.Equal(t, map[string]interface{}{}, partialRefs, tc.typ,
			"a partial call chain traces nothing usable")
		refs, _ := c.resourceReferences(&resources[i])
		require.Equal(t, tc.want, refs, tc.typ)
	}
}

func TestStaticReferencesAmbiguousOnlyWhenOverApproximated(t *testing.T) {
	files := func(on string) map[string]string {
		return map[string]string{"main.tf": `
variable "on" {` + on + `}
variable "i" {}
resource "aws_subnet" "s" {
  count = 2
}
resource "aws_subnet" "one" {}
resource "aws_route_table_association" "a" {
  count     = 2
  pinned    = aws_subnet.s[count.index].id
  literal   = aws_subnet.s[1].id
  all       = aws_subnet.s[*].id
  dynamic   = aws_subnet.s[var.i].id
  single    = aws_subnet.one.id
  choice    = var.on ? aws_subnet.s[0].id : aws_subnet.one.id
  same      = var.on ? aws_subnet.one.id : aws_subnet.one.arn
  none      = var.i
}
`}
	}
	resources := evaluateReferences(t, files("\n  default = true\n"))
	require.Equal(t, map[string]interface{}{
		"pinned":  addrs("aws_subnet.s[1]"),
		"literal": addrs("aws_subnet.s[1]"),
		"all":     addrs("aws_subnet.s[0]", "aws_subnet.s[1]"),
		"dynamic": addrs("aws_subnet.s[0]", "aws_subnet.s[1]"),
		"single":  addrs("aws_subnet.one"),
		"choice":  addrs("aws_subnet.s[0]"),
		"same":    addrs("aws_subnet.one"),
		"none":    addrs(),
	}, referencesOf(t, resources, "aws_route_table_association.a[1]"))
	require.Equal(t, map[string]interface{}{"dynamic": true},
		ambiguityOf(t, resources, "aws_route_table_association.a[1]"))

	resources = evaluateReferences(t, files(""))
	require.Equal(t, addrs("aws_subnet.one", "aws_subnet.s[0]"),
		referencesOf(t, resources, "aws_route_table_association.a[1]")["choice"])
	require.Equal(t, map[string]interface{}{"dynamic": true, "choice": true},
		ambiguityOf(t, resources, "aws_route_table_association.a[1]"))
}

func TestStaticReferencesLiteralKeyIntoLocalConstructor(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{
		"main.tf": `
resource "aws_subnet" "a" {}
resource "aws_subnet" "b" {}
locals {
  by_name = {
    a = aws_subnet.a.id
    b = aws_subnet.b.id
  }
  ordered = [aws_subnet.a.id, aws_subnet.b.id]
}
module "m" {
  source  = "./m"
  subnets = { a = aws_subnet.a.id, b = aws_subnet.b.id }
}
resource "aws_route_table_association" "r" {
  indexed  = local.by_name["a"]
  attr     = local.by_name.b
  position = local.ordered[1]
  whole    = local.by_name
}
`,
		"m/main.tf": `
variable "subnets" {}
resource "aws_route_table_association" "inner" {
  subnet_id = var.subnets["b"]
}
`,
	})
	require.Equal(t, map[string]interface{}{
		"indexed":  addrs("aws_subnet.a"),
		"attr":     addrs("aws_subnet.b"),
		"position": addrs("aws_subnet.b"),
		"whole":    addrs("aws_subnet.a", "aws_subnet.b"),
	}, referencesOf(t, resources, "aws_route_table_association.r"))
	require.Nil(t, ambiguityOf(t, resources, "aws_route_table_association.r"))
	require.Equal(t, map[string]interface{}{"subnet_id": addrs("aws_subnet.b")},
		referencesOf(t, resources, "module.m.aws_route_table_association.inner"))
}

func TestStaticReferencesFollowsTheRestOfASelection(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_subnet" "a" {}
resource "aws_subnet" "b" {}
locals {
  nested = {
    x = {
      selected = aws_subnet.a.id
      other    = aws_subnet.b.id
    }
  }
}
resource "aws_route_table_association" "r" {
  subnet_id = local.nested.x.selected
}
`})
	require.Equal(t, map[string]interface{}{"subnet_id": addrs("aws_subnet.a")},
		referencesOf(t, resources, "aws_route_table_association.r"))
	require.Nil(t, ambiguityOf(t, resources, "aws_route_table_association.r"))
}

func TestStaticReferencesDynamicIteratorReadsItsCollection(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_security_group" "a" { name = "a" }
resource "aws_security_group" "b" { name = "b" }
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = toset([aws_security_group.a.name, aws_security_group.b.name])
    content {
      description = ingress.value
    }
  }
}
`})
	both := addrs("aws_security_group.a", "aws_security_group.b")
	require.Equal(t, map[string]interface{}{
		"ingress": []interface{}{
			map[string]interface{}{"description": both},
			map[string]interface{}{"description": both},
		},
	}, referencesOf(t, resources, "aws_security_group.sg"))
	require.Equal(t, map[string]interface{}{
		"ingress": []interface{}{
			map[string]interface{}{"description": true},
			map[string]interface{}{"description": true},
		},
	}, ambiguityOf(t, resources, "aws_security_group.sg"))
}

func TestStaticReferencesRootForEachResolvesEachValue(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_iam_policy" "a" {}
resource "aws_iam_policy" "b" {}
resource "aws_iam_role_policy_attachment" "r" {
  for_each   = { a = true, b = false }
  policy_arn = each.value ? aws_iam_policy.a.arn : aws_iam_policy.b.arn
}
`})
	require.Equal(t, map[string]interface{}{"policy_arn": addrs("aws_iam_policy.a")},
		referencesOf(t, resources, `aws_iam_role_policy_attachment.r["a"]`))
	require.Nil(t, ambiguityOf(t, resources, `aws_iam_role_policy_attachment.r["a"]`))
	require.Equal(t, map[string]interface{}{"policy_arn": addrs("aws_iam_policy.b")},
		referencesOf(t, resources, `aws_iam_role_policy_attachment.r["b"]`))
}

func TestStaticReferencesRootCountResolvesCountIndex(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
resource "aws_iam_policy" "a" {}
resource "aws_iam_policy" "b" {}
resource "aws_iam_role_policy_attachment" "r" {
  count      = 2
  policy_arn = count.index == 0 ? aws_iam_policy.a.arn : aws_iam_policy.b.arn
}
`})
	require.Equal(t, map[string]interface{}{"policy_arn": addrs("aws_iam_policy.a")},
		referencesOf(t, resources, "aws_iam_role_policy_attachment.r[0]"))
	require.Equal(t, map[string]interface{}{"policy_arn": addrs("aws_iam_policy.b")},
		referencesOf(t, resources, "aws_iam_role_policy_attachment.r[1]"))
	require.Nil(t, ambiguityOf(t, resources, "aws_iam_role_policy_attachment.r[0]"))
}

func TestStaticReferencesUnexpandedDynamicStaysUntraced(t *testing.T) {
	resources := evaluateReferences(t, map[string]string{"main.tf": `
variable "rules" {}
resource "aws_security_group" "a" { name = "a" }
resource "aws_security_group" "sg" {
  name = aws_security_group.a.name
  dynamic "ingress" {
    for_each = var.rules
    content {
      description = ingress.value
    }
  }
}
`})
	refs := referencesOf(t, resources, "aws_security_group.sg")
	require.Equal(t, addrs("aws_security_group.a"), refs["name"])
	require.NotContains(t, refs, "ingress", "an unexpanded dynamic block must not look traced")
}
