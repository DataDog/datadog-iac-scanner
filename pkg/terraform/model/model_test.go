/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func load(t *testing.T, files map[string]string) *Scan {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := Load(context.Background(), dir, Options{})
	require.NoError(t, err)
	return scan
}

func rootByID(t *testing.T, s *Scan, id string) *Root {
	t.Helper()
	for _, r := range s.Roots {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no root %q", id)
	return nil
}

func blocksOf(r *Root, kind, typ string) []*Block {
	var out []*Block
	for _, m := range r.Modules {
		for _, b := range m.Blocks {
			if b.Kind == kind && b.Type == typ {
				out = append(out, b)
			}
		}
	}
	return out
}

func addresses(blocks []*Block) []string {
	var out []string
	for _, b := range blocks {
		for _, i := range b.Instances {
			out = append(out, i.Address)
		}
	}
	sort.Strings(out)
	return out
}

func conv(v cty.Value) any { return value.Converter{Placeholder: "P"}.Go(v) }

func TestInstancesKeysAndShapes(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
variable "u" {}
resource "aws_instance" "c" {
  count = 2
  ami   = "a-${count.index}"
}
resource "aws_instance" "f" {
  for_each = toset([1])
  ami      = each.key
  lifecycle { prevent_destroy = true }
  depends_on = [aws_instance.c]
}
resource "aws_instance" "u" {
  count = var.u
}
resource "aws_security_group" "sg" {
  ingress { from_port = 1 }
  dynamic "egress" {
    for_each = var.u
    content { from_port = egress.value }
  }
  dynamic "ingress" {
    for_each = [2, 3]
    content { from_port = ingress.value }
  }
}
resource "aws_instance" "zero" {
  count = 0
}
`})
	r := rootByID(t, s, ".")
	require.Equal(t, []string{"aws_instance.c[0]", "aws_instance.c[1]", "aws_instance.f", "aws_instance.u"}, addresses(blocksOf(r, "resource", "aws_instance")))
	c := blocksOf(r, "resource", "aws_instance")[0]
	require.Equal(t, "a-1", conv(c.Instances[1].Attrs["ami"]))
	require.NotContains(t, c.Instances[0].Attrs, "count")

	f := blocksOf(r, "resource", "aws_instance")[1]
	require.True(t, f.KeyUnknown)
	require.Equal(t, "P", conv(f.Instances[0].Attrs["ami"]))
	require.NotContains(t, f.Instances[0].Attrs, "lifecycle")
	require.NotContains(t, f.Instances[0].Attrs, "depends_on")
	require.Equal(t, []string{"aws_instance.c"}, f.DependsOn)
	require.True(t, f.Lifecycle.IsKnown())

	u := blocksOf(r, "resource", "aws_instance")[2]
	require.True(t, u.KeyUnknown)
	require.True(t, u.Overridable)
	require.False(t, c.KeyUnknown)
	require.False(t, c.Overridable)

	sg := blocksOf(r, "resource", "aws_security_group")[0].Instances[0]
	require.Equal(t, []any{map[string]any{"from_port": int64(1)}, map[string]any{"from_port": int64(2)}, map[string]any{"from_port": int64(3)}}, conv(sg.Attrs["ingress"]))
	require.Equal(t, []any{"P"}, conv(sg.Attrs["egress"]))
	require.NotContains(t, sg.Attrs, "dynamic")
	require.Equal(t, 17, sg.Ranges["ingress.0"].Start.Line)
	require.Equal(t, 24, sg.Ranges["ingress.1"].Start.Line, "a generated block maps to its content")
	require.Equal(t, 24, sg.Ranges["ingress.2.from_port"].Start.Line)
	require.Equal(t, 18, sg.Ranges["egress.0"].Start.Line)
}

// Attribute-style object lists must expose per-element and nested member
// ranges so finding paths like ["spec",0,"container",1,"resources",0] resolve.
func TestAttributeObjectListRanges(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
resource "kubernetes_pod" "p" {
  spec {
    container = [
      {
        image = "nginx:a"
        name  = "a"
      },
      {
        image = "nginx:b"
        name  = "b"
        resources = {
          requests = {
            memory = "50Mi"
          }
        }
      },
    ]
  }
}
`,
	})
	r := rootByID(t, s, ".")
	pod := blocksOf(r, "resource", "kubernetes_pod")[0].Instances[0]
	require.Equal(t, 5, pod.Ranges["spec.0.container.0"].Start.Line)
	require.Equal(t, 6, pod.Ranges["spec.0.container.0.image"].Start.Line)
	require.Equal(t, 9, pod.Ranges["spec.0.container.1"].Start.Line)
	require.Equal(t, 12, pod.Ranges["spec.0.container.1.resources"].Start.Line)
	require.Equal(t, 12, pod.Ranges["spec.0.container.1.resources.0"].Start.Line, "tf.nested index-0 path")
	require.Equal(t, 13, pod.Ranges["spec.0.container.1.resources.0.requests"].Start.Line)
}

func TestDocumentRangesAreCapped(t *testing.T) {
	big := strings.Repeat(`{"a": 1}, `, maxDocNodes) + `{"a": 1}`
	s := load(t, map[string]string{"main.tf": `
resource "aws_iam_policy" "big" {
  policy = <<EOF
[` + big + `]
EOF
  small = jsonencode({ a = [1, { b = 2 }] })
}
`})
	inst := blocksOf(rootByID(t, s, "."), "resource", "aws_iam_policy")[0].Instances[0]
	require.NotContains(t, inst.Ranges, "policy.0", "a document over the node cap records nothing")
	require.Equal(t, 3, inst.Ranges["policy"].Start.Line)
	require.Equal(t, 6, inst.Ranges["small.a.1.b"].Start.Line)
	require.Equal(t, 6, inst.Ranges["small.a.1"].Start.Line)
}

func TestExpansionIsNotCapped(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
resource "aws_instance" "c" {
  count = 120
}
resource "aws_instance" "f" {
  for_each = toset([for i in range(600) : tostring(i)])
}
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = range(300)
    content { from_port = ingress.value }
  }
}
module "m" {
  source = "./m"
  count  = 70
}
output "last" { value = module.m[69].id }
`,
		"m/main.tf": `
resource "aws_s3_bucket" "b" {}
output "id" { value = "x" }
`,
	})
	r := rootByID(t, s, ".")
	instances := blocksOf(r, "resource", "aws_instance")
	require.Len(t, instances[0].Instances, 120)
	require.Len(t, instances[1].Instances, 600)
	sg := blocksOf(r, "resource", "aws_security_group")[0].Instances[0]
	require.Len(t, conv(sg.Attrs["ingress"]), 300)
	require.Len(t, addresses(blocksOf(r, "resource", "aws_s3_bucket")), 70)
	last := blocksOf(r, "output", "")
	require.NotEmpty(t, last)
	require.Equal(t, "x", conv(last[0].Instances[0].Attrs["value"]))
}

func TestOverrideMerge(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
resource "aws_db_instance" "db" {
  engine              = "mysql"
  publicly_accessible = false
  tags { a = 1 }
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [tags]
  }
}
locals {
  a = 1
  b = 2
}
`,
		"main_override.tf": `
resource "aws_db_instance" "db" {
  publicly_accessible = true
  tags { b = 2 }
  lifecycle { prevent_destroy = false }
}
locals { b = 3 }
`,
	})
	r := rootByID(t, s, ".")
	dbs := blocksOf(r, "resource", "aws_db_instance")
	require.Len(t, dbs, 1, "the override is merged, not a second block")
	db := dbs[0]
	require.False(t, db.Duplicate)
	require.Equal(t, "main.tf", db.File)
	inst := db.Instances[0]
	require.Equal(t, true, conv(inst.Attrs["publicly_accessible"]))
	require.Equal(t, "mysql", conv(inst.Attrs["engine"]))
	require.Equal(t, []any{map[string]any{"b": int64(2)}}, conv(inst.Attrs["tags"]))
	require.True(t, strings.HasSuffix(inst.Ranges["publicly_accessible"].Filename, "main_override.tf"))
	require.True(t, strings.HasSuffix(inst.Ranges["engine"].Filename, "main.tf"))
	lc := conv(db.Lifecycle).(map[string]any)
	require.Equal(t, false, lc["prevent_destroy"])
	require.Contains(t, lc, "ignore_changes")
	locals := blocksOf(r, "locals", "")
	require.Len(t, locals, 1)
	require.Equal(t, int64(3), conv(locals[0].Instances[0].Attrs["b"]))
}

func TestDuplicateAddressesAreKeptAndMayOnly(t *testing.T) {
	s := load(t, map[string]string{
		"a.tf": `resource "aws_s3_bucket" "b" { bucket = "a" }`,
		"b.tf": `
resource "aws_s3_bucket" "b" { bucket = "b" }
resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.b.id }
`,
	})
	r := rootByID(t, s, ".")
	buckets := blocksOf(r, "resource", "aws_s3_bucket")
	require.Len(t, buckets, 2)
	require.True(t, buckets[0].Duplicate && buckets[1].Duplicate)
	v := blocksOf(r, "resource", "aws_s3_bucket_versioning")[0].Instances[0]
	require.Len(t, v.Refs, 2)
	for _, ref := range v.Refs {
		require.False(t, ref.Certain)
	}
}

func TestReferences(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
variable "name" {}
variable "flag" { default = true }
resource "aws_s3_bucket" "b" { bucket = "x" }
resource "aws_s3_bucket" "c" {
  count  = 2
  bucket = "c"
}
locals { bid = aws_s3_bucket.b.id }
resource "aws_s3_bucket_versioning" "exact" { bucket = local.bid }
resource "aws_s3_bucket_versioning" "cond" { bucket = var.flag ? aws_s3_bucket.b.id : aws_s3_bucket.c[0].id }
resource "aws_s3_bucket_versioning" "keyed" { bucket = aws_s3_bucket.c[1].arn }
resource "aws_s3_bucket_versioning" "unknown" { bucket = var.name }
resource "aws_instance" "i" {
  vpc_config { security_group_ids = [aws_s3_bucket.b.id] }
}
module "m" {
  source = "./mod"
  in     = aws_s3_bucket.b.id
}
resource "aws_s3_bucket_policy" "via_module" { bucket = module.m.out }
`,
		"mod/main.tf": `
variable "in" {}
output "out" { value = var.in }
`,
	})
	r := rootByID(t, s, ".")
	ref := func(label string) []Ref {
		for _, typ := range []string{"aws_s3_bucket_versioning", "aws_instance", "aws_s3_bucket_policy"} {
			for _, b := range blocksOf(r, "resource", typ) {
				if b.Name == label {
					return b.Instances[0].Refs
				}
			}
		}
		t.Fatalf("no %s", label)
		return nil
	}
	exact := ref("exact")
	require.Len(t, exact, 1)
	require.Equal(t, "aws_s3_bucket.b", exact[0].To.Address)
	require.Equal(t, "id", exact[0].Attr)
	require.Equal(t, []string{"bucket"}, exact[0].Path)
	require.True(t, exact[0].Certain)

	cond := ref("cond")
	require.Len(t, cond, 2)
	require.False(t, cond[0].Certain)
	require.False(t, cond[1].Certain)

	keyed := ref("keyed")
	require.Len(t, keyed, 1)
	require.Equal(t, "aws_s3_bucket.c[1]", keyed[0].To.Address)
	require.Equal(t, "arn", keyed[0].Attr)

	require.Empty(t, ref("unknown"))
	for _, b := range blocksOf(r, "resource", "aws_s3_bucket_versioning") {
		if b.Name == "unknown" {
			require.True(t, b.Instances[0].Untraced["bucket"])
		}
		if b.Name == "exact" {
			require.Empty(t, b.Instances[0].Untraced)
		}
	}
	nested := ref("i")
	require.Len(t, nested, 1)
	require.Equal(t, []string{"vpc_config", "security_group_ids"}, nested[0].Path)

	viaModule := ref("via_module")
	require.Len(t, viaModule, 1)
	require.Equal(t, "aws_s3_bucket.b", viaModule[0].To.Address)
	require.True(t, viaModule[0].Certain)

	calls := blocksOf(r, "module", "")
	require.Len(t, calls, 1)
	require.Len(t, calls[0].Instances[0].Refs, 1)
	require.Equal(t, []string{"in"}, calls[0].Instances[0].Refs[0].Path)
}

func TestModuleScopesProvidersAndStaticKinds(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
provider "aws" { region = "eu-west-1" }
provider "aws" {
  alias  = "west"
  region = "us-west-2"
}
module "m" {
  for_each  = toset(["a", "b"])
  source    = "./mod"
  name      = each.key
  providers = { aws = aws.west }
}
resource "aws_s3_bucket" "root" { bucket = "r" }
resource "aws_s3_bucket" "aliased" {
  provider = aws.west
  bucket   = "a"
}
`,
		"mod/main.tf": `
variable "name" { type = string }
locals { full = "n-${var.name}" }
output "id" { value = aws_s3_bucket.b.id }
resource "aws_s3_bucket" "b" { bucket = local.full }
`,
	})
	require.Len(t, s.Roots, 1, "a called directory is not a root")
	r := s.Roots[0]
	require.False(t, r.Incomplete, r.Notes)
	require.Equal(t, []string{"aws_s3_bucket.aliased", "aws_s3_bucket.root", `module.m["a"].aws_s3_bucket.b`, `module.m["b"].aws_s3_bucket.b`},
		addresses(blocksOf(r, "resource", "aws_s3_bucket")))
	for _, b := range blocksOf(r, "resource", "aws_s3_bucket") {
		require.NotNil(t, b.ProviderBlock, b.Address())
		switch b.Name {
		case "root":
			require.Empty(t, b.ProviderBlock.Name)
		default:
			require.Equal(t, "west", b.ProviderBlock.Name, b.Address())
		}
		if b.Module.Address == `module.m["b"]` {
			require.Equal(t, "n-b", conv(b.Instances[0].Attrs["bucket"]))
		}
	}
	require.Len(t, blocksOf(r, "variable", ""), 1, "variables of a module directory are modelled once")
	require.Equal(t, "string", conv(blocksOf(r, "variable", "")[0].Instances[0].Attrs["type"]))
	require.Len(t, blocksOf(r, "output", ""), 1)
	require.Len(t, blocksOf(r, "locals", ""), 2, "locals are modelled per module instance")
	calls := blocksOf(r, "module", "")
	require.Len(t, calls, 1)
	require.Equal(t, []string{`module.m["a"]`, `module.m["b"]`}, addresses(calls))
	require.Equal(t, "a", conv(calls[0].Instances[0].Attrs["name"]))
	require.Equal(t, "./mod", conv(calls[0].Instances[0].Attrs["source"]))
	require.NotContains(t, calls[0].Instances[0].Attrs, "providers")
}

func TestUndeclaredAddressInCompleteRootIsNotUntraced(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
resource "aws_api_gateway_authorizer" "a" {
  name        = "a"
  rest_api_id = aws_api_gateway_rest_api.missing.id
}
resource "aws_api_gateway_rest_api" "other" { name = "other" }
`})
	r := rootByID(t, s, ".")
	require.False(t, r.Incomplete, r.Notes)
	authorizer := blocksOf(r, "resource", "aws_api_gateway_authorizer")
	require.Len(t, authorizer, 1)
	require.Empty(t, authorizer[0].Instances[0].Untraced)
	require.Empty(t, authorizer[0].Instances[0].Refs)
}

// each.value over for_each = <resource map> selects the same-key instance.
func TestEachValueOverResourceMap(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
resource "azurerm_subnet" "protected" {
  for_each = toset(["a", "b"])
  name     = each.key
}
resource "azurerm_subnet_network_security_group_association" "protected" {
  for_each  = azurerm_subnet.protected
  subnet_id = each.value.id
}
resource "azurerm_subnet" "unsecured" { name = "unsecured" }
`})
	r := rootByID(t, s, ".")
	assoc := blocksOf(r, "resource", "azurerm_subnet_network_security_group_association")
	require.Len(t, assoc, 1)
	require.Len(t, assoc[0].Instances, 2)
	byKey := map[string]*Instance{}
	for _, inst := range assoc[0].Instances {
		byKey[inst.Key] = inst
		require.Empty(t, inst.Untraced)
		require.Len(t, inst.Refs, 1)
		require.True(t, inst.Refs[0].Certain)
		require.Equal(t, []string{"subnet_id"}, inst.Refs[0].Path)
		require.Equal(t, "id", inst.Refs[0].Attr)
		require.Equal(t, inst.Key, inst.Refs[0].To.Key)
		require.Equal(t, "protected", inst.Refs[0].To.Block.Name)
	}
	require.Contains(t, byKey, `["a"]`)
	require.Contains(t, byKey, `["b"]`)
}

// A dynamic index local.list[count.index] selects the concrete instance when
// the list entry is known.
func TestNestedLocalCountIndex(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
locals {
  role_indexes = [0]
}
resource "aws_iam_role" "nested_indexed" {
  count = 1
  name  = "nested-indexed-role"
}
resource "aws_iam_role_policy" "dangerous_nested_index" {
  name = "dangerous_nested_index"
  role = aws_iam_role.nested_indexed[local.role_indexes[count.index]].id
  policy = "{}"
}
`})
	r := rootByID(t, s, ".")
	policy := blocksOf(r, "resource", "aws_iam_role_policy")
	require.Len(t, policy, 1)
	inst := policy[0].Instances[0]
	require.Empty(t, inst.Untraced)
	require.Len(t, inst.Refs, 1)
	require.True(t, inst.Refs[0].Certain)
	require.Equal(t, "aws_iam_role.nested_indexed[0]", inst.Refs[0].To.Address)
	require.Equal(t, "id", inst.Refs[0].Attr)
}

// A literal index into a local map reads only that entry.
func TestLocalMapLiteralIndex(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
locals {
  by_name = {
    a = azurerm_subnet.selected.id
    b = azurerm_subnet.unselected.id
  }
}
resource "azurerm_subnet" "selected" { name = "selected" }
resource "azurerm_subnet" "unselected" { name = "unselected" }
resource "azurerm_subnet_network_security_group_association" "bracket" {
  subnet_id = local.by_name["a"]
}
resource "azurerm_subnet_network_security_group_association" "dot" {
  subnet_id = local.by_name.a
}
`})
	r := rootByID(t, s, ".")
	for _, name := range []string{"bracket", "dot"} {
		var inst *Instance
		for _, b := range blocksOf(r, "resource", "azurerm_subnet_network_security_group_association") {
			if b.Name == name {
				inst = b.Instances[0]
				break
			}
		}
		require.NotNil(t, inst, name)
		require.Empty(t, inst.Untraced, name)
		require.Len(t, inst.Refs, 1, name)
		require.True(t, inst.Refs[0].Certain, name)
		require.Equal(t, "azurerm_subnet.selected", inst.Refs[0].To.Address, name)
		require.Equal(t, "id", inst.Refs[0].Attr, name)
	}
}

func TestUndeclaredModuleInCompleteRootIsNotUntraced(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
resource "azurerm_subnet_network_security_group_association" "unknown" {
  subnet_id = module.network.subnet_id
}
resource "azurerm_subnet" "first" { name = "first" }
`})
	r := rootByID(t, s, ".")
	require.False(t, r.Incomplete, r.Notes)
	assoc := blocksOf(r, "resource", "azurerm_subnet_network_security_group_association")
	require.Len(t, assoc, 1)
	require.Empty(t, assoc[0].Instances[0].Untraced)
	require.Empty(t, assoc[0].Instances[0].Refs)
}

func TestUndeclaredAddressInIncompleteRootIsUntraced(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
resource "aws_api_gateway_authorizer" "a" {
  rest_api_id = aws_api_gateway_rest_api.missing.id
}
module "remote" { source = "terraform-aws-modules/vpc/aws" }
`})
	r := rootByID(t, s, ".")
	require.True(t, r.Incomplete)
	authorizer := blocksOf(r, "resource", "aws_api_gateway_authorizer")
	require.Len(t, authorizer, 1)
	require.True(t, authorizer[0].Instances[0].Untraced["rest_api_id"])
}

func TestUnresolvedModuleMakesTheRootIncomplete(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
module "remote" {
  source = "terraform-aws-modules/vpc/aws"
  cidr   = "10.0.0.0/16"
}
module "none" {
  count  = 0
  source = "terraform-aws-modules/vpc/aws"
}
`})
	r := s.Roots[0]
	require.True(t, r.Incomplete)
	calls := blocksOf(r, "module", "")
	require.Len(t, calls, 1, "a call known to have no instance is dropped")
	require.Equal(t, "10.0.0.0/16", conv(calls[0].Instances[0].Attrs["cidr"]))
}

func TestUnresolvedModuleExposesOnlyWhatItsArgumentsReach(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
variable "region" {}
locals { via_local = aws_s3_bucket.local.id }
resource "aws_s3_bucket" "direct" { bucket = "direct" }
resource "aws_s3_bucket" "local" { bucket = "local" }
resource "aws_s3_bucket" "named" { bucket = "shared-name" }
resource "aws_s3_bucket" "unrelated" { bucket = "unrelated" }
module "first" {
  source = "terraform-aws-modules/vpc/aws"
  bucket = aws_s3_bucket.direct.id
  names  = [local.via_local]
  name   = "shared-name"
  region = var.region
}
module "second" {
  source = "git::https://example.invalid/mod.git"
  input  = module.first.id
}
`})
	r := s.Roots[0]
	require.True(t, r.Incomplete)
	require.False(t, r.Unscoped, r.Notes)
	require.False(t, r.IncompleteEverywhere())
	require.Len(t, r.Unresolved, 2)
	exposed := map[string]bool{}
	for inst := range r.Exposed {
		exposed[inst.Address] = true
	}
	require.Equal(t, map[string]bool{
		"aws_s3_bucket.direct": true, "aws_s3_bucket.local": true, "module.first": true, "module.second": true,
	}, exposed)
	require.True(t, r.ExposedStrings["shared-name"])
	require.False(t, r.ExposedStrings["unrelated"])
	require.False(t, r.ExposedStrings["terraform-aws-modules/vpc/aws"], "the module source is not an argument")
}

func TestUntracedUnresolvedModuleArgumentLeavesTheRootUnscoped(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
module "remote" {
  source = "terraform-aws-modules/vpc/aws"
  bucket = aws_s3_bucket.missing.id
}
`})
	r := s.Roots[0]
	require.True(t, r.Unscoped)
	require.True(t, r.IncompleteEverywhere())
}

func TestUnresolvedModuleOutputReadIsNotUntraced(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
resource "aws_s3_bucket_versioning" "v" { bucket = module.logs.bucket }
resource "aws_s3_bucket_versioning" "w" { bucket = var.outside }
variable "outside" {}
module "logs" { source = "terraform-aws-modules/vpc/aws" }
`})
	r := s.Roots[0]
	versioning := blocksOf(r, "resource", "aws_s3_bucket_versioning")
	require.Len(t, versioning, 2)
	for _, b := range versioning {
		inst := b.Instances[0]
		switch b.Name {
		case "v":
			require.Empty(t, inst.Untraced)
			require.True(t, inst.UnresolvedAt["bucket"])
		case "w":
			require.True(t, inst.Untraced["bucket"])
			require.Empty(t, inst.UnresolvedAt)
		}
	}
}

func TestNestedUnresolvedModuleIsScopedToItsInstance(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "passed" { bucket = "passed" }
resource "aws_s3_bucket" "unrelated" { bucket = "unrelated" }
module "child" {
  source = "./child"
  bucket = aws_s3_bucket.passed.id
}
`,
		"child/main.tf": `
variable "bucket" {}
resource "aws_s3_bucket" "inner" { bucket = "inner" }
resource "aws_s3_bucket" "inner_unrelated" { bucket = "inner-unrelated" }
module "deep" {
  source = "git::https://example.invalid/mod.git"
  a      = aws_s3_bucket.inner.id
  b      = var.bucket
}
`,
	})
	r := rootByID(t, s, ".")
	require.False(t, r.Unscoped, r.Notes)
	require.Len(t, r.Unresolved, 1)
	require.Equal(t, "module.child", r.Unresolved[0].Block.Module.Address)
	exposed := map[string]bool{}
	for inst := range r.Exposed {
		exposed[inst.Address] = true
	}
	require.Equal(t, map[string]bool{
		"aws_s3_bucket.passed": true, "module.child.aws_s3_bucket.inner": true, "module.child.module.deep": true,
	}, exposed)
}

func TestParseFailureMakesTheRootIncomplete(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "b" { bucket = "x" }`,
		"bad.tf":  `resource "aws_s3_bucket" {`,
	})
	r := s.Roots[0]
	require.True(t, r.Incomplete)
	require.True(t, r.IncompleteEverywhere())
	require.Len(t, blocksOf(r, "resource", "aws_s3_bucket"), 1)
}

func TestFailedEvaluationRunsDegraded(t *testing.T) {
	real := runEvaluation
	t.Cleanup(func() { runEvaluation = real })
	var calls []map[string]cty.Value
	runEvaluation = func(
		ctx context.Context, fsys vfs.FS, e *tfeval.Evaluator, dir string, inputs map[string]cty.Value, varsPath string,
	) *evaluation {
		calls = append(calls, inputs)
		ev := real(ctx, fsys, e, dir, inputs, varsPath)
		if len(calls) == 1 {
			ev.err = errors.New("evaluation failed")
		}
		return ev
	}
	s := load(t, map[string]string{
		"main.tf": `
variable "n" {}
resource "aws_s3_bucket" "b" { bucket = var.n }
`,
		"terraform.tfvars": `n = "named"`,
	})
	r := s.Roots[0]
	require.Len(t, calls, 2)
	require.Nil(t, calls[0], "the first run reads the autoloaded variables")
	require.True(t, r.Degraded)
	b := blocksOf(r, "resource", "aws_s3_bucket")[0]
	require.Equal(t, "P", conv(b.Instances[0].Attrs["bucket"]), "every root variable is unknown in degraded mode")
}

func TestJSONConfiguration(t *testing.T) {
	s := load(t, map[string]string{"main.tf.json": `{
  "provider": {"aws": {"region": "eu-west-1"}},
  "resource": {"aws_s3_bucket": {"b": {"bucket": "x", "versioning": {"enabled": true}}}}
}`})
	r := s.Roots[0]
	require.Len(t, blocksOf(r, "provider", "aws"), 1)
	b := blocksOf(r, "resource", "aws_s3_bucket")[0]
	require.Equal(t, map[string]any{"enabled": true}, conv(b.Instances[0].Attrs["versioning"]))
	require.NotNil(t, b.ProviderBlock)
}

// Plain .json Terraform configuration (CDKTF-style) must project blocks the
// same way as .tf.json; package.json next to it must not become a root.
func TestPlainJSONConfiguration(t *testing.T) {
	s := load(t, map[string]string{
		"positive5.json": `{
  "//": {"metadata": {"backend": "local", "stackName": "cdktf-test", "version": "0.9.0"}},
  "provider": {"aws": [{"region": "us-east-1"}]},
  "resource": {"aws_instance": {"cdktf-test": {
    "ami": "ami-1212f123",
    "instance_type": "t2.micro",
    "monitoring": false
  }}},
  "terraform": {"backend": {"local": {"path": "/terraform.cdktf-test.tfstate"}}}
}`,
		"package.json": `{"name":"app","dependencies":{}}`,
	})
	require.Len(t, s.Roots, 1)
	inst := blocksOf(s.Roots[0], "resource", "aws_instance")
	require.Len(t, inst, 1)
	require.Equal(t, false, conv(inst[0].Instances[0].Attrs["monitoring"]))
}

func TestPartialStringsTemplatesAndJSON(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
variable "acct" {}
resource "aws_iam_role" "r" {
  name = "arn:aws:iam::${var.acct}:role/x"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Resource = var.acct }] })
  path = "${path.module}/x"
  tags = { known = "k", unknown = var.acct }
  literal = "$${aws:username}"
}
`})
	inst := blocksOf(s.Roots[0], "resource", "aws_iam_role")[0].Instances[0]
	require.Equal(t, "P", conv(inst.Attrs["name"]), "a partly unknown string is wholly unknown")
	require.Equal(t, []any{"arn:aws:iam::", "P", ":role/x"}, convList(inst.Templates["name"]))
	require.Equal(t, "P", conv(inst.Attrs["policy"]))
	require.Equal(t, map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Resource": "P"}}}, conv(inst.JSON["policy"]))
	require.Equal(t, "${var.acct}", inst.JSONExpr["policy"]["Statement.0.Resource"])
	require.Equal(t, map[string]any{"known": "k", "unknown": "P"}, conv(inst.Attrs["tags"]))
	require.Equal(t, "${aws:username}", conv(inst.Attrs["literal"]))
	require.Equal(t, []string{"path"}, inst.Block.Nonliteral)
}

func TestJSONHeredocWithUnknownInterpolation(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
resource "aws_sqs_queue" "positive1" {
  name   = "examplequeue"
  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.q.arn}"
    }
  ]
}
POLICY
}
`})
	inst := blocksOf(s.Roots[0], "resource", "aws_sqs_queue")[0].Instances[0]
	require.Equal(t, "P", conv(inst.Attrs["policy"]))
	require.NotEmpty(t, inst.Templates["policy"])
	require.Equal(t, map[string]any{
		"Statement": []any{map[string]any{
			"Effect":    "Allow",
			"Principal": "*",
			"Action":    "sqs:SendMessage",
			"Resource":  "P",
		}},
	}, conv(inst.JSON["policy"]))
}

func TestJSONHeredocKeepsKnownARNParts(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
data "aws_caller_identity" "current" {}
resource "aws_kms_key" "k" {
  policy = <<POLICY
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"},
    "Action": "kms:*",
    "Resource": "*"
  }]
}
POLICY
}
`})
	kms := blocksOf(s.Roots[0], "resource", "aws_kms_key")[0].Instances[0]
	require.Equal(t, map[string]any{
		"Statement": []any{map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]any{"AWS": "arn:aws:iam::P:root"},
			"Action":    "kms:*",
			"Resource":  "*",
		}},
	}, conv(kms.JSON["policy"]))
}

func convList(vals []cty.Value) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = conv(v)
	}
	return out
}

func TestCachedModuleReplaysKeepTheirDescendants(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf":       "module \"a\" {\n  source = \"./a\"\n  count  = 3\n}\n",
		"a/main.tf":     "module \"b\" {\n  source = \"../b\"\n  count  = 2\n}\n",
		"b/main.tf":     `resource "aws_s3_bucket" "x" { bucket = "x" }`,
		"b/versions.tf": `terraform {}`,
	})
	r := s.Roots[0]
	require.Len(t, addresses(blocksOf(r, "resource", "aws_s3_bucket")), 6)
	for _, m := range r.Modules {
		require.NotNil(t, m.Scope, m.Address)
	}
}

func TestJSONEncodeMarksUnknownLeavesInNestedTemplates(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
data "aws_caller_identity" "current" {}
resource "aws_kms_key" "k" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
        "arn:aws:iam::444455556666:root",
      ] }
      Action   = "kms:*"
      Resource = "*"
    }]
  })
}
`})
	kms := blocksOf(s.Roots[0], "resource", "aws_kms_key")[0].Instances[0]
	require.Equal(t, map[string]any{
		"Statement": []any{map[string]any{
			"Effect": "Allow",
			"Principal": map[string]any{"AWS": []any{
				"arn:aws:iam::P:root",
				"arn:aws:iam::444455556666:root",
			}},
			"Action":   "kms:*",
			"Resource": "*",
		}},
	}, conv(kms.JSON["policy"]))
	require.Equal(t, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
		kms.JSONExpr["policy"]["Statement.0.Principal.AWS.0"])
}

func TestJSONEncodeMarksUnknownLeafThroughLocal(t *testing.T) {
	s := load(t, map[string]string{"main.tf": `
data "aws_caller_identity" "current" {}
locals { account_id = data.aws_caller_identity.current.account_id }
resource "aws_kms_key" "k" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}
`})
	kms := blocksOf(s.Roots[0], "resource", "aws_kms_key")[0].Instances[0]
	require.Equal(t, map[string]any{
		"Statement": []any{map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]any{"AWS": "arn:aws:iam::P:root"},
			"Action":    "kms:*",
			"Resource":  "*",
		}},
	}, conv(kms.JSON["policy"]))
	require.Equal(t, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
		kms.JSONExpr["policy"]["Statement.0.Principal.AWS"])
}

func TestExpansionPastTraceDepthCountsAsRootInput(t *testing.T) {
	var b strings.Builder
	b.WriteString("locals {\n  l0 = 2\n")
	for i := 1; i <= maxTraceDepth+8; i++ {
		fmt.Fprintf(&b, "  l%d = local.l%d\n", i, i-1)
	}
	b.WriteString("}\nresource \"aws_instance\" \"deep\" {\n  count = local.l")
	fmt.Fprintf(&b, "%d\n}\n", maxTraceDepth+8)
	s := load(t, map[string]string{"main.tf": b.String()})
	deep := blocksOf(s.Roots[0], "resource", "aws_instance")[0]
	require.True(t, deep.Overridable, "a chain too deep to follow must not count as a literal")
}

func TestRepeatedModuleCallsKeepDistinctProviders(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
provider "aws" {
  alias = "a"
  region = "eu-west-1"
  default_tags { tags = { Team = "a" } }
}
provider "aws" {
  alias = "b"
  region = "eu-west-1"
  default_tags { tags = { Team = "b" } }
}
module "left" {
  source    = "./mod"
  providers = { aws = aws.a }
}
module "right" {
  source    = "./mod"
  providers = { aws = aws.b }
}
`,
		"mod/main.tf": `resource "aws_s3_bucket" "b" { bucket = "b" }`,
	})
	r := s.Roots[0]
	var left, right *Block
	for _, b := range blocksOf(r, "resource", "aws_s3_bucket") {
		switch b.Module.Address {
		case "module.left":
			left = b
		case "module.right":
			right = b
		}
	}
	require.NotNil(t, left)
	require.NotNil(t, right)
	require.NotNil(t, left.ProviderBlock)
	require.NotNil(t, right.ProviderBlock)
	require.Equal(t, "a", left.ProviderBlock.Name)
	require.Equal(t, "b", right.ProviderBlock.Name)
	require.NotSame(t, left.ProviderBlock, right.ProviderBlock)
}

func TestProvidersDeclaredInsideRepeatedModules(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
module "left" {
  source = "./mod"
  team   = "a"
}
module "right" {
  source = "./mod"
  team   = "b"
}
`,
		"mod/main.tf": `
variable "team" { type = string }
provider "aws" {
  region = "eu-west-1"
  default_tags { tags = { Team = var.team } }
}
resource "aws_s3_bucket" "b" { bucket = "b" }
`,
	})
	r := s.Roots[0]
	var left, right *Block
	for _, b := range blocksOf(r, "resource", "aws_s3_bucket") {
		switch b.Module.Address {
		case "module.left":
			left = b
		case "module.right":
			right = b
		}
	}
	require.NotNil(t, left)
	require.NotNil(t, right)
	require.NotNil(t, left.ProviderBlock, "first module instance keeps its provider")
	require.NotNil(t, right.ProviderBlock, "second module instance must not drop its provider")
	require.NotSame(t, left.ProviderBlock, right.ProviderBlock)
	require.Equal(t, "a", providerDefaultTeam(t, left.ProviderBlock))
	require.Equal(t, "b", providerDefaultTeam(t, right.ProviderBlock))
}

func providerDefaultTeam(t *testing.T, b *Block) string {
	t.Helper()
	require.NotEmpty(t, b.Instances)
	tags := conv(b.Instances[0].Attrs["default_tags"])
	switch v := tags.(type) {
	case []any:
		require.NotEmpty(t, v)
		obj, ok := v[0].(map[string]any)
		require.True(t, ok)
		return obj["tags"].(map[string]any)["Team"].(string)
	case map[string]any:
		return v["tags"].(map[string]any)["Team"].(string)
	default:
		t.Fatalf("unexpected default_tags shape %T", tags)
		return ""
	}
}

func TestSelectedVarsPathKeepsCountEnabledResource(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"main.tf": `
variable "enabled" { default = false }
resource "aws_s3_bucket" "b" {
  count  = var.enabled ? 1 : 0
  bucket = "kept"
}
`,
		"env.tfvars": `enabled = true`,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	scan, err := Load(context.Background(), dir, Options{VarsPath: filepath.Join(dir, "env.tfvars")})
	require.NoError(t, err)
	require.Len(t, blocksOf(scan.Roots[0], "resource", "aws_s3_bucket"), 1)
}

func TestSelectedVarsDirectiveKeepsCountEnabledResource(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
// kics_terraform_vars: env.tfvars
variable "enabled" { default = false }
resource "aws_s3_bucket" "b" {
  count  = var.enabled ? 1 : 0
  bucket = "kept"
}
`,
		"env.tfvars": `enabled = true`,
	})
	require.Len(t, blocksOf(s.Roots[0], "resource", "aws_s3_bucket"), 1)
}

func TestZeroInstanceUnresolvedModuleCallIsLeftOut(t *testing.T) {
	s := load(t, map[string]string{
		"main.tf": `
module "off" {
  source = "git::https://example.invalid/missing.git"
  count  = 0
}
resource "aws_s3_bucket" "kept" { bucket = "kept" }
`,
	})
	r := s.Roots[0]
	require.Len(t, blocksOf(r, "resource", "aws_s3_bucket"), 1)
	for _, m := range r.Modules {
		require.NotContains(t, m.Address, "module.off", "a known-empty call is not modeled")
	}
}
