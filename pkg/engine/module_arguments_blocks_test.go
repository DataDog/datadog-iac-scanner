/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
