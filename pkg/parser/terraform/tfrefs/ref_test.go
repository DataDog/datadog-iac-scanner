/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfrefs

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestParse(t *testing.T) {
	zero, k := cty.NumberIntVal(0), cty.StringVal("k")
	tests := []struct {
		src     string
		expr    bool
		kind    Kind
		typ     string
		name    string
		key     *cty.Value
		dynamic bool
	}{
		{src: `var.a`, kind: KindVar, name: "a"},
		{src: `local.a`, kind: KindLocal, name: "a"},
		{src: `aws_s3_bucket.b.id`, kind: KindResource, typ: "aws_s3_bucket", name: "b"},
		{src: `aws_s3_bucket.b[0].id`, kind: KindResource, typ: "aws_s3_bucket", name: "b", key: &zero},
		{src: `aws_s3_bucket.b["k"].id`, kind: KindResource, typ: "aws_s3_bucket", name: "b", key: &k},
		{src: `aws_s3_bucket.b[var.k].id`, expr: true, kind: KindResource, typ: "aws_s3_bucket", name: "b", dynamic: true},
		{src: `data.aws_iam_policy_document.p.json`, kind: KindData, typ: "aws_iam_policy_document", name: "p"},
		{src: `ephemeral.random_password.p.result`, kind: KindEphemeral, typ: "random_password", name: "p"},
		{src: `module.m.out`, kind: KindModule, name: "m"},
		{src: `each.value`, kind: KindEach},
		{src: `count.index`, kind: KindCount},
		{src: `self.x`, kind: KindSelf},
		{src: `path.module`, kind: KindPath},
		{src: `terraform.workspace`, kind: KindTerraform},
		{src: `aws_s3_bucket`, kind: KindOther},
	}
	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			var ref Ref
			if tt.expr {
				expr, diags := hclsyntax.ParseExpression([]byte(tt.src), "main.tf", hcl.InitialPos)
				require.False(t, diags.HasErrors())
				ref = Of(expr)[0]
			} else {
				traversal, diags := hclsyntax.ParseTraversalAbs([]byte(tt.src), "main.tf", hcl.InitialPos)
				require.False(t, diags.HasErrors())
				ref = Parse(traversal)
			}
			require.Equal(t, tt.kind, ref.Kind)
			require.Equal(t, tt.typ, ref.Type)
			require.Equal(t, tt.name, ref.Name)
			require.Equal(t, tt.dynamic, ref.DynamicKey)
			if tt.key == nil {
				require.Nil(t, ref.Key)
			} else {
				require.NotNil(t, ref.Key)
				require.True(t, tt.key.RawEquals(*ref.Key))
			}
		})
	}
}

func TestOfSplat(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte(`aws_x.y[*].id`), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	refs := Of(expr)
	require.Len(t, refs, 1)
	require.Equal(t, KindResource, refs[0].Kind)
	require.Equal(t, "aws_x", refs[0].Type)
	require.Equal(t, "y", refs[0].Name)
}
