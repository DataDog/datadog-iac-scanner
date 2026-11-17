/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package address

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestInstanceAddress(t *testing.T) {
	for _, tc := range []struct {
		name, module string
		block        Block
		suffix, want string
	}{
		{"root count", "", Block{Kind: KindResource, Type: "aws_s3_bucket", Name: "web"}, "[1]", "aws_s3_bucket.web[1]"},
		{"nested for_each", `module.network["blue"]`, Block{Kind: KindData, Type: "aws_vpc", Name: "current"}, `["prod"]`, `module.network["blue"].data.aws_vpc.current["prod"]`},
		{"variable", "", Block{Kind: KindVariable, Name: "region"}, "[0]", "var.region"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, Instance(tc.module, tc.block, tc.suffix))
		})
	}
}

func TestInstanceSuffixUsesHCLQuoting(t *testing.T) {
	require.Equal(t, `["a\"b"]`, InstanceSuffix(cty.StringVal(`a"b`)))
	require.Equal(t, "[2]", InstanceSuffix(cty.NumberIntVal(2)))
	require.Empty(t, InstanceSuffix(cty.UnknownVal(cty.String)))
}

func TestInstanceSuffixRoundTripsHCLTraversal(t *testing.T) {
	for _, key := range []string{
		`quote"slash\`, "line\nbreak", `${literal}`, `%{literal}`, "\x00", "雪",
	} {
		t.Run(key, func(t *testing.T) {
			suffix, ok := FormatIndexKey(cty.StringVal(key))
			require.True(t, ok)
			traversal, diags := hclsyntax.ParseTraversalAbs(
				[]byte("aws_s3_bucket.web"+suffix), "address.tf", hcl.InitialPos,
			)
			require.False(t, diags.HasErrors(), "%q should remain valid HCL: %s", key, diags.Error())
			index, ok := traversal[len(traversal)-1].(hcl.TraverseIndex)
			require.True(t, ok)
			require.True(t, index.Key.RawEquals(cty.StringVal(key)), "%q round-tripped as %#v", key, index.Key)
		})
	}
}
