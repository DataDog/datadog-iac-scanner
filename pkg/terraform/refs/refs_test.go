/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package refs

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

func TestParseAndExtractRefs(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression(
		[]byte(`[aws_s3_bucket.logs[0].arn, data.aws_caller_identity.current.account_id, aws_iam_role.r[each.key].name, module.net.vpc_id, local.x]`),
		"main.tf",
		hcl.InitialPos,
	)
	require.False(t, diags.HasErrors())

	got := Of(expr)
	require.Len(t, got, 6) // includes each.key

	require.Equal(t, KindResource, got[0].Kind)
	require.Equal(t, "aws_s3_bucket", got[0].Type)
	require.Equal(t, "logs", got[0].Name)
	require.NotNil(t, got[0].Key)
	require.Equal(t, "arn", got[0].ReadPath())

	require.Equal(t, KindData, got[1].Kind)
	require.Equal(t, "aws_caller_identity", got[1].Type)
	require.Equal(t, "current", got[1].Name)
	require.Equal(t, "account_id", got[1].FirstAttr())

	require.Equal(t, KindResource, got[2].Kind)
	require.Equal(t, "aws_iam_role", got[2].Type)
	require.True(t, got[2].DynamicKey)
	require.Equal(t, "name", got[2].ReadPath())

	require.Equal(t, KindModule, got[4].Kind)
	require.Equal(t, "net", got[4].Name)
	require.Equal(t, "vpc_id", got[4].FirstAttr())

	require.Equal(t, KindLocal, got[5].Kind)
	require.Equal(t, "x", got[5].Name)
}
