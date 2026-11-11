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

func parse(t *testing.T, src string) []Ref {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "x.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	return Of(expr)
}

func TestOf(t *testing.T) {
	got := parse(t, `[aws_s3_bucket.b[0].arn, data.aws_iam_policy_document.d.json, module.m["x"].out, var.v, local.l, each.value, aws_sg.s[count.index].id]`)
	require.Len(t, got, 8)
	require.Equal(t, KindResource, got[0].Kind)
	require.Equal(t, "aws_s3_bucket", got[0].Type)
	require.Equal(t, "b", got[0].Name)
	require.NotNil(t, got[0].Key)
	require.Equal(t, []string{"arn"}, got[0].After())
	require.Equal(t, KindData, got[1].Kind)
	require.Equal(t, []string{"json"}, got[1].After())
	require.Equal(t, KindModule, got[2].Kind)
	require.Equal(t, []string{"out"}, got[2].After())
	require.Equal(t, KindVar, got[3].Kind)
	require.Equal(t, KindLocal, got[4].Kind)
	require.Equal(t, KindEach, got[5].Kind)
	require.Equal(t, []string{"value"}, got[5].After())
	require.Equal(t, KindResource, got[6].Kind)
	require.True(t, got[6].DynamicKey)
	require.NotNil(t, got[6].KeyExpr)
	require.Equal(t, []string{"id"}, got[6].RelAfter)
	require.Equal(t, []string{"id"}, got[6].After())
	require.Equal(t, "arn", got[0].ReadPath())
	require.Equal(t, "id", got[6].ReadPath())

	read := parse(t, `[aws_cloudwatch_log_metric_filter.f.metric_transformation[0].name, aws_s3_bucket.b.tags["k"], aws_s3_bucket.b]`)
	require.Equal(t, "metric_transformation.name", read[0].ReadPath())
	require.Equal(t, []string{"metric_transformation"}, read[0].After())
	require.Equal(t, "tags.k", read[1].ReadPath())
	require.Empty(t, read[2].ReadPath())

	nested := parse(t, `aws_iam_role.nested_indexed[local.role_indexes[count.index]].id`)
	var role Ref
	for _, r := range nested {
		if r.Kind == KindResource {
			role = r
			break
		}
	}
	require.Equal(t, "nested_indexed", role.Name)
	require.True(t, role.DynamicKey)
	require.NotNil(t, role.KeyExpr)
	require.Equal(t, []string{"id"}, role.After())

	eachID := parse(t, `each.value.id`)
	require.Len(t, eachID, 1)
	require.Equal(t, KindEach, eachID[0].Kind)
	require.Equal(t, []string{"value", "id"}, eachID[0].After())
}
