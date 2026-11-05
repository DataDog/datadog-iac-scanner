/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnresolvedLocalRendersAsItsExpression(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "mod", map[string]string{"main.tf": `
data "aws_caller_identity" "current" {}
locals {
  account = data.aws_caller_identity.current.account_id
  chained = local.account
  known   = "123456789012"
}
resource "aws_kms_key" "k" {
  description = "arn:aws:iam::${local.chained}:root"
  policy = jsonencode({
    Principal = { AWS = "arn:aws:iam::${local.account}:root" }
    Known     = local.known
  })
}
`})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	r := findResource(t, resources, "aws_kms_key", "k")
	doc := AttributesToDocument(&r)
	require.Equal(t, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root", doc["description"])
	require.JSONEq(t,
		`{"Principal":{"AWS":"arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"},"Known":"123456789012"}`,
		doc["policy"].(string))
}
