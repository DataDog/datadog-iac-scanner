/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package address

import (
	"fmt"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

func TestBlockAddress(t *testing.T) {
	for _, tc := range []struct {
		block Block
		want  string
	}{
		{Block{KindResource, "aws_s3_bucket", "example"}, "aws_s3_bucket.example"},
		{Block{KindData, "aws_ami", "ubuntu"}, "data.aws_ami.ubuntu"},
		{Block{KindEphemeral, "aws_secret", "login"}, "ephemeral.aws_secret.login"},
		{Block{KindModule, "", "network"}, "module.network"},
		{Block{KindVariable, "", "size"}, "var.size"},
		{Block{KindLocal, "", "name"}, "local.name"},
		{Block{KindOutput, "", "config"}, "output.config"},
		{Block{KindProvider, "aws", ""}, "provider.aws"},
		{Block{KindProvider, "aws", "west"}, "provider.aws.west"},
		{Block{KindCheck, "", "health"}, "check.health"},
		{Block{KindTerraform, "", ""}, "terraform"},
		{Block{"moved", "", ""}, "moved"},
	} {
		require.Equal(t, tc.want, Addr(tc.block), tc.block)
	}
}

func TestInstance(t *testing.T) {
	bucket := Block{KindResource, "aws_s3_bucket", "example"}
	require.Equal(t, "aws_s3_bucket.example", Instance("", bucket, ""))
	require.Equal(t, "aws_s3_bucket.example[0]", Instance("", bucket, "[0]"))
	require.Equal(t, `module.a["x"].aws_s3_bucket.example[0]`, Instance(`module.a["x"]`, bucket, "[0]"))
	// Go-quoted for_each keys the evaluator names internally become HCL.
	require.Equal(t, `aws_s3_bucket.example["prod"]`, Instance("", bucket, `["prod"]`))
	// Non-instance blocks never carry a key: a module call block configures
	// every instance at once.
	module := Block{KindModule, "", "network"}
	require.Equal(t, `module.a["x"].module.network`, Instance(`module.a["x"]`, module, "[0]"))
	require.Equal(t, "var.size", Instance("", Block{KindVariable, "", "size"}, "[0]"))
}

func TestInstanceKeyEscaping(t *testing.T) {
	for _, key := range []string{"", "a.b", `a"b`, `a\b`, `["]`, "\n\t\a", "${key}", "%{key}", "日本語"} {
		t.Run(fmt.Sprintf("%q", key), func(t *testing.T) {
			addr := Instance(`module.a["x"].module.b[0]`, Block{KindData, "example_type", "example"}, fmt.Sprintf("[%q]", key))
			traversal, diags := hclsyntax.ParseTraversalAbs([]byte(addr), "", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			index := traversal[len(traversal)-1].(hcl.TraverseIndex)
			require.Equal(t, key, index.Key.AsString())
		})
	}
}
