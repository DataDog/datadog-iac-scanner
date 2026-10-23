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

func TestInstanceKeyEscaping(t *testing.T) {
	for _, key := range []string{"", "a.b", `a"b`, `a\b`, `["]`, "\n\t\a", "${key}", "%{key}", "日本語"} {
		t.Run(fmt.Sprintf("%q", key), func(t *testing.T) {
			addr := Resource(`module.a["x"].module.b[0]`, "data", "example_type", fmt.Sprintf("example[%q]", key))
			traversal, diags := hclsyntax.ParseTraversalAbs([]byte(addr), "", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			index := traversal[len(traversal)-1].(hcl.TraverseIndex)
			require.Equal(t, key, index.Key.AsString())
		})
	}
	require.Equal(t, "aws_s3_bucket.example[2]", Resource("", "resource", "aws_s3_bucket", "example[2]"))
	require.Equal(t, `data.example_type.example["key"]`, Resource("", "data", "example_type", `example["key"]`))
}
