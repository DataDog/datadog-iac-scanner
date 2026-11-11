/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJSONSchemaKeepsProviders(t *testing.T) {
	body, ok := parseJSONAsHCLBody([]byte(`{"provider": {"aws": {"region": "x"}}}`), "main.tf.json")
	require.True(t, ok)
	require.Len(t, body.Blocks, 1)
	require.Equal(t, "provider", body.Blocks[0].Type)
	require.Equal(t, []string{"aws"}, body.Blocks[0].Labels)
}
