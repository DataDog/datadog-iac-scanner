/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVarsFile(t *testing.T) {
	attrs := ParseVarsFile([]byte("a = 1\nb = \"x\"\n"), "terraform.tfvars")
	require.Len(t, attrs, 2)
	assert.Equal(t, 2, attrs["b"].Range.Start.Line)

	attrs = ParseVarsFile([]byte(`{"a": 1}`), "terraform.tfvars.json")
	require.Len(t, attrs, 1)

	assert.Nil(t, ParseVarsFile([]byte("a = ="), "terraform.tfvars"))
}
