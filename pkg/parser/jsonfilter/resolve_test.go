/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package jsonfilter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolve_ParsesCloudWatchPattern(t *testing.T) {
	got := Resolve(`{ $.eventName = CreateNetworkAcl }`)
	require.Contains(t, got, "_dd_filter_expr")
	require.NotEqual(t, `{ $.eventName = CreateNetworkAcl }`, got)
}

func TestResolve_LeavesUnparseablePattern(t *testing.T) {
	in := `{ $.eventType % "ConsoleLogin" }`
	require.Equal(t, in, Resolve(in))
}
