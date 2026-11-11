/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetermineActualBaseIndentOutOfRange(t *testing.T) {
	require.Empty(t, determineActualBaseIndent(nil, 6, 1))
	require.Equal(t, "  ", determineActualBaseIndent([]string{"x {", "  a = 1"}, 2, -3))
}
