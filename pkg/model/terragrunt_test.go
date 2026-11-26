/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLineTableLookupOrAnchor(t *testing.T) {
	table := LineTable{
		{FromLine: 1, ToLine: 1, Real: SourceLocation{LineStart: 10}},
		{FromLine: 2, ToLine: 3, Argument: "a", Real: SourceLocation{LineStart: 20}},
	}
	m, ok := table.LookupOrAnchor(3)
	assert.True(t, ok)
	assert.Equal(t, 20, m.Real.LineStart)
	m, ok = table.LookupOrAnchor(99)
	assert.True(t, ok)
	assert.Equal(t, 10, m.Real.LineStart, "an unmapped line falls back to the anchor")
	_, ok = LineTable{}.LookupOrAnchor(1)
	assert.False(t, ok)
}
