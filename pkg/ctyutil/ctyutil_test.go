/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package ctyutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestConcreteString_nullIsNotConcrete(t *testing.T) {
	_, ok := ConcreteString(cty.NullVal(cty.String))
	require.False(t, ok)
	require.True(t, cty.NullVal(cty.String).IsWhollyKnown())
}

func TestContainsNestedUnknown_nullCollection(t *testing.T) {
	require.NotPanics(t, func() {
		require.False(t, ContainsNestedUnknown(cty.NullVal(cty.List(cty.String))))
	})
}

func TestLiteralInt_rejectsFractionalNumber(t *testing.T) {
	_, ok := LiteralInt(cty.NumberFloatVal(0.5))
	require.False(t, ok)
}

func TestFormatIndexKey(t *testing.T) {
	s, ok := FormatIndexKey(cty.StringVal("bar"))
	require.True(t, ok)
	require.Equal(t, `["bar"]`, s)

	_, ok = FormatIndexKey(cty.NullVal(cty.String))
	require.False(t, ok)
}
