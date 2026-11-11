/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package value

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestNewPlaceholderIsRandom(t *testing.T) {
	a, b := NewPlaceholder(), NewPlaceholder()
	require.NotEqual(t, a, b)
	require.True(t, strings.HasPrefix(a, "\u0000dd-unknown-"))
	require.Len(t, a, len("\u0000dd-unknown-")+32)
}

func TestConverter(t *testing.T) {
	c := Converter{Placeholder: "P"}
	for _, tc := range []struct {
		name string
		in   cty.Value
		want any
	}{
		{"unknown", cty.UnknownVal(cty.String), "P"},
		{"refined unknown string", cty.UnknownVal(cty.String).Refine().StringPrefix("arn:").NewValue(), "P"},
		{"dynamic unknown", cty.DynamicVal, "P"},
		{"string", cty.StringVal("${aws:username}"), "${aws:username}"},
		{"int", cty.NumberIntVal(3), int64(3)},
		{"float", cty.NumberFloatVal(1.5), 1.5},
		{"bool", cty.True, true},
		{"null", cty.NullVal(cty.String), nil},
		{"sensitive", cty.StringVal("s").Mark("sensitive"), "s"},
		{
			"list with an unknown element",
			cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.UnknownVal(cty.String), cty.NullVal(cty.String)}),
			[]any{"a", "P", nil},
		},
		{"unknown list", cty.UnknownVal(cty.List(cty.String)), "P"},
		{"set keys stay strings", cty.SetVal([]cty.Value{cty.StringVal("1")}), []any{"1"}},
		{
			"object keeps known keys",
			cty.ObjectVal(map[string]cty.Value{
				"a": cty.StringVal("x"), "b": cty.UnknownVal(cty.Number), "c": cty.NullVal(cty.String),
			}),
			map[string]any{"a": "x", "b": "P"},
		},
		{"unknown object", cty.UnknownVal(cty.Map(cty.String)), "P"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, c.Go(tc.in))
		})
	}
}

func TestPresentAndHasUnknown(t *testing.T) {
	require.False(t, Present(cty.NullVal(cty.String)))
	require.True(t, Present(cty.UnknownVal(cty.String)))
}

func TestSubstitute(t *testing.T) {
	const placeholder = "\u0000dd-unknown-0123"
	for _, tc := range []struct {
		name, in, want string
		changed        bool
	}{
		{"no marker", "arn:aws:s3:::b", "arn:aws:s3:::b", false},
		{"raw marker keeps known parts", "a" + UnknownMarker + "b", "a" + placeholder + "b", true},
		{"marker alone", UnknownMarker, placeholder, true},
		{"marker in JSON text", `{"Resource":["` + JSONUnknownMarker + `","*"]}`, `{"Resource":["\u0000dd-unknown-0123","*"]}`, true},
	} {
		got, changed := Substitute(tc.in, placeholder)
		require.Equal(t, tc.want, got, tc.name)
		require.Equal(t, tc.changed, changed, tc.name)
	}
	require.True(t, HasUnknownMarker(UnknownMarker))
	require.True(t, HasUnknownMarker(JSONUnknownMarker))
	require.False(t, HasUnknownMarker(NewPlaceholder()))

	c := Converter{Placeholder: placeholder}
	require.Equal(t, placeholder, c.Go(cty.StringVal(UnknownMarker)))
	require.Equal(t, "arn:aws:iam::"+placeholder+":root", c.Go(cty.StringVal("arn:aws:iam::"+UnknownMarker+":root")))
}
