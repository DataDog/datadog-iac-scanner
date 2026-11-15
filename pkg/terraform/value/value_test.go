/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package value

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
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
		{"float", cty.NumberFloatVal(1.5), json.Number("1.5")},
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

// Every number the converter produces must reach the rule payload as an OPA
// number: a decimal literal such as an app-service minimum_tls_version of 1.2
// used to become a *big.Float the payload cannot represent, and the attribute
// reached rules as an empty object.
func mustNumber(t *testing.T, s string) cty.Value {
	t.Helper()
	v, err := cty.ParseNumberVal(s)
	require.NoError(t, err)
	return v
}

func TestNumberPayloadShapes(t *testing.T) {
	c := Converter{Placeholder: "P"}
	// The exact decimal expansion of the float64 1.2, which the previous
	// engine's documents carried through their JSON round-trip.
	const onePointTwo = "1.1999999999999999555910790149937383830547332763671875"
	for _, tc := range []struct {
		name    string
		in      cty.Value
		want    any
		wantOPA string
	}{
		{"zero", cty.NumberIntVal(0), int64(0), "0"},
		{"int", cty.NumberIntVal(42), int64(42), "42"},
		{"negative", cty.NumberIntVal(-7), int64(-7), "-7"},
		{"float", cty.NumberFloatVal(1.5), json.Number("1.5"), "1.5"},
		{"azure app-service minimum_tls_version", mustNumber(t, "1.2"),
			json.Number("1.2"), "1.2"},
		{"negative float", cty.NumberFloatVal(-0.5), json.Number("-0.5"), "-0.5"},
		{"large integer", mustNumber(t, "9223372036854775808"),
			json.Number("9223372036854775808"), "9223372036854775808"},
		{"integer beyond float64 precision", mustNumber(t, "9223372036854775809"),
			json.Number("9223372036854775809"), "9223372036854775809"},
		{"exponent", mustNumber(t, "1e21"),
			json.Number("1000000000000000000000"), "1000000000000000000000"},
		{"beyond float64", mustNumber(t, "1e400"),
			json.Number("1" + strings.Repeat("0", 400)), "1" + strings.Repeat("0", 400)},
		{"precise decimal", mustNumber(t, "1.0000000000000000005"),
			json.Number(mustNumber(t, "1.0000000000000000005").AsBigFloat().Text('f', -1)),
			"1.0000000000000000005"},
		{"big.Float input", cty.NumberVal(new(big.Float).SetPrec(200).SetFloat64(1.2)),
			json.Number(onePointTwo), onePointTwo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.Go(tc.in)
			require.Equal(t, tc.want, got)
			require.IsType(t, tc.want, got)
			// The payload converter must represent the value exactly: no
			// *big.Float, no JSON marshal failure, and an OPA number that
			// holds the source value with no rounding and no saturation.
			b, err := json.Marshal(got)
			require.NoError(t, err)
			v, err := ast.InterfaceToValue(got)
			require.NoError(t, err)
			num, isNumber := v.(ast.Number)
			require.True(t, isNumber, "payload value %v of %v is not a number", v, string(b))
			parsed, ok := new(big.Float).SetPrec(4096).SetString(string(num))
			require.True(t, ok, "OPA number %q does not parse", string(num))
			want, _, err2 := big.ParseFloat(tc.wantOPA, 10, 4096, big.ToNearestEven)
			require.NoError(t, err2)
			require.Zero(t, parsed.Cmp(want), "payload number %s does not match the expected digits %s", string(num), tc.wantOPA)
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
