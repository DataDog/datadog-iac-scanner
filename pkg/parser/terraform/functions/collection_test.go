package functions

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

func TestCollectionConversions(t *testing.T) {
	t.Parallel()

	unknown := cty.UnknownVal(cty.String)
	for _, tc := range []struct {
		name        string
		function    function.Function
		input, want cty.Value
	}{
		{"object to map", ToMapFunc, cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("x"), "b": unknown}), cty.MapVal(map[string]cty.Value{"a": cty.StringVal("x"), "b": unknown})},
		{"map to map", ToMapFunc, cty.MapVal(map[string]cty.Value{"a": unknown}), cty.MapVal(map[string]cty.Value{"a": unknown})},
		{"tuple to list", ToListFunc, cty.TupleVal([]cty.Value{cty.StringVal("x"), unknown}), cty.ListVal([]cty.Value{cty.StringVal("x"), unknown})},
		{"tuple to set", ToSetFunc, cty.TupleVal([]cty.Value{cty.StringVal("x"), unknown}), cty.SetVal([]cty.Value{cty.StringVal("x"), unknown})},
		{"duplicate set elements", ToSetFunc, cty.TupleVal([]cty.Value{cty.StringVal("x"), cty.StringVal("x")}), cty.SetVal([]cty.Value{cty.StringVal("x")})},
		{"unified list elements", ToListFunc, cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.StringVal("2")}), cty.ListVal([]cty.Value{cty.StringVal("1"), cty.StringVal("2")})},
		{"unified map elements", ToMapFunc, cty.ObjectVal(map[string]cty.Value{"a": cty.NumberIntVal(1), "b": unknown}), cty.MapVal(map[string]cty.Value{"a": cty.StringVal("1"), "b": unknown})},
		{"empty list", ToListFunc, cty.EmptyTupleVal, cty.ListValEmpty(cty.DynamicPseudoType)},
		{"null map", ToMapFunc, cty.NullVal(cty.DynamicPseudoType), cty.NullVal(cty.Map(cty.DynamicPseudoType))},
		{"empty map", ToMapFunc, cty.EmptyObjectVal, cty.MapValEmpty(cty.DynamicPseudoType)},
		{"empty set", ToSetFunc, cty.EmptyTupleVal, cty.SetValEmpty(cty.DynamicPseudoType)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.function.Call([]cty.Value{tc.input})
			require.NoError(t, err)
			require.True(t, got.RawEquals(tc.want), "got %s; want %s", got.GoString(), tc.want.GoString())
			if got.Type().IsSetType() && !got.IsWhollyKnown() {
				require.False(t, got.Length().IsKnown(), "unknown elements may coincide")
			}
		})
	}
	t.Run("incompatible input", func(t *testing.T) {
		t.Parallel()
		_, err := ToMapFunc.Call([]cty.Value{cty.StringVal("not a collection")})
		require.Error(t, err)
	})
}
