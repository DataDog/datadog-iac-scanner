package functions

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestToMapObject(t *testing.T) {
	t.Parallel()

	val := cty.ObjectVal(map[string]cty.Value{
		"a": cty.StringVal("x"),
		"b": cty.StringVal("y"),
	})
	result, err := ToMapFunc.Call([]cty.Value{val})
	if err != nil {
		t.Fatalf("ToMapFunc.Call() error = %v", err)
	}
	if !result.Type().IsMapType() {
		t.Fatalf("result type = %s, want map", result.Type().FriendlyName())
	}
	if !result.Type().ElementType().Equals(cty.String) {
		t.Fatalf("map element type = %s, want string", result.Type().ElementType().FriendlyName())
	}
	if result.LengthInt() != 2 {
		t.Fatalf("map length = %d, want 2", result.LengthInt())
	}
}

func TestToMapMap(t *testing.T) {
	t.Parallel()

	val := cty.MapVal(map[string]cty.Value{
		"a": cty.StringVal("x"),
	})
	result, err := ToMapFunc.Call([]cty.Value{val})
	if err != nil {
		t.Fatalf("ToMapFunc.Call() error = %v", err)
	}
	if !result.Type().Equals(val.Type()) {
		t.Fatalf("result type = %s, want %s", result.Type().FriendlyName(), val.Type().FriendlyName())
	}
}
