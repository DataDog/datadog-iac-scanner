package tfeval

import (
	"testing"
	"github.com/zclconf/go-cty/cty"
)

func TestNullTypeCacheCollision(t *testing.T) {
	// null string and null number produce the same cache key fragment
	keyStr := canonicalInputsKey(map[string]cty.Value{"x": cty.NullVal(cty.String)})
	keyNum := canonicalInputsKey(map[string]cty.Value{"x": cty.NullVal(cty.Number)})
	if keyStr == keyNum {
		t.Errorf("null-string and null-number produce the same cache key: %q", keyStr)
	}
}
