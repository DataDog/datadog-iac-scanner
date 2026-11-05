package functions

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

func evalTryExpr(t *testing.T, src string, vars map[string]cty.Value) cty.Value {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "t.tf", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	ctx := &hcl.EvalContext{
		Variables: vars,
		Functions: map[string]function.Function{"try": TryFunc, "can": CanFunc},
	}
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	return v
}

func instanceVars() map[string]cty.Value {
	instance := cty.ObjectVal(map[string]cty.Value{
		"triggers": cty.MapVal(map[string]cty.Value{"a": cty.StringVal("x")}),
		"name":     cty.StringVal("n"),
	})
	return map[string]cty.Value{
		"null_resource": cty.ObjectVal(map[string]cty.Value{"r": instance}),
	}
}

func TestTryMissingNestedKeyFallsBack(t *testing.T) {
	v := evalTryExpr(t, `try(null_resource.r.triggers.acl, "fallback")`, instanceVars())
	if !v.IsKnown() || v.AsString() != "fallback" {
		t.Fatalf("missing nested key must fall back, got %#v", v)
	}
	if c := evalTryExpr(t, `can(null_resource.r.triggers.acl)`, instanceVars()); !c.IsKnown() || c.True() {
		t.Fatalf("can on a missing nested key must be false, got %#v", c)
	}
}

func TestTryMissingInstanceAttributeIsUnknown(t *testing.T) {
	v := evalTryExpr(t, `try(null_resource.r.id, "fallback")`, instanceVars())
	if v.IsKnown() {
		t.Fatalf("a computed instance attribute must be unknown, got %#v", v)
	}
	if c := evalTryExpr(t, `can(null_resource.r.id)`, instanceVars()); c.IsKnown() {
		t.Fatalf("can on a computed attribute must be unknown, got %#v", c)
	}
}

func TestTryIndexOutOfRangeDespiteComputedElementFallsBack(t *testing.T) {
	// A one-element tuple cannot have index 1, even when that element is a
	// computed instance attribute. try must take the fallback; can is false.
	v := evalTryExpr(t, `try([null_resource.r.id][1], "public-read")`, instanceVars())
	if !v.IsKnown() || v.AsString() != "public-read" {
		t.Fatalf("index out of range must fall back, got %#v", v)
	}
	if c := evalTryExpr(t, `can([null_resource.r.id][1])`, instanceVars()); !c.IsKnown() || c.True() {
		t.Fatalf("can on an out-of-range index must be false, got %#v", c)
	}
}

func TestTryDeadBranchIndexDoesNotFail(t *testing.T) {
	// The selected branch only reads a computed attribute; the dead branch's
	// out-of-range index must not make try fail.
	v := evalTryExpr(t, `try(true ? null_resource.r.id : [1][5], "fallback")`, instanceVars())
	if v.IsKnown() {
		t.Fatalf("computed attribute in the live branch must be unknown, got %#v", v)
	}
}

func TestTryNestedTryGuardsInnerIndex(t *testing.T) {
	v := evalTryExpr(t, `try(try([1][5], 1) + null_resource.r.id, "fallback")`, instanceVars())
	if v.IsKnown() {
		t.Fatalf("outer try must stay unknown when the inner try guards the index, got %#v", v)
	}
}

func TestTryIndexIntoIndexedCollection(t *testing.T) {
	v := evalTryExpr(t, `try([[1]][0][5], "fallback")`, instanceVars())
	if !v.IsKnown() || v.AsString() != "fallback" {
		t.Fatalf("nested out-of-range index must fall back, got %#v", v)
	}
}
