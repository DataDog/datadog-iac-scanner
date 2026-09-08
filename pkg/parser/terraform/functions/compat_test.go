/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestLengthString(t *testing.T) {
	t.Parallel()

	got, err := LengthFunc.Call([]cty.Value{cty.StringVal("hello")})
	if err != nil {
		t.Fatalf("LengthFunc.Call() error = %v", err)
	}
	if !got.RawEquals(cty.NumberIntVal(5)) {
		t.Fatalf("length = %#v, want 5", got)
	}
}

func TestLengthList(t *testing.T) {
	t.Parallel()

	got, err := LengthFunc.Call([]cty.Value{cty.ListVal([]cty.Value{
		cty.StringVal("a"),
		cty.StringVal("b"),
	})})
	if err != nil {
		t.Fatalf("LengthFunc.Call() error = %v", err)
	}
	if !got.RawEquals(cty.NumberIntVal(2)) {
		t.Fatalf("length = %#v, want 2", got)
	}
}

func TestCoalesceSkipsEmptyString(t *testing.T) {
	t.Parallel()

	got, err := CoalesceFunc.Call([]cty.Value{
		cty.NullVal(cty.String),
		cty.StringVal(""),
		cty.StringVal("fallback"),
	})
	if err != nil {
		t.Fatalf("CoalesceFunc.Call() error = %v", err)
	}
	if !got.RawEquals(cty.StringVal("fallback")) {
		t.Fatalf("coalesce = %#v, want fallback", got)
	}
}

func TestLookupDefault(t *testing.T) {
	t.Parallel()

	input := cty.MapVal(map[string]cty.Value{"a": cty.StringVal("x")})
	got, err := LookupFunc.Call([]cty.Value{input, cty.StringVal("b"), cty.StringVal("d")})
	if err != nil {
		t.Fatalf("LookupFunc.Call() error = %v", err)
	}
	if !got.RawEquals(cty.StringVal("d")) {
		t.Fatalf("lookup = %#v, want d", got)
	}
}

func TestIndexFindsValue(t *testing.T) {
	t.Parallel()

	got, err := IndexFunc.Call([]cty.Value{
		cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}),
		cty.StringVal("b"),
	})
	if err != nil {
		t.Fatalf("IndexFunc.Call() error = %v", err)
	}
	if !got.RawEquals(cty.NumberIntVal(1)) {
		t.Fatalf("index = %#v, want 1", got)
	}
}

func TestReplaceLiteralAndRegex(t *testing.T) {
	t.Parallel()

	got, err := ReplaceFunc.Call([]cty.Value{
		cty.StringVal("a-b-c"),
		cty.StringVal("-"),
		cty.StringVal("_"),
	})
	if err != nil {
		t.Fatalf("ReplaceFunc.Call() error = %v", err)
	}
	if !got.RawEquals(cty.StringVal("a_b_c")) {
		t.Fatalf("replace = %#v, want a_b_c", got)
	}

	got, err = ReplaceFunc.Call([]cty.Value{
		cty.StringVal("hello 123"),
		cty.StringVal("/[0-9]+/"),
		cty.StringVal("N"),
	})
	if err != nil {
		t.Fatalf("ReplaceFunc.Call() regex error = %v", err)
	}
	if !got.RawEquals(cty.StringVal("hello N")) {
		t.Fatalf("replace regex = %#v, want hello N", got)
	}
}
