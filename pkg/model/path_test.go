/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"reflect"
	"testing"
)

func TestDecodeOPAPath_StringKey(t *testing.T) {
	raw := []interface{}{"Properties", "Protocol"}
	got, err := DecodeOPAPath(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := Path{
		{Key: "Properties"},
		{Key: "Protocol"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestDecodeOPAPath_NumericIndex(t *testing.T) {
	raw := []interface{}{"containers", float64(2)}
	got, err := DecodeOPAPath(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[1].IsIndex != true || got[1].Index != 2 {
		t.Errorf("expected index element with Index=2, got %+v", got[1])
	}
	if got[0].IsIndex || got[0].Key != "containers" {
		t.Errorf("expected key element 'containers', got %+v", got[0])
	}
}

func TestDecodeOPAPath_Mixed(t *testing.T) {
	raw := []interface{}{"spec", "containers", float64(0), "image"}
	got, err := DecodeOPAPath(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 elements, got %d", len(got))
	}
	if got[2].IsIndex != true || got[2].Index != 0 {
		t.Errorf("expected index 0 at position 2, got %+v", got[2])
	}
}

func TestDecodeOPAPath_StringVsFloatZero(t *testing.T) {
	// "0" as a string key vs float64(0) as an array index must differ.
	strPath, err := DecodeOPAPath([]interface{}{"data", "0", "key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idxPath, err := DecodeOPAPath([]interface{}{"data", float64(0), "key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strPath[1].IsIndex {
		t.Errorf("string '0' should not be an index, got %+v", strPath[1])
	}
	if !idxPath[1].IsIndex {
		t.Errorf("float64(0) should be an index, got %+v", idxPath[1])
	}
	if reflect.DeepEqual(strPath, idxPath) {
		t.Errorf("string '0' and float64(0) paths should differ")
	}
}

func TestPath_LegacyComponents(t *testing.T) {
	p := Path{
		{Key: "spec"},
		{Key: "containers"},
		{Index: 1, IsIndex: true},
		{Key: "image"},
	}
	got := p.LegacyComponents()
	want := []string{"spec", "containers", "1", "image"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LegacyComponents() = %v, want %v", got, want)
	}
}

func TestDecodeOPAPath_InvalidType(t *testing.T) {
	raw := []interface{}{"key", true}
	_, err := DecodeOPAPath(raw)
	if err == nil {
		t.Error("expected error for unsupported type bool")
	}
}

func TestDecodeOPAPathRejectsInvalidIndices(t *testing.T) {
	for _, value := range []interface{}{float64(-1), float64(1.5), int(-1)} {
		if _, err := DecodeOPAPath([]interface{}{"items", value}); err == nil {
			t.Errorf("DecodeOPAPath accepted invalid index %v", value)
		}
	}
}

func TestDecodeOPAPath_NotArray(t *testing.T) {
	_, err := DecodeOPAPath("not-an-array")
	if err == nil {
		t.Error("expected error for non-array input")
	}
}
