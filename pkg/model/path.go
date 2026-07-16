/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// PathElement is one component of a structured source/authoring path.
type PathElement struct {
	Key     string // non-empty for object keys
	Index   int    // valid only when IsIndex is true
	IsIndex bool
}

// Path is an ordered sequence of path components.
type Path []PathElement

// DecodeOPAPath converts the OPA attributePath value ([]interface{} of strings/numbers)
// into a typed Path, preserving the distinction between string keys and array indices.
func DecodeOPAPath(raw interface{}) (Path, error) {
	slice, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("attributePath is not an array: %T", raw)
	}
	out := make(Path, len(slice))
	for i, v := range slice {
		element, err := decodeOPAPathElement(v)
		if err != nil {
			return nil, fmt.Errorf("attributePath element %d: %w", i, err)
		}
		out[i] = element
	}
	return out, nil
}

func decodeOPAPathElement(value interface{}) (PathElement, error) {
	switch typed := value.(type) {
	case string:
		return PathElement{Key: typed}, nil
	case float64:
		if typed < 0 || typed != math.Trunc(typed) || typed > float64(math.MaxInt) {
			return PathElement{}, fmt.Errorf("invalid array index %v", typed)
		}
		return PathElement{Index: int(typed), IsIndex: true}, nil
	case int:
		return integerPathElement(int64(typed))
	case int64:
		return integerPathElement(typed)
	case json.Number:
		index, err := typed.Int64()
		if err != nil {
			return PathElement{}, fmt.Errorf("invalid number %q", typed)
		}
		return integerPathElement(index)
	default:
		return PathElement{}, fmt.Errorf("unsupported type %T", value)
	}
}

func integerPathElement(index int64) (PathElement, error) {
	if index < 0 || strconv.IntSize == 32 && index > math.MaxInt32 {
		return PathElement{}, fmt.Errorf("invalid array index %d", index)
	}
	return PathElement{Index: int(index), IsIndex: true}, nil
}

// LegacyComponents returns string representations for backward-compat dotted join.
// String keys are returned as-is; array indices are formatted with Itoa.
func (p Path) LegacyComponents() []string {
	out := make([]string, len(p))
	for i, el := range p {
		if el.IsIndex {
			out[i] = strconv.Itoa(el.Index)
		} else {
			out[i] = el.Key
		}
	}
	return out
}
