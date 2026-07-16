/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// PathResolution describes how precisely a path matched source metadata.
type PathResolution struct {
	MatchedElements int  // path components consumed before the walk stopped
	TotalElements   int  // total input path length
	StructuralExact bool // true when all components were found in the tree
}

func ResolveTypedPathWithStatus(root interface{}, path model.Path) PathResolution {
	components := resolutionComponents(path)
	_, remaining, stoppedString, _ := lineFromPath(root, components)
	return PathResolution{
		MatchedElements: len(components) - len(remaining),
		TotalElements:   len(components),
		StructuralExact: len(remaining) == 0 && stoppedString == "",
	}
}

// lineFromPath returns the deepest source line reached and any unmatched path.
// stoppedString lets callers continue traversal inside JSON-encoded values.
//
//nolint:gocyclo // path-shape branching is inherent to multi-platform line metadata.
func lineFromPath(root interface{}, path []string) (best int, remaining []string, stoppedString string, jsonAnchor int) {
	node := root
	lines, _ := mapValue(root, "_dd_lines")
	best = updateBest(best, nodeSelfLine(root, lines))

	i := 0
	for i < len(path) {
		component := strings.TrimPrefix(path[i], numericKeyPrefix)

		keyEntry, hasKeyEntry := mapValue(lines, "_dd_"+component)
		if hasKeyEntry {
			best = updateBest(best, lineValue(keyEntry))
		}

		if idx, ok := nextIndex(path, i); ok {
			elem, hasElem, dataElem, hasDataElem := sequenceElement(node, lines, keyEntry, component, idx)
			if hasElem || hasDataElem {
				if hasElem {
					best = updateBest(best, defaultLine(elem))
					lines = elem
				} else {
					lines = nil
				}
				if hasDataElem {
					best = updateBest(best, lineValue(dataElem))
					if nested, ok := mapValue(dataElem, "_dd_lines"); ok {
						lines = nested
					}
				}
				node = dataElem
				i += 2
				continue
			}
		}

		// Terraform set blocks historically omit their index from finding paths.
		// A singleton sequence is unambiguous, so descend into its only element.
		if i+1 < len(path) && hasConstantValueAnchor(keyEntry) {
			elem, hasElem, dataElem, hasDataElem := singletonSequenceElement(node, keyEntry, component)
			if hasElem || hasDataElem {
				if hasElem {
					best = updateBest(best, defaultLine(elem))
					lines = elem
				} else {
					lines = nil
				}
				if hasDataElem {
					best = updateBest(best, lineValue(dataElem))
					if nested, ok := mapValue(dataElem, "_dd_lines"); ok {
						lines = nested
					}
				}
				node = dataElem
				i++
				continue
			}
		}

		if nestedLines, ok := mapValue(keyEntry, "_dd_lines"); ok && hasStructuralNestedLines(nestedLines) {
			best = updateBest(best, defaultLine(nestedLines))
			lines = nestedLines
			node = nil
			i++
			continue
		}

		if child, ok := mapValue(node, component); ok {
			if s, isString := child.(string); isString && s != "" && i+1 < len(path) {
				stoppedString = s
				remaining = path[i+1:]
				if nested, ok := mapValue(keyEntry, "_dd_lines"); ok {
					if cv, ok := mapValue(nested, "_dd_constant_value"); ok {
						jsonAnchor = updateBest(0, lineValue(cv))
					}
				}
				return best, remaining, stoppedString, jsonAnchor
			}

			node = child
			best = updateBest(best, lineValue(child))
			if nested, ok := mapValue(child, "_dd_lines"); ok {
				lines = nested
				best = updateBest(best, defaultLine(nested))
			} else {
				lines = nil
			}
			i++
			continue
		}

		break
	}

	return best, path[i:], "", 0
}

func sequenceElement(
	node, lines, keyEntry interface{},
	component string,
	idx int,
) (elem interface{}, hasElem bool, dataElem interface{}, hasDataElem bool) {
	arr, hasArr := mapValue(keyEntry, "_dd_arr")
	if !hasArr {
		if def, ok := mapValue(lines, "_dd__default"); ok {
			arr, hasArr = mapValue(def, "_dd_arr")
		}
	}
	if hasArr {
		elem, hasElem = sequenceValue(arr, idx)
	}

	if dataArr, ok := mapValue(node, component); ok {
		dataElem, hasDataElem = sequenceValue(dataArr, idx)
	}
	return elem, hasElem, dataElem, hasDataElem
}

func singletonSequenceElement(
	node, keyEntry interface{},
	component string,
) (elem interface{}, hasElem bool, dataElem interface{}, hasDataElem bool) {
	arr, _ := mapValue(keyEntry, "_dd_arr")
	dataArr, _ := mapValue(node, component)
	arrLen := sequenceLen(arr)
	dataLen := sequenceLen(dataArr)
	if arrLen > 1 || dataLen > 1 || arrLen+dataLen == 0 {
		return nil, false, nil, false
	}
	if arrLen == 1 {
		elem, hasElem = sequenceValue(arr, 0)
	}
	if dataLen == 1 {
		dataElem, hasDataElem = sequenceValue(dataArr, 0)
	}
	return elem, hasElem, dataElem, hasDataElem
}

func hasConstantValueAnchor(keyEntry interface{}) bool {
	nested, ok := mapValue(keyEntry, "_dd_lines")
	if !ok {
		return false
	}
	_, ok = mapValue(nested, "_dd_constant_value")
	return ok
}

func nextIndex(path []string, i int) (int, bool) {
	if i+1 >= len(path) {
		return 0, false
	}
	idx, err := strconv.Atoi(path[i+1])
	if err != nil {
		return 0, false
	}
	return idx, true
}

func nodeSelfLine(node, lines interface{}) interface{} {
	if ln, ok := mapValue(node, "_dd_line"); ok {
		return ln
	}
	return defaultLine(lines)
}

func defaultLine(lines interface{}) interface{} {
	if def, ok := mapValue(lines, "_dd__default"); ok {
		return lineValue(def)
	}
	return nil
}

func updateBest(current int, candidate interface{}) int {
	if line := toLine(candidate); line > 0 {
		return line
	}
	return current
}

func toLine(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case int32:
		return int(n)
	case json.Number:
		line, _ := strconv.Atoi(n.String())
		return line
	default:
		return 0
	}
}

func lineValue(value interface{}) interface{} {
	result, _ := mapValue(value, "_dd_line")
	return result
}

func mapValue(value interface{}, key string) (interface{}, bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		result, ok := typed[key]
		return result, ok
	case model.Document:
		result, ok := typed[key]
		return result, ok
	case map[string]model.LineObject:
		result, ok := typed[key]
		return result, ok
	case map[string]*model.LineObject:
		result, ok := typed[key]
		return result, ok
	case model.LineObject:
		return lineObjectValue(&typed, key)
	case *model.LineObject:
		return lineObjectValue(typed, key)
	}

	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil, false
	}
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}
	result := rv.MapIndex(reflect.ValueOf(key).Convert(rv.Type().Key()))
	if !result.IsValid() {
		return nil, false
	}
	return result.Interface(), true
}

func lineObjectValue(value *model.LineObject, key string) (interface{}, bool) {
	if value == nil {
		return nil, false
	}
	switch key {
	case "_dd_line":
		return value.Line, true
	case "_dd_arr":
		return value.Arr, value.Arr != nil
	case "_dd_lines":
		return value.Map, value.Map != nil
	default:
		return nil, false
	}
}

func sequenceValue(value interface{}, index int) (interface{}, bool) {
	if index < 0 {
		return nil, false
	}
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil, false
	}
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	if (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) || index >= rv.Len() {
		return nil, false
	}
	return rv.Index(index).Interface(), true
}

func sequenceLen(value interface{}) int {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return 0
	}
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return 0
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return 0
	}
	return rv.Len()
}

func hasStructuralNestedLines(nested interface{}) bool {
	rv := reflect.ValueOf(nested)
	if !rv.IsValid() {
		return false
	}
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return false
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return false
	}
	iter := rv.MapRange()
	for iter.Next() {
		key := iter.Key().String()
		if key != "_dd_constant_value" && key != "_dd__default" {
			return true
		}
	}
	return false
}
