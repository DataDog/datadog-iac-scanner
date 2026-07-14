/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// GetLineBySearchLine finds a key's source line from the parser's line metadata.
func GetLineBySearchLine(pathComponents []string, file *model.FileMetadata) (int, error) {
	if len(pathComponents) == 0 {
		return 1, nil
	}

	target := pathComponents[len(pathComponents)-1]
	objectPath := pathComponents[:len(pathComponents)-1]
	targetKey := "_dd_" + target
	if line := lineAtJoinedPath(file.LineInfoDocument, objectPath, []string{"_dd_lines", targetKey, "_dd_line"}); line > 0 {
		return line, nil
	}
	if line := lineAtJoinedPath(file.LineInfoDocument, objectPath, []string{target, "_dd_lines", "_dd__default", "_dd_line"}); line > 0 {
		return line, nil
	}

	arrayObject := ""
	foundArrayIdx := false
	for i := len(pathComponents) - 1; i >= 0; i-- {
		if _, err := strconv.Atoi(pathComponents[i]); err == nil {
			foundArrayIdx = true
			continue
		}
		if foundArrayIdx {
			arrayObject = pathComponents[i]
			break
		}
	}
	arrayPath := make([]string, 1, len(pathComponents)*3)
	arrayPath[0] = pathComponents[0]
	if arrayObject == pathComponents[0] {
		arrayPath = append(arrayPath[:0], "_dd_lines", "_dd_"+arrayObject, "_dd_arr")
	}
	if len(pathComponents) > 2 {
		for _, pathItem := range pathComponents[1 : len(pathComponents)-1] {
			if pathItem == arrayObject {
				arrayPath = append(arrayPath, "_dd_lines", "_dd_"+pathItem, "_dd_arr")
			} else {
				arrayPath = append(arrayPath, pathItem)
			}
		}
	}

	if line := lineAtJoinedPath(file.LineInfoDocument, arrayPath, []string{target, "_dd__default", "_dd_line"}); line > 0 {
		return line, nil
	}
	if line := lineAtJoinedPath(file.LineInfoDocument, arrayPath, []string{targetKey, "_dd_line"}); line > 0 {
		return line, nil
	}
	return -1, nil
}

func lineAtJoinedPath(root interface{}, prefix, suffix []string) int {
	value := root
	for _, path := range [2][]string{prefix, suffix} {
		for _, component := range path {
			var ok bool
			value, ok = pathComponent(value, component)
			if !ok {
				return -1
			}
		}
	}
	return positiveInt(indirectValue(reflect.ValueOf(value)))
}

func pathComponent(value interface{}, component string) (interface{}, bool) {
	switch current := value.(type) {
	case map[string]interface{}:
		next, ok := current[component]
		return next, ok
	case model.Document:
		next, ok := current[component]
		return next, ok
	case []interface{}:
		index, ok := pathIndex(component, len(current))
		if !ok {
			return nil, false
		}
		return current[index], true
	case map[string]*model.LineObject:
		next, ok := current[component]
		return next, ok
	case *model.LineObject:
		if current == nil {
			return nil, false
		}
		switch component {
		case "_dd_line":
			return current.Line, true
		case "_dd_arr":
			return current.Arr, true
		}
		return nil, false
	case []map[string]*model.LineObject:
		index, ok := pathIndex(component, len(current))
		if !ok {
			return nil, false
		}
		return current[index], true
	default:
		return reflectedPathComponent(value, component)
	}
}

func pathIndex(component string, length int) (int, bool) {
	index, err := strconv.Atoi(component)
	return index, err == nil && index >= 0 && index < length
}

func reflectedPathComponent(current interface{}, component string) (interface{}, bool) {
	value := indirectValue(reflect.ValueOf(current))
	if !value.IsValid() {
		return nil, false
	}
	switch value.Kind() {
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return nil, false
		}
		value = value.MapIndex(reflect.ValueOf(component).Convert(value.Type().Key()))
	case reflect.Slice, reflect.Array:
		index, ok := pathIndex(component, value.Len())
		if !ok {
			return nil, false
		}
		value = value.Index(index)
	case reflect.Struct:
		value = structJSONField(value, component)
	default:
		return nil, false
	}
	value = indirectValue(value)
	if !value.IsValid() || !value.CanInterface() {
		return nil, false
	}
	return value.Interface(), true
}

func indirectValue(value reflect.Value) reflect.Value {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

func structJSONField(value reflect.Value, name string) reflect.Value {
	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag == name {
			return value.Field(i)
		}
	}
	return reflect.Value{}
}

func positiveInt(value reflect.Value) int {
	if !value.IsValid() {
		return -1
	}
	var line int64
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		line = value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		line = int64(value.Uint())
	case reflect.Float32, reflect.Float64:
		line = int64(value.Float())
	case reflect.String:
		parsed, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil {
			return -1
		}
		line = parsed
	default:
		return -1
	}
	if line <= 0 {
		return -1
	}
	return int(line)
}
