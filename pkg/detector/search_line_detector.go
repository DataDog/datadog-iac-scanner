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

// GetLineBySearchLine finds the line of a key in the original file, given its
// path as a slice of strings, by walking the file's line-info document.
//
// The document is walked in place rather than serialized: this runs once per
// finding, and the document can be hundreds of KB. Returns -1 when no line
// marker matches.
func GetLineBySearchLine(pathComponents []string, file *model.FileMetadata) int {
	if len(pathComponents) == 0 {
		return 1
	}
	objPath, arrPath, target := searchLinePaths(pathComponents)
	// Each shared prefix is resolved once; the candidate suffixes are short
	// and cheap to walk from the resolved node. Candidates keep the order the
	// previous gjson implementation tried them in.
	if node, ok := resolvePath(file.LineInfoDocument, objPath); ok {
		for _, suffix := range [][]string{
			{"_dd_lines", "_dd_" + target, "_dd_line"},
			{target, "_dd_lines", "_dd__default", "_dd_line"},
		} {
			if line := lineAtPath(node, suffix); line > 0 {
				return line
			}
		}
	}
	if node, ok := resolvePath(file.LineInfoDocument, arrPath); ok {
		for _, suffix := range [][]string{
			{target, "_dd__default", "_dd_line"},
			{"_dd_" + target, "_dd_line"},
		} {
			if line := lineAtPath(node, suffix); line > 0 {
				return line
			}
		}
	}
	return -1
}

// searchLinePaths returns the object path and the _dd_lines array path leading
// to the target key (the last path item). The array path descends into the
// _dd_arr line markers of the last array in the path, needed where array
// elements are <"key": "value"> pairs rather than <object>.
//
// The root comparison against arrayObject uses the raw (unescaped) root:
// the previous gjson implementation compared against a dot-escaped path, so a
// dotted root key that was also the array object never matched. Paths here
// address map keys directly, so the raw comparison is the intended behavior
// and differs from the old one only for that dotted-root case.
func searchLinePaths(pathItems []string) (objPath, arrPath []string, target string) {
	target = pathItems[len(pathItems)-1]

	arrayObject := ""
	foundArrayIdx := false
	for i := len(pathItems) - 1; i >= 0; i-- {
		if _, err := strconv.Atoi(pathItems[i]); err == nil {
			foundArrayIdx = true
			continue
		}
		if foundArrayIdx {
			arrayObject = pathItems[i]
			break
		}
	}

	var inner []string
	if len(pathItems) > 1 {
		inner = pathItems[1 : len(pathItems)-1]
	}
	objPath = make([]string, 0, len(inner)+1)
	arrPath = make([]string, 0, len(inner)+3)

	root := pathItems[0]
	objPath = append(objPath, root)
	if arrayObject == root {
		arrPath = append(arrPath, "_dd_lines", "_dd_"+arrayObject, "_dd_arr")
	} else {
		arrPath = append(arrPath, root)
	}
	for _, item := range inner {
		objPath = append(objPath, item)
		if item == arrayObject {
			arrPath = append(arrPath, "_dd_lines", "_dd_"+item, "_dd_arr")
		} else {
			arrPath = append(arrPath, item)
		}
	}
	return objPath, arrPath, target
}

// resolvePath walks path from doc the way lineAtPath does and returns the
// node it lands on, so several candidate suffixes can share one prefix walk.
func resolvePath(doc interface{}, path []string) (interface{}, bool) {
	v := doc
	for _, seg := range path {
		next, ok := childAt(v, seg)
		if !ok {
			return nil, false
		}
		v = next
	}
	return v, true
}

// lineAtPath follows path through v (string keys into maps, numeric
// segments into arrays or maps) and returns the integer found there, or -1.
func lineAtPath(v interface{}, path []string) int {
	for _, seg := range path {
		next, ok := childAt(v, seg)
		if !ok {
			return -1
		}
		v = next
	}
	return lineValue(v)
}

// childAt resolves one path segment the way it would resolve against the
// value's JSON encoding.
func childAt(v interface{}, seg string) (interface{}, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		c, ok := t[seg]
		return c, ok
	case model.Document:
		c, ok := t[seg]
		return c, ok
	case []interface{}:
		i, err := strconv.Atoi(seg)
		if err != nil || i < 0 || i >= len(t) {
			return nil, false
		}
		return t[i], true
	case map[string]*model.LineObject:
		c, ok := t[seg]
		return c, ok && c != nil
	case *model.LineObject:
		return lineObjectChild(t, seg)
	case nil:
		return nil, false
	}
	return reflectChildAt(v, seg)
}

func lineObjectChild(obj *model.LineObject, seg string) (interface{}, bool) {
	if obj == nil {
		return nil, false
	}
	switch seg {
	case "_dd_line":
		return obj.Line, true
	case "_dd_arr":
		return obj.Arr, len(obj.Arr) > 0
	default:
		return nil, false
	}
}

func reflectChildAt(v interface{}, seg string) (interface{}, bool) {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Struct:
		return structFieldByJSONName(rv, seg)
	case reflect.Map:
		keyType := rv.Type().Key()
		if keyType.Kind() != reflect.String {
			return nil, false
		}
		c := rv.MapIndex(reflect.ValueOf(seg).Convert(keyType))
		if !c.IsValid() {
			return nil, false
		}
		return c.Interface(), true
	case reflect.Slice, reflect.Array:
		i, err := strconv.Atoi(seg)
		if err != nil || i < 0 || i >= rv.Len() {
			return nil, false
		}
		return rv.Index(i).Interface(), true
	default:
		return nil, false
	}
}

// structFieldByJSONName returns the exported field encoded under name,
// honoring omitempty and embedded (anonymous) struct flattening the way
// encoding/json does. It does not honor json.Marshaler implementations or
// the ",string" option: no parser enrichment type attached to line-info
// documents uses them (guarded by the parity tests).
func structFieldByJSONName(rv reflect.Value, name string) (interface{}, bool) {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		tagName, opts, _ := strings.Cut(tag, ",")
		// encoding/json flattens embedded structs with no explicit json name
		// into the parent: their fields resolve as the parent's own fields.
		// This includes embedded fields of unexported struct types, whose
		// exported fields still promote and marshal.
		if field.Anonymous && tagName == "" {
			fv := rv.Field(i)
			if fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue
				}
				fv = fv.Elem()
			}
			if fv.Kind() == reflect.Struct {
				if v, ok := structFieldByJSONName(fv, name); ok {
					return v, true
				}
			}
			continue
		}
		if !field.IsExported() {
			continue
		}
		if tagName == "" {
			tagName = field.Name
		}
		if tagName != name {
			continue
		}
		fv := rv.Field(i)
		if strings.Contains(opts, "omitempty") && isEmptyJSONValue(fv) {
			return nil, false
		}
		return fv.Interface(), true
	}
	return nil, false
}

// isEmptyJSONValue mirrors encoding/json's omitempty test.
func isEmptyJSONValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
		return v.IsZero()
	default:
		return false
	}
}

func lineValue(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i
		}
		return -1
	case nil:
		return -1
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(rv.Uint())
	case reflect.Float32, reflect.Float64:
		return int(rv.Float())
	default:
		return -1
	}
}
