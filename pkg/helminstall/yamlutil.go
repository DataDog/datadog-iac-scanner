/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"

	"gopkg.in/yaml.v3"
)

// yamlDocuments decodes every document of data, anchors and merge keys
// resolved. A document that does not decode ends the list.
func yamlDocuments(data []byte) []map[string]interface{} {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []map[string]interface{}
	for {
		var doc interface{}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) || err != nil {
			return docs
		}
		if m, ok := normalizeYAML(doc).(map[string]interface{}); ok {
			docs = append(docs, m)
		}
	}
}

// normalizeYAML turns what yaml.v3 decodes into the types Helm values hold:
// maps with string keys, and numbers as Helm reads them from a values file.
// Values nested deeper than maxValuesDepth are left out, which bounds a cyclic
// value, as a values function may return.
func normalizeYAML(v interface{}) interface{} {
	return normalizeDepth(v, 0)
}

// maxValuesDepth bounds how deep values are read.
const maxValuesDepth = 64

func normalizeDepth(v interface{}, depth int) interface{} {
	if depth > maxValuesDepth {
		return nil
	}
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			out[k] = normalizeDepth(val, depth+1)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = normalizeDepth(val, depth+1)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, val := range x {
			out[i] = normalizeDepth(val, depth+1)
		}
		return out
	case int:
		return int64(x)
	case uint64:
		return float64(x)
	default:
		return v
	}
}

// helmValues converts decoded YAML to values typed as Helm types those of a
// values file.
func helmValues(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, false
	}
	data, err := yaml.Marshal(m)
	if err != nil {
		return nil, false
	}
	values, err := ParseValues(data)
	return values, err == nil
}

func str(m map[string]interface{}, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprint(v)
	}
}

func mapOf(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func listOf(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key].([]interface{}); ok {
		return v
	}
	return nil
}

func strList(m map[string]interface{}, key string) []string {
	var out []string
	for _, v := range listOf(m, key) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// boolOr returns the boolean m holds at key, def when it holds none.
func boolOr(m map[string]interface{}, key string, def bool) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// scalarText is how --set receives a value given in YAML.
func scalarText(v interface{}) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case nil:
		return "null", true
	}
	return "", false
}
