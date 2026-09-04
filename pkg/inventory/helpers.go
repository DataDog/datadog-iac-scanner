/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// internalKeyPrefixes covers parser bookkeeping keys that are never declared
// attributes: line annotations (_dd_), legacy field names (_kics_), and the
// CI/CD parser's run/expression enrichments (_parsed).
var internalKeyPrefixes = []string{"_dd_", "_kics_", "_parsed"}

// scannerInjectedKeys are document-root keys injected by the scan pipeline
// (path, id, file) that are not part of the IaC source. Both the Kubernetes
// and CI/CD parsers inject these same keys.
var scannerInjectedKeys = []string{"_path", "id", "file"}

// deleteInjectedKeys removes scannerInjectedKeys from an attrs map. Safe to
// call with a nil map (no-op).
func deleteInjectedKeys(attrs map[string]interface{}) {
	for _, k := range scannerInjectedKeys {
		delete(attrs, k)
	}
}

func isInternalKey(k string) bool {
	for _, p := range internalKeyPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// cleanAttrs strips internal annotation keys from a parsed body at every
// nesting level. map[string]model.LineObject values are annotation-only and
// dropped entirely.
func cleanAttrs(v interface{}) interface{} {
	switch t := v.(type) {
	case model.Document:
		return cleanMap(map[string]interface{}(t))
	case map[string]interface{}:
		return cleanMap(t)
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for _, item := range t {
			out = append(out, cleanAttrs(item))
		}
		return out
	case map[string]model.LineObject, map[string]*model.LineObject:
		return nil
	default:
		return v
	}
}

func attrsFromBody(body interface{}) map[string]interface{} {
	cleaned := cleanAttrs(body)
	if m, ok := cleaned.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func cleanMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if isInternalKey(k) {
			continue
		}
		cleaned := cleanAttrs(v)
		// Preserve explicit source nulls (v == nil); only drop values that
		// became nil because cleanAttrs consumed them (annotation maps, etc.).
		if cleaned != nil || v == nil {
			out[k] = cleaned
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// lineBounds returns the min/max line numbers annotated anywhere in a parsed
// body, tolerating both the Terraform converter's struct form and the
// JSON-decoded form used by YAML/JSON parsers.
func lineBounds(body interface{}) (minLine, maxLine int) {
	tracker := &lineTracker{}
	tracker.walk(body)
	return tracker.min, tracker.max
}

type lineTracker struct{ min, max int }

func (t *lineTracker) consider(line int) {
	if line <= 0 {
		return
	}
	if t.min == 0 || line < t.min {
		t.min = line
	}
	if line > t.max {
		t.max = line
	}
}

func (t *lineTracker) walk(v interface{}) {
	switch val := v.(type) {
	case map[string]model.LineObject:
		t.walkLineObjects(val)
	case map[string]*model.LineObject:
		for _, lo := range val {
			if lo != nil {
				t.consider(lo.Line)
			}
		}
	case model.Document:
		for _, child := range val {
			t.walk(child)
		}
	case map[string]interface{}:
		if line, ok := genericLine(val); ok {
			t.consider(line)
		}
		for _, child := range val {
			t.walk(child)
		}
	case []interface{}:
		for _, child := range val {
			t.walk(child)
		}
	}
}

func (t *lineTracker) walkLineObjects(m map[string]model.LineObject) {
	for _, lo := range m {
		t.consider(lo.Line)
		for _, arr := range lo.Arr {
			for _, p := range arr {
				if p != nil {
					t.consider(p.Line)
				}
			}
		}
	}
}

func genericLine(m map[string]interface{}) (int, bool) {
	switch v := m["_dd_line"].(type) {
	case int:
		return v, true
	case float64:
		return int(v), true
	}
	return 0, false
}

func stringAttr(body interface{}, key string) string {
	bodyMap, ok := toMap(body)
	if !ok {
		return ""
	}
	if s, ok := bodyMap[key].(string); ok {
		return s
	}
	return ""
}

func toMap(v interface{}) (map[string]interface{}, bool) {
	switch m := v.(type) {
	case model.Document:
		return m, true
	case map[string]interface{}:
		return m, true
	default:
		return nil, false
	}
}

func toList(v interface{}) ([]interface{}, bool) {
	list, ok := v.([]interface{})
	return list, ok
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if isInternalKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
