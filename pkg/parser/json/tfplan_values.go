/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/tidwall/gjson"
)

const linesKey = "_dd_lines"

// planValues rewrites the planned values of the resource at addr with its
// after_unknown and configuration expressions.
func (c *resourceChangeCorrelation) planValues(addr string, values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	expressions := c.configByAddress[canonicalConfigAddress(addr)]
	return planValues(values, c.afterUnknownByAddress[addr], &expressions)
}

// planValues rewrites one resource's planned values in place and returns its
// _dd_meta.unknown, nil when nothing is unknown.
func planValues(values map[string]any, afterUnknown any, expressions *gjson.Result) map[string]any {
	unknown, _ := pruneUnknown(afterUnknown).(map[string]any)
	if expressions == nil {
		expressions = &gjson.Result{}
	}
	rewriteObject(values, unknown, newBlockConfig([]gjson.Result{*expressions}))
	return unknown
}

// pruneUnknown reduces an after_unknown value to the _dd_meta.unknown shape, nil when nothing is unknown.
func pruneUnknown(afterUnknown any) any {
	switch au := afterUnknown.(type) {
	case bool:
		if au {
			return true
		}
	case map[string]any:
		out := make(map[string]any)
		for k, v := range au {
			if p := pruneUnknown(v); p != nil {
				out[k] = p
			}
		}
		if len(out) > 0 {
			return out
		}
	case []any:
		out := make([]any, len(au))
		found := false
		for i, v := range au {
			if p := pruneUnknown(v); p != nil {
				out[i], found = p, true
			} else if _, isObject := v.(map[string]any); isObject {
				out[i] = map[string]any{}
			} else {
				out[i] = false
			}
		}
		if found {
			return out
		}
	}
	return nil
}

// blockConfig maps the keys configured at one nested block level to the
// expressions of every configured instance of the nested block under that
// key, nil for an attribute. Planned set elements are not in configuration
// order, so every planned instance is matched against the union.
type blockConfig map[string][]gjson.Result

func newBlockConfig(instances []gjson.Result) blockConfig {
	cfg := make(blockConfig)
	for i := range instances {
		instances[i].ForEach(func(key, expr gjson.Result) bool {
			k := key.String()
			switch {
			case expr.IsArray():
				cfg[k] = append(cfg[k], expr.Array()...)
			case expr.IsObject() && !isAttributeExpression(&expr):
				cfg[k] = append(cfg[k], expr)
			default:
				if _, seen := cfg[k]; !seen {
					cfg[k] = nil
				}
			}
			return true
		})
	}
	return cfg
}

// rewriteObject rewrites one object level. A nil cfg is an attribute's value
// or a block without configuration, where no empty list is dropped.
func rewriteObject(obj, unknown map[string]any, cfg blockConfig) {
	fillUnknown(obj, unknown)
	for k, v := range obj {
		if k == linesKey {
			continue
		}
		var nested blockConfig
		if cfg != nil {
			instances, configured := cfg[k]
			if l, ok := v.([]any); ok && len(l) == 0 && !configured {
				delete(obj, k)
				continue
			}
			if len(instances) > 0 {
				nested = newBlockConfig(instances)
			}
		}
		switch v.(type) {
		case nil:
			delete(obj, k)
		case []any, map[string]any:
			rewriteValue(v, unknown[k], nested)
		}
	}
}

func fillUnknown(obj, unknown map[string]any) {
	for k, u := range unknown {
		switch u := u.(type) {
		case bool:
			obj[k] = partial.UnknownPlaceholder
		case map[string]any:
			if _, ok := obj[k].(map[string]any); !ok {
				obj[k] = map[string]any{}
			}
		case []any:
			if _, ok := obj[k].([]any); !ok {
				obj[k] = unknownList(u)
			}
		}
	}
}

// unknownList builds the structure of a list missing from planned values;
// rewriteValue then fills its unknown positions and its known ones stay null.
func unknownList(unknown []any) []any {
	out := make([]any, len(unknown))
	for i, u := range unknown {
		switch elem := u.(type) {
		case map[string]any:
			out[i] = map[string]any{}
		case []any:
			out[i] = unknownList(elem)
		}
	}
	return out
}

// isAttributeExpression reports whether expr is an attribute's expression
// rather than a nested block's.
func isAttributeExpression(expr *gjson.Result) bool {
	if !expr.IsObject() {
		return false
	}
	attribute := true
	expr.ForEach(func(key, _ gjson.Result) bool {
		attribute = key.String() == "constant_value" || key.String() == "references"
		return attribute
	})
	return attribute
}

func rewriteValue(value, unknown any, cfg blockConfig) {
	switch val := value.(type) {
	case map[string]any:
		u, _ := unknown.(map[string]any)
		rewriteObject(val, u, cfg)
	case []any:
		u, _ := unknown.([]any)
		for i, elem := range val {
			var elemUnknown any
			if i < len(u) {
				elemUnknown = u[i]
			}
			if elemUnknown == true {
				val[i] = partial.UnknownPlaceholder
				continue
			}
			rewriteValue(elem, elemUnknown, cfg)
		}
	}
}
