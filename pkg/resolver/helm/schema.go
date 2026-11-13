package helm

import (
	"encoding/json"
	"strings"

	"helm.sh/helm/v3/pkg/chart"
)

// A chart's values.schema.json may require values the chart does not hold,
// which only a deployment supplies. The render gives each missing one its
// default in the schema, or else a placeholder of its type, as a deployment
// would give some value: a string names the value, as "<.Values.image.tag>".

// maxSchemaDepth bounds the nesting of the schemas walked, $ref cycles
// included.
const maxSchemaDepth = 32

// schemaObject is the JSON schema type of a map.
const schemaObject = "object"

func hasSchema(ch *chart.Chart) bool {
	if len(ch.Schema) > 0 {
		return true
	}
	for _, dep := range ch.Dependencies() {
		if hasSchema(dep) {
			return true
		}
	}
	return false
}

// requiredBySchema returns the values the schemas of ch and its dependencies
// require that values, the coalesced values of the chart, lack.
func requiredBySchema(ch *chart.Chart, values map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	var schema map[string]interface{}
	if len(ch.Schema) > 0 && json.Unmarshal(ch.Schema, &schema) == nil {
		out = schemaRequired(schema, schema, values, nil, 0)
	}
	for _, dep := range ch.Dependencies() {
		for _, key := range dependencyKeys(ch, dep) {
			sub, _ := values[key].(map[string]interface{})
			if sub == nil {
				sub = map[string]interface{}{}
			}
			if missing := requiredBySchema(dep, sub); len(missing) > 0 {
				existing, _ := out[key].(map[string]interface{})
				out[key] = mergeInto(existing, missing)
			}
		}
	}
	return out
}

// dependencyKeys returns the keys of the parent's values a dependency reads:
// its aliases, or its name.
func dependencyKeys(parent, dep *chart.Chart) []string {
	var keys []string
	if parent.Metadata != nil {
		for _, d := range parent.Metadata.Dependencies {
			if d != nil && d.Name == dep.Name() && d.Alias != "" {
				keys = append(keys, d.Alias)
			}
		}
	}
	if len(keys) == 0 {
		keys = append(keys, dep.Name())
	}
	return keys
}

func mergeInto(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = map[string]interface{}{}
	}
	for k, v := range src {
		if sm, ok := v.(map[string]interface{}); ok {
			if dm, ok := dst[k].(map[string]interface{}); ok {
				dst[k] = mergeInto(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}

// schemaRequired returns what schema requires of values that they lack, path
// being where values are under .Values.
func schemaRequired(root, schema, values map[string]interface{}, path []string, depth int) map[string]interface{} {
	out := map[string]interface{}{}
	if depth > maxSchemaDepth {
		return out
	}
	schema = resolveSchemaRef(root, schema, depth)
	props, _ := schema["properties"].(map[string]interface{})
	for _, r := range asList(schema["required"]) {
		name, ok := r.(string)
		if !ok {
			continue
		}
		if _, present := values[name]; present {
			continue
		}
		prop, _ := props[name].(map[string]interface{})
		out[name] = schemaPlaceholder(root, prop, appendPath(path, name), depth+1)
	}
	for name, p := range props {
		prop, ok := p.(map[string]interface{})
		sub, isMap := values[name].(map[string]interface{})
		if !ok || !isMap {
			continue
		}
		if missing := schemaRequired(root, prop, sub, appendPath(path, name), depth+1); len(missing) > 0 {
			out[name] = missing
		}
	}
	for _, s := range asList(schema["allOf"]) {
		if sub, ok := s.(map[string]interface{}); ok {
			out = mergeInto(out, schemaRequired(root, sub, values, path, depth+1))
		}
	}
	return out
}

// schemaPlaceholder is the value given a required property absent from the
// values: its default, or a value of its type.
func schemaPlaceholder(root, prop map[string]interface{}, path []string, depth int) interface{} {
	prop = resolveSchemaRef(root, prop, depth)
	if v, ok := prop["default"]; ok {
		return v
	}
	if v, ok := prop["const"]; ok {
		return v
	}
	switch schemaType(prop) {
	case schemaObject:
		return schemaRequired(root, prop, map[string]interface{}{}, path, depth+1)
	case "array":
		return []interface{}{}
	case "integer", "number":
		return 0
	case "boolean":
		return false
	default:
		return placeholderText(valuesLabel(path))
	}
}

// schemaType is the first type of a schema other than null; a schema with
// properties is an object.
func schemaType(prop map[string]interface{}) string {
	switch t := prop["type"].(type) {
	case string:
		return t
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "null" {
				return s
			}
		}
	}
	if _, ok := prop["properties"]; ok {
		return schemaObject
	}
	return ""
}

// resolveSchemaRef follows a local $ref ("#/definitions/x", "#/$defs/x").
func resolveSchemaRef(root, schema map[string]interface{}, depth int) map[string]interface{} {
	for i := 0; i < maxSchemaDepth-depth; i++ {
		ref, ok := schema["$ref"].(string)
		if !ok || !strings.HasPrefix(ref, "#/") {
			return schema
		}
		var cur interface{} = root
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			m, ok := cur.(map[string]interface{})
			if !ok {
				return schema
			}
			cur = m[part]
		}
		next, ok := cur.(map[string]interface{})
		if !ok {
			return schema
		}
		schema = next
	}
	return schema
}

func asList(v interface{}) []interface{} {
	l, _ := v.([]interface{})
	return l
}
