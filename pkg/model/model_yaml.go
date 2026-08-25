/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"bytes"
	"context"
	json "encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"gopkg.in/yaml.v3"
)

// cfnShortFormTags maps CloudFormation short-form intrinsic tags to long-form keys.
var cfnShortFormTags = map[string]string{
	"!Ref":          "Ref",
	"!Sub":          "Fn::Sub",
	"!GetAtt":       "Fn::GetAtt",
	"!Join":         "Fn::Join",
	"!Select":       "Fn::Select",
	"!Split":        "Fn::Split",
	"!FindInMap":    "Fn::FindInMap",
	"!ImportValue":  "Fn::ImportValue",
	"!Base64":       "Fn::Base64",
	"!Cidr":         "Fn::Cidr",
	"!GetAZs":       "Fn::GetAZs",
	"!If":           "Fn::If",
	"!And":          "Fn::And",
	"!Or":           "Fn::Or",
	"!Not":          "Fn::Not",
	"!Equals":       "Fn::Equals",
	"!Condition":    "Condition",
	"!Transform":    "Fn::Transform",
	"!Length":       "Fn::Length",
	"!ToJsonString": "Fn::ToJsonString",
}

// cfnContextKey marks a parsing context as belonging to a CloudFormation
// template, gating short-form intrinsic rewriting to that platform only.
type cfnContextKey struct{}

func withCloudFormation(ctx context.Context, isCFN bool) context.Context {
	return context.WithValue(ctx, cfnContextKey{}, isCFN)
}

func isCloudFormationContext(ctx context.Context) bool {
	isCFN, _ := ctx.Value(cfnContextKey{}).(bool)
	return isCFN
}

// isCloudFormationDocument reports whether the root YAML mapping node looks like
// a CloudFormation template. Short-form intrinsic tags (!Ref, !Sub, ...) are
// CloudFormation-specific, so rewriting must never run on Kubernetes, Ansible,
// or other YAML that happens to use a custom tag.
func isCloudFormationDocument(value *yaml.Node) bool {
	if value == nil || value.Kind != yaml.MappingNode {
		return false
	}
	hasResources := false
	for i := 0; i+1 < len(value.Content); i += 2 {
		switch value.Content[i].Value {
		case "AWSTemplateFormatVersion", "Transform":
			return true
		case "Resources":
			hasResources = true
		}
	}
	return hasResources
}

// GetIgnoreLines recomputes YAML ignore comments from OriginalData after reference resolution shifted line numbers.
func GetIgnoreLines(file *FileMetadata) []int {
	ignoreLines := file.LinesIgnore
	if !utils.Contains(filepath.Ext(file.FilePath), []string{".yml", ".yaml"}) {
		return ignoreLines
	}

	ignore := &Ignore{}
	dec := yaml.NewDecoder(bytes.NewReader([]byte(file.OriginalData)))
	found := false
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			break
		}
		walkIgnoreCommentsYAML(&node, ignore)
		found = true
	}
	if found {
		return ignore.GetLines()
	}
	return ignoreLines
}

func walkIgnoreCommentsYAML(node *yaml.Node, ignore *Ignore) {
	if node == nil {
		return
	}
	ignore.ignoreCommentsYAML(node)
	switch node.Kind {
	case yaml.DocumentNode, yaml.MappingNode, yaml.SequenceNode:
		for _, child := range node.Content {
			walkIgnoreCommentsYAML(child, ignore)
		}
	case yaml.AliasNode:
		if node.Alias != nil {
			walkIgnoreCommentsYAML(node.Alias, ignore)
		}
	}
}

// UnmarshalYAML is a custom yaml parser that places line information in the payload
func (m *Document) UnmarshalYAML(ctx context.Context, value *yaml.Node, ignore *Ignore) error {
	ctx = withCloudFormation(ctx, isCloudFormationDocument(value))
	dpc := unmarshal(ctx, value, ignore)
	if mapDcp, ok := dpc.(map[string]interface{}); ok {
		if isCloudFormationContext(ctx) {
			expandCloudFormationForEach(mapDcp)
		}
		// set line information for root level objects
		mapDcp["_dd_lines"] = getLines(value, 0)

		// place the payload in the Document struct
		tmp, _ := json.Marshal(mapDcp)
		_ = json.Unmarshal(tmp, m)
		return nil
	}
	return errors.New("failed to parse yaml content")
}

func expandCloudFormationForEach(doc map[string]interface{}) {
	resources, parameters := forEachExpansionContext(doc)
	if resources == nil {
		return
	}
	for {
		forEachKeys := collectForEachKeys(resources)
		if len(forEachKeys) == 0 {
			break
		}
		anyExpanded := false
		for _, key := range forEachKeys {
			if expandForEachEntry(resources, key, parameters) {
				anyExpanded = true
			}
		}
		if !anyExpanded {
			break
		}
	}
}

func forEachExpansionContext(doc map[string]interface{}) (resources, parameters map[string]interface{}) {
	if !hasLanguageExtensionsTransform(doc) {
		return nil, nil
	}
	resourcesRaw, ok := doc["Resources"]
	if !ok {
		return nil, nil
	}
	resources, ok = resourcesRaw.(map[string]interface{})
	if !ok {
		return nil, nil
	}
	parameters, _ = doc["Parameters"].(map[string]interface{})
	return resources, parameters
}

func expandForEachEntry(resources map[string]interface{}, key string, parameters map[string]interface{}) bool {
	varName, collection, templateMap, ok := parseForEachSpec(resources[key], parameters)
	if !ok {
		return false
	}
	for _, item := range collection {
		bindings := map[string]string{varName: item}
		for logicalID, resourceValue := range templateMap {
			resolvedLogicalID := replaceForEachVars(logicalID, bindings)
			if _, exists := resources[resolvedLogicalID]; !exists {
				resources[resolvedLogicalID] = substituteForEachBindings(resourceValue, bindings)
				copyForEachLineInfo(resources, key, resolvedLogicalID)
			}
		}
	}
	delete(resources, key)
	removeForEachLineInfo(resources, key)
	return true
}

func parseForEachSpec(
	raw interface{},
	parameters map[string]interface{},
) (varName string, collection []string, templateMap map[string]interface{}, ok bool) {
	// spec is [loopVarName string, collection expr, templateMap]
	spec, ok := raw.([]interface{})
	if !ok || len(spec) != 3 {
		return "", nil, nil, false
	}
	varName, ok = spec[0].(string)
	if !ok || varName == "" {
		return "", nil, nil, false
	}
	collection, ok = resolveForEachCollection(spec[1], parameters)
	if !ok || len(collection) == 0 {
		return "", nil, nil, false
	}
	templateMap, ok = spec[2].(map[string]interface{})
	if !ok {
		return "", nil, nil, false
	}
	return varName, collection, templateMap, true
}

func collectForEachKeys(resources map[string]interface{}) []string {
	keys := []string{}
	for key := range resources {
		if strings.HasPrefix(key, "Fn::ForEach::") {
			keys = append(keys, key)
		}
	}
	return keys
}

// hasLanguageExtensionsTransform reports whether the document declares the
// AWS::LanguageExtensions transform, which is required for Fn::ForEach to be
// valid CloudFormation syntax.
func hasLanguageExtensionsTransform(doc map[string]interface{}) bool {
	const ext = "AWS::LanguageExtensions"
	switch t := doc["Transform"].(type) {
	case string:
		return t == ext
	case []interface{}:
		for _, v := range t {
			if s, ok := v.(string); ok && s == ext {
				return true
			}
		}
	}
	return false
}

func resolveForEachCollection(expr interface{}, parameters map[string]interface{}) ([]string, bool) {
	switch v := expr.(type) {
	case []interface{}:
		return normalizeForEachDefault(v), true
	case map[string]interface{}:
		refName, ok := v["Ref"].(string)
		if !ok || refName == "" {
			return nil, false
		}
		param, ok := parameters[refName].(map[string]interface{})
		if !ok {
			return nil, false
		}
		defaultValue, ok := param["Default"]
		if !ok {
			return nil, false
		}
		return normalizeForEachDefault(defaultValue), true
	default:
		return nil, false
	}
}

func normalizeForEachDefault(v interface{}) []string {
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	case string:
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			out = append(out, trimmed)
		}
		return out
	default:
		return []string{fmt.Sprintf("%v", t)}
	}
}

func substituteForEachBindings(v interface{}, bindings map[string]string) interface{} {
	switch t := v.(type) {
	case string:
		return replaceForEachVars(t, bindings)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i := range t {
			out[i] = substituteForEachBindings(t[i], bindings)
		}
		return out
	case map[string]interface{}:
		if ref, ok := t["Ref"].(string); ok && isPureRefNode(t) {
			if resolved, exists := bindings[ref]; exists {
				return resolved
			}
		}
		out := make(map[string]interface{}, len(t))
		for key, val := range t {
			out[replaceForEachVars(key, bindings)] = substituteForEachBindings(val, bindings)
		}
		return out
	default:
		return v
	}
}

func isPureRefNode(m map[string]interface{}) bool {
	for k := range m {
		if k != "Ref" && k != "_dd_lines" {
			return false
		}
	}
	return true
}

func replaceForEachVars(template string, bindings map[string]string) string {
	resolved := template
	for name, value := range bindings {
		resolved = strings.ReplaceAll(resolved, "${"+name+"}", value)
		resolved = strings.ReplaceAll(resolved, "&{"+name+"}", value)
	}
	return resolved
}

func copyForEachLineInfo(resources map[string]interface{}, foreachKey, resourceKey string) {
	lines, ok := resources["_dd_lines"].(map[string]*LineObject)
	if !ok {
		return
	}
	source, ok := lines["_dd_"+foreachKey]
	if !ok {
		return
	}
	lines["_dd_"+resourceKey] = source
}

func removeForEachLineInfo(resources map[string]interface{}, foreachKey string) {
	lines, ok := resources["_dd_lines"].(map[string]*LineObject)
	if !ok {
		return
	}
	delete(lines, "_dd_"+foreachKey)
}

/*
	YAML Node TYPES

	SequenceNode -> array
	ScalarNode -> generic (except for arrays, objects and maps)
	MappingNode -> map

*/
// unmarshal is the function that will parse the yaml elements and call the functions needed
// to place their line information in the payload
func unmarshal(ctx context.Context, val *yaml.Node, ignore *Ignore) interface{} {
	return unmarshalWithDepth(ctx, val, make(map[*yaml.Node]bool), ignore)
}

// unmarshalWithDepth handles recursive unmarshaling with circular reference detection
func unmarshalWithDepth(ctx context.Context, val *yaml.Node, visited map[*yaml.Node]bool, ignore *Ignore) interface{} { //nolint:gocyclo
	if visited[val] {
		return nil
	}
	visited[val] = true
	defer func() { delete(visited, val) }()
	tmp := make(map[string]interface{})
	if ignore != nil {
		ignore.ignoreCommentsYAML(val)
	}

	// if Yaml Node is an Array than we are working with ansible
	// which need to be placed inside "playbooks"
	// nolint:staticcheck
	if val.Kind == yaml.SequenceNode {
		contentArray := make([]interface{}, 0)
		for _, contentEntry := range val.Content {
			contentArray = append(contentArray, unmarshalWithDepth(ctx, contentEntry, visited, ignore))
		}
		tmp["playbooks"] = contentArray
	} else if val.Kind == yaml.ScalarNode {
		return scalarNodeResolver(ctx, val)
	} else {
		// iterate two by two, since first iteration is the key and the second is the value
		for i := 0; i < len(val.Content); i += 2 {
			if val.Content[i].Kind == yaml.ScalarNode {
				if rewritten, ok := rewriteCFNShortFormIntrinsic(ctx, val.Content[i+1], visited, ignore); ok {
					if m, ok := rewritten.(map[string]interface{}); ok {
						m["_dd_lines"] = getLines(val.Content[i+1], val.Content[i].Line)
					}
					tmp[val.Content[i].Value] = rewritten
					continue
				}
				switch val.Content[i+1].Kind {
				case yaml.ScalarNode:
					tmp[val.Content[i].Value] = scalarNodeResolver(ctx, val.Content[i+1])
				// in case value iteration is a map
				case yaml.MappingNode:
					// unmarshall map value and get its line information
					result := unmarshalWithDepth(ctx, val.Content[i+1], visited, ignore)
					if tt, ok := result.(map[string]interface{}); ok {
						tt["_dd_lines"] = getLines(val.Content[i+1], val.Content[i].Line)
						tmp[val.Content[i].Value] = tt
					} else {
						tmp[val.Content[i].Value] = result
					}
				// in case value iteration is an array
				case yaml.SequenceNode:
					contentArray := make([]interface{}, 0)
					// unmarshall each iteration of the array
					for _, contentEntry := range val.Content[i+1].Content {
						contentArray = append(contentArray, unmarshalWithDepth(ctx, contentEntry, visited, ignore))
					}
					tmp[val.Content[i].Value] = contentArray
				case yaml.AliasNode:
					if val.Content[i+1].Alias != nil {
						result := unmarshalWithDepth(ctx, val.Content[i+1].Alias, visited, ignore)
						if tt, ok := result.(map[string]interface{}); ok {
							tt["_dd_lines"] = getLines(val.Content[i+1], val.Content[i].Line)
							utils.MergeMaps(tmp, tt)
						}
						if v, ok := result.(string); ok {
							tmp[val.Content[i].Value] = v
						}
					}
				}
			}
		}
	}
	return tmp
}

// getLines creates the map containing the line information for the yaml Node
// def is the line to be used as "_dd__default"
func getLines(val *yaml.Node, def int) map[string]*LineObject {
	lineMap := make(map[string]*LineObject)

	// line information map
	lineMap["_dd__default"] = &LineObject{
		Line: def,
		Arr:  []map[string]*LineObject{},
	}

	// if yaml Node is an Array use func getSeqLines
	if val.Kind == yaml.SequenceNode {
		return getSeqLines(val, def)
	}

	// iterate two by two, since first iteration is the key and the second is the value
	for i := 0; i < len(val.Content); i += 2 {
		lineArr := make([]map[string]*LineObject, 0)
		// in case the value iteration is an array call getLines for each iteration of the array
		if val.Content[i+1].Kind == yaml.SequenceNode {
			for _, contentEntry := range val.Content[i+1].Content {
				defaultLine := val.Content[i].Line
				if contentEntry.Kind == yaml.ScalarNode {
					defaultLine = contentEntry.Line
				} else if contentEntry.Kind == yaml.MappingNode && len(contentEntry.Content) > 0 {
					defaultLine = contentEntry.Content[0].Line
				}
				lineArr = append(lineArr, getLines(contentEntry, defaultLine))
			}
		}

		// line information map of each key of the yaml Node
		lineMap["_dd_"+val.Content[i].Value] = &LineObject{
			Line: val.Content[i].Line,
			Arr:  lineArr,
		}
	}

	return lineMap
}

// getSeqLines iterates through the elements of an Array
// creating a map with each iteration lines information
func getSeqLines(val *yaml.Node, def int) map[string]*LineObject {
	lineMap := make(map[string]*LineObject)
	lineArr := make([]map[string]*LineObject, 0)

	// get line information slice of every element in the array
	for _, cont := range val.Content {
		lineArr = append(lineArr, getLines(cont, cont.Line))
	}

	// create line information of array with its line and elements line information
	lineMap["_dd__default"] = &LineObject{
		Line: def,
		Arr:  lineArr,
	}
	return lineMap
}

// scalarNodeResolver transforms a ScalarNode value in its correct type
func scalarNodeResolver(ctx context.Context, val *yaml.Node) interface{} {
	if rewritten, ok := rewriteCFNShortFormIntrinsic(ctx, val, nil, nil); ok {
		return rewritten
	}
	contextLogger := logger.FromContext(ctx)
	var resolved interface{}
	if err := val.Decode(&resolved); err != nil {
		contextLogger.Error().Msgf("failed to decode scalar in yaml parser: %q", val.Value)
		return val.Value
	}
	return resolved
}

// rewriteCFNShortFormIntrinsic converts a short-form CFN intrinsic to its long-form map.
// It is a no-op for documents that are not CloudFormation templates.
func rewriteCFNShortFormIntrinsic(ctx context.Context, val *yaml.Node, visited map[*yaml.Node]bool, ignore *Ignore) (interface{}, bool) {
	if val == nil || !isCloudFormationContext(ctx) {
		return nil, false
	}
	longForm, ok := cfnShortFormTags[val.Tag]
	if !ok {
		return nil, false
	}

	switch val.Kind {
	case yaml.ScalarNode:
		var payload interface{} = val.Value
		if longForm == "Fn::GetAtt" {
			parts := strings.SplitN(val.Value, ".", 2)
			converted := make([]interface{}, 0, len(parts))
			for _, p := range parts {
				converted = append(converted, p)
			}
			payload = converted
		}
		return map[string]interface{}{longForm: payload}, true
	case yaml.SequenceNode:
		seq := make([]interface{}, 0, len(val.Content))
		for _, child := range val.Content {
			seq = append(seq, decodeIntrinsicChild(ctx, child, visited, ignore))
		}
		return map[string]interface{}{longForm: seq}, true
	case yaml.MappingNode:
		v := visited
		if v == nil {
			v = make(map[*yaml.Node]bool)
		}
		return map[string]interface{}{longForm: unmarshalWithDepth(ctx, val, v, ignore)}, true
	}
	return nil, false
}

func decodeIntrinsicChild(ctx context.Context, val *yaml.Node, visited map[*yaml.Node]bool, ignore *Ignore) interface{} {
	if val == nil {
		return nil
	}
	if rewritten, ok := rewriteCFNShortFormIntrinsic(ctx, val, visited, ignore); ok {
		return rewritten
	}
	v := visited
	if v == nil {
		v = make(map[*yaml.Node]bool)
	}
	switch val.Kind {
	case yaml.ScalarNode:
		return scalarNodeResolver(ctx, val)
	case yaml.MappingNode:
		return unmarshalWithDepth(ctx, val, v, ignore)
	case yaml.SequenceNode:
		seq := make([]interface{}, 0, len(val.Content))
		for _, child := range val.Content {
			seq = append(seq, decodeIntrinsicChild(ctx, child, v, ignore))
		}
		return seq
	}
	return nil
}
