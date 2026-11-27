/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"gopkg.in/yaml.v3"
)

const yamlLineInfoKey = "_dd_lines"

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

type yamlFilePathContextKey struct{}

// WithYAMLFilePath adds the source file path to YAML parsing diagnostics.
func WithYAMLFilePath(ctx context.Context, filePath string) context.Context {
	return context.WithValue(ctx, yamlFilePathContextKey{}, filePath)
}

type (
	lazyLineInfoContextKey struct{}
	lineInfoOnlyContextKey struct{}
)

// WithLazyLineInfo marks a parse whose documents' line markers are never read
// (line info is rebuilt on demand when needed), so parsers may omit _dd_lines.
func WithLazyLineInfo(ctx context.Context) context.Context {
	return context.WithValue(ctx, lazyLineInfoContextKey{}, true)
}

// IsLazyLineInfo reports whether ctx was marked with WithLazyLineInfo.
func IsLazyLineInfo(ctx context.Context) bool {
	v, _ := ctx.Value(lazyLineInfoContextKey{}).(bool)
	return v
}

// WithLineInfoOnly marks a reparse that only needs the document's line markers,
// so parsers may skip enrichment that only rules consume.
func WithLineInfoOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, lineInfoOnlyContextKey{}, true)
}

// IsLineInfoOnly reports whether ctx was marked with WithLineInfoOnly.
func IsLineInfoOnly(ctx context.Context) bool {
	v, _ := ctx.Value(lineInfoOnlyContextKey{}).(bool)
	return v
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
		walkIgnoreCommentsYAML(&node, ignore, make(map[*yaml.Node]bool))
		found = true
	}
	if found {
		return ignore.GetLines()
	}
	return ignoreLines
}

func walkIgnoreCommentsYAML(node *yaml.Node, ignore *Ignore, visited map[*yaml.Node]bool) {
	if node == nil {
		return
	}
	if visited[node] {
		return
	}
	visited[node] = true
	defer delete(visited, node)

	ignore.ignoreCommentsYAML(node)
	switch node.Kind {
	case yaml.DocumentNode, yaml.MappingNode, yaml.SequenceNode:
		for _, child := range node.Content {
			walkIgnoreCommentsYAML(child, ignore, visited)
		}
	case yaml.AliasNode:
		if node.Alias != nil {
			walkIgnoreCommentsYAML(node.Alias, ignore, visited)
		}
	}
}

// UnmarshalYAML is a custom yaml parser that places line information in the payload
func (m *Document) UnmarshalYAML(ctx context.Context, value *yaml.Node, ignore *Ignore) error {
	return m.unmarshalYAML(ctx, value, nil, ignore)
}

// UnmarshalSharedYAML is UnmarshalYAML for a document whose file references
// were resolved, where a node can be reached through several parents (see
// file.Resolver.ResolveYAML, which states what sharing implies for callers).
// Such a node is converted once, and its value is shared by every parent.
// Ignore comments are not read: the shared nodes hold the comments of the
// referenced files.
func (m *Document) UnmarshalSharedYAML(ctx context.Context, value *yaml.Node) error {
	return m.unmarshalYAML(ctx, value, newSharedNodes(), nil)
}

func (m *Document) unmarshalYAML(ctx context.Context, value *yaml.Node, shared *sharedNodes, ignore *Ignore) error {
	ctx = withCloudFormation(ctx, isCloudFormationDocument(value))
	skipLines := IsLazyLineInfo(ctx)
	dpc := unmarshal(ctx, value, shared, ignore, skipLines)
	if mapDcp, ok := dpc.(map[string]interface{}); ok {
		if isCloudFormationContext(ctx) {
			expandCloudFormationForEach(mapDcp)
		}
		if !skipLines {
			// set line information for root level objects
			mapDcp[yamlLineInfoKey] = getLines(value, 0, shared)
		}

		// mapDcp is freshly built and exclusively owned: assign it directly instead of
		// deep-copying via a JSON round-trip (the dominant YAML parse cost);
		// scalarNodeResolver already normalizes types the way json.Marshal did.
		*m = mapDcp
		return nil
	}
	return errors.New("failed to parse yaml content")
}

func expandCloudFormationForEach(doc map[string]interface{}) {
	resources, parameters := forEachExpansionContext(doc)
	if resources == nil {
		return
	}
	lines, _ := resources[yamlLineInfoKey].(map[string]*LineObject)
	for _, key := range collectForEachKeys(resources) {
		lineKey := "_dd_" + key
		if expandForEachEntry(resources, resources[key], parameters, lines, lines[lineKey]) {
			delete(resources, key)
			delete(lines, lineKey)
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

func expandForEachEntry(resources map[string]interface{}, spec interface{}, parameters map[string]interface{},
	lines map[string]*LineObject, source *LineObject,
) bool {
	varName, collection, templateMap, ok := parseForEachSpec(spec, parameters)
	if !ok {
		return false
	}
	for _, item := range collection {
		bindings := map[string]string{varName: item}
		for logicalID, resourceValue := range templateMap {
			resolvedLogicalID := replaceForEachVars(logicalID, bindings)
			value := substituteForEachBindings(resourceValue, bindings)
			// Try each nested directive even if an earlier unresolved
			// iteration occupies the same key.
			if strings.HasPrefix(resolvedLogicalID, "Fn::ForEach::") && expandForEachEntry(resources, value, parameters, lines, source) {
				continue
			}
			if _, exists := resources[resolvedLogicalID]; exists {
				continue
			}
			resources[resolvedLogicalID] = value
			if source != nil {
				// Keep the outer loop's marker for the generated resource span.
				lines["_dd_"+resolvedLogicalID] = source
			}
		}
	}
	return true
}

// CloudFormationResourceLoopLine returns the written loop key line for a
// generated resource in an annotated YAML document.
func CloudFormationResourceLoopLine(doc map[string]interface{}, logicalID string) (int, bool) {
	resources, _ := doc["Resources"].(map[string]interface{})
	lines, _ := resources[yamlLineInfoKey].(map[string]*LineObject)
	marker := lines["_dd_"+logicalID]
	// A generated resource mapping inherits its loop's three argument markers.
	// A written resource mapping has no such array.
	if _, mapping := resources[logicalID].(map[string]interface{}); !mapping || marker == nil || len(marker.Arr) != 3 {
		return 0, false
	}
	return marker.Line, true
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
		// The YAML decoder wraps nested sequences in a playbooks map.
		if items, ok := v["playbooks"].([]interface{}); ok && len(v) == 1 {
			return normalizeForEachDefault(items), true
		}
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
	case map[string]*LineObject:
		return substituteForEachLineKeys(t, bindings)
	default:
		return v
	}
}

// Substitute the lookup keys while leaving the written source lines intact.
// Metadata can be shared by several expansions of the same template.
func substituteForEachLineKeys(lines map[string]*LineObject, bindings map[string]string) map[string]*LineObject {
	out := make(map[string]*LineObject, len(lines))
	for key, marker := range lines {
		if len(marker.Arr) > 0 {
			array := make([]map[string]*LineObject, len(marker.Arr))
			for i, element := range marker.Arr {
				array[i] = substituteForEachLineKeys(element, bindings)
			}
			marker = &LineObject{Line: marker.Line, Arr: array}
		}
		out[replaceForEachVars(key, bindings)] = marker
	}
	return out
}

func isPureRefNode(m map[string]interface{}) bool {
	for k := range m {
		if k != "Ref" && k != yamlLineInfoKey {
			return false
		}
	}
	return true
}

func replaceForEachVars(template string, bindings map[string]string) string {
	if !strings.Contains(template, "${") && !strings.Contains(template, "&{") {
		return template
	}
	const entriesPerBinding = 4
	replacements := make([]string, 0, entriesPerBinding*len(bindings))
	for _, name := range slices.Sorted(maps.Keys(bindings)) {
		value := bindings[name]
		replacements = append(replacements, "${"+name+"}", value, "&{"+name+"}", value)
	}
	return strings.NewReplacer(replacements...).Replace(template)
}

/*
	YAML Node TYPES

	SequenceNode -> array
	ScalarNode -> generic (except for arrays, objects and maps)
	MappingNode -> map

*/
// sharedNodes memoizes the value and the line information built for each node
// of a document whose file references were resolved: the content of a file
// referenced from several places is shared between its references, so its
// nodes are reached through several parents. Converting them once and sharing
// the result keeps the document as small as the files it is made of, where
// converting them on every path made it grow exponentially with the nesting
// depth of the references. It is nil for other documents.
type sharedNodes struct {
	values map[*yaml.Node]interface{}
	lines  map[linesKey]map[string]*LineObject
}

type linesKey struct {
	node *yaml.Node
	def  int
}

func newSharedNodes() *sharedNodes {
	return &sharedNodes{
		values: make(map[*yaml.Node]interface{}),
		lines:  make(map[linesKey]map[string]*LineObject),
	}
}

// forAlias returns the memo to convert the target of an alias with: each alias
// gets its own copy of the target, which its parent then modifies.
func (s *sharedNodes) forAlias() *sharedNodes {
	if s == nil {
		return nil
	}
	return newSharedNodes()
}

// unmarshal is the function that will parse the yaml elements and call the functions needed
// to place their line information in the payload
func unmarshal(ctx context.Context, val *yaml.Node, shared *sharedNodes, ignore *Ignore, skipLines bool) interface{} {
	return unmarshalWithDepth(ctx, val, make(map[*yaml.Node]bool), shared, ignore, skipLines)
}

// unmarshalWithDepth handles recursive unmarshaling with circular reference detection
func unmarshalWithDepth(ctx context.Context, val *yaml.Node, visited map[*yaml.Node]bool, //nolint:gocyclo
	shared *sharedNodes, ignore *Ignore, skipLines bool) interface{} {
	if val == nil {
		return nil
	}
	if shared != nil {
		if value, ok := shared.values[val]; ok {
			return value
		}
	}
	if visited[val] {
		return nil
	}
	visited[val] = true
	defer func() { delete(visited, val) }()
	if ignore != nil {
		ignore.ignoreCommentsYAML(val)
	}

	if val.Kind == yaml.AliasNode {
		return unmarshalWithDepth(ctx, val.Alias, visited, shared.forAlias(), ignore, skipLines)
	}

	// Preserve the legacy representation of sequence documents and nested
	// sequence elements. Mapping fields use arrays in unmarshalYAMLField.
	if val.Kind == yaml.SequenceNode {
		contentArray := make([]interface{}, 0, len(val.Content))
		for _, contentEntry := range val.Content {
			contentArray = append(contentArray, unmarshalWithDepth(ctx, contentEntry, visited, shared, ignore, skipLines))
		}
		tmp := map[string]interface{}{"playbooks": contentArray}
		if shared != nil {
			shared.values[val] = tmp
		}
		return tmp
	}
	if val.Kind == yaml.ScalarNode {
		return internedScalarNodeResolver(ctx, val)
	}

	tmp := make(map[string]interface{}, len(val.Content)/2+1)
	var merges []*yaml.Node
	// iterate two by two, since first iteration is the key and the second is the value
	for i := 0; i < len(val.Content); i += 2 {
		field := yamlAliasTarget(val.Content[i])
		if field != nil && field.Kind == yaml.ScalarNode {
			if isYAMLMergeKey(val.Content[i]) {
				merges = append(merges, val.Content[i+1])
				continue
			}

			tmp[internYAMLScalar(field.Value)] = unmarshalYAMLField(
				ctx, val.Content[i+1], val.Content[i].Line, visited, shared, ignore, skipLines)
		}
	}
	// Explicit keys win regardless of source order; earlier merge sources win
	// over later ones. A quoted "<<" is an ordinary key, not a merge.
	for _, merge := range merges {
		walkYAMLMerges(merge, visited, shared, func(node *yaml.Node, memo *sharedNodes) {
			values, _ := unmarshalWithDepth(ctx, node, visited, memo, ignore, skipLines).(map[string]interface{})
			for key, value := range values {
				if _, exists := tmp[key]; !exists && key != yamlLineInfoKey {
					tmp[key] = value
				}
			}
		})
	}
	if !skipLines && len(merges) > 0 {
		// Locations belong to the resulting mapping, including explicit keys
		// and every merge source, not just the first inherited marker map.
		tmp[yamlLineInfoKey] = getLines(val, merges[0].Line, shared)
	}
	if shared != nil {
		shared.values[val] = tmp
	}
	return tmp
}

// Field aliases must use the same representation as an inline field value.
// In particular, sequences here are arrays, not top-level Ansible documents.
func unmarshalYAMLField(ctx context.Context, node *yaml.Node, def int, visited map[*yaml.Node]bool,
	shared *sharedNodes, ignore *Ignore, skipLines bool) interface{} {
	if node == nil || visited[node] {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		visited[node] = true
		defer delete(visited, node)
		return unmarshalYAMLField(ctx, node.Alias, def, visited, shared.forAlias(), ignore, skipLines)
	}
	if rewritten, ok := rewriteCFNShortFormIntrinsic(ctx, node, visited, shared, ignore, skipLines); ok {
		if mapping, ok := rewritten.(map[string]interface{}); ok && !skipLines {
			mapping[yamlLineInfoKey] = getLines(node, def, shared)
		}
		return rewritten
	}
	if node.Kind == yaml.SequenceNode {
		visited[node] = true
		defer delete(visited, node)
		items := make([]interface{}, 0, len(node.Content))
		for _, child := range node.Content {
			items = append(items, unmarshalWithDepth(ctx, child, visited, shared, ignore, skipLines))
		}
		return items
	}
	value := unmarshalWithDepth(ctx, node, visited, shared, ignore, skipLines)
	if mapping, ok := value.(map[string]interface{}); ok && !skipLines {
		mapping[yamlLineInfoKey] = getLines(node, def, shared)
	}
	return value
}

// Only actual merge keys reach this walk. Alias and sequence cycles are cut
// using the same active path as conversion; sibling aliases remain independent.
func walkYAMLMerges(node *yaml.Node, visited map[*yaml.Node]bool, shared *sharedNodes,
	visit func(*yaml.Node, *sharedNodes)) {
	if node == nil || visited[node] {
		return
	}
	switch node.Kind {
	case yaml.AliasNode:
		visited[node] = true
		defer delete(visited, node)
		walkYAMLMerges(node.Alias, visited, shared.forAlias(), visit)
	case yaml.SequenceNode:
		visited[node] = true
		defer delete(visited, node)
		for _, child := range node.Content {
			walkYAMLMerges(child, visited, shared, visit)
		}
	case yaml.MappingNode:
		visit(node, shared)
	}
}

// getLines creates the map containing the line information for the yaml Node
// def is the line to be used as "_dd__default"
func getLines(val *yaml.Node, def int, shared *sharedNodes) map[string]*LineObject {
	return getYAMLLines(val, def, shared, make(map[*yaml.Node]bool))
}

func getYAMLLines(val *yaml.Node, def int, shared *sharedNodes, visited map[*yaml.Node]bool) map[string]*LineObject {
	lineMap := map[string]*LineObject{"_dd__default": {Line: def, Arr: []map[string]*LineObject{}}}
	if val == nil || visited[val] {
		return lineMap
	}
	visited[val] = true
	defer delete(visited, val)
	if val.Kind == yaml.AliasNode {
		return getYAMLLines(val.Alias, def, shared.forAlias(), visited)
	}
	key := linesKey{node: val, def: def}
	if shared != nil {
		if lines, ok := shared.lines[key]; ok {
			return lines
		}
	}
	if val.Kind == yaml.SequenceNode {
		lineMap["_dd__default"].Arr = yamlSequenceLines(val, shared, visited)
	} else {
		yamlMappingLines(val, def, shared, visited, lineMap)
	}
	if shared != nil {
		shared.lines[key] = lineMap
	}
	return lineMap
}

func isYAMLMergeKey(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Value == "<<" && node.ShortTag() == "!!merge"
}

func yamlMappingLines(val *yaml.Node, def int, shared *sharedNodes, visited map[*yaml.Node]bool,
	lineMap map[string]*LineObject) {
	var merges []*yaml.Node
	for i := 0; i+1 < len(val.Content); i += 2 {
		field, value := val.Content[i], val.Content[i+1]
		name := yamlAliasTarget(field)
		if name == nil || name.Kind != yaml.ScalarNode {
			continue
		}
		var array []map[string]*LineObject
		if target := yamlAliasTarget(value); target != nil && target.Kind == yaml.SequenceNode {
			for _, child := range target.Content {
				defaultLine := field.Line
				if child.Kind == yaml.ScalarNode {
					defaultLine = child.Line
				} else if child.Kind == yaml.MappingNode && len(child.Content) > 0 {
					defaultLine = child.Content[0].Line
				}
				array = append(array, getYAMLLines(child, defaultLine, shared, visited))
			}
		}
		if array == nil {
			array = []map[string]*LineObject{}
		}
		lineMap["_dd_"+name.Value] = &LineObject{Line: field.Line, Arr: array}
		if isYAMLMergeKey(field) {
			merges = append(merges, value)
		}
	}
	for _, merge := range merges {
		walkYAMLMerges(merge, visited, shared, func(node *yaml.Node, memo *sharedNodes) {
			for name, marker := range getYAMLLines(node, def, memo, visited) {
				if _, exists := lineMap[name]; !exists {
					lineMap[name] = marker
				}
			}
		})
	}
}

func yamlAliasTarget(node *yaml.Node) *yaml.Node {
	var visited map[*yaml.Node]bool
	for node != nil && node.Kind == yaml.AliasNode {
		if visited[node] {
			return nil
		}
		if visited == nil {
			visited = make(map[*yaml.Node]bool)
		}
		visited[node] = true
		node = node.Alias
	}
	return node
}

func yamlSequenceLines(node *yaml.Node, shared *sharedNodes, visited map[*yaml.Node]bool) []map[string]*LineObject {
	array := make([]map[string]*LineObject, 0, len(node.Content))
	for _, child := range node.Content {
		array = append(array, getYAMLLines(child, child.Line, shared, visited))
	}
	return array
}

// yamlScalarInterner canonicalizes YAML scalar strings so repeated values
// across a corpus share one backing array.
var (
	yamlScalarInternerMu sync.RWMutex
	yamlScalarInterner   = make(map[string]string)
)

// ClearYAMLScalarInterner drops the intern lookup after prepare. Live
// documents still share the interned strings; the table is not retained
// across scans in a long-lived process.
func ClearYAMLScalarInterner() {
	yamlScalarInternerMu.Lock()
	yamlScalarInterner = make(map[string]string)
	yamlScalarInternerMu.Unlock()
}

func internYAMLScalar(s string) string {
	if s == "" {
		return s
	}
	yamlScalarInternerMu.RLock()
	canonical, ok := yamlScalarInterner[s]
	yamlScalarInternerMu.RUnlock()
	if ok {
		return canonical
	}

	yamlScalarInternerMu.Lock()
	if existing, ok := yamlScalarInterner[s]; ok {
		yamlScalarInternerMu.Unlock()
		return existing
	}
	yamlScalarInterner[s] = s
	yamlScalarInternerMu.Unlock()
	return s
}

// internedScalarNodeResolver is scalarNodeResolver with interning; string-tagged
// scalars skip the per-scalar decoder construction (Decode returns the node's
// own string, so the fast path is equivalent).
func internedScalarNodeResolver(ctx context.Context, val *yaml.Node) interface{} {
	if val.Tag == "!!str" {
		return internYAMLScalar(val.Value)
	}
	resolved := scalarNodeResolver(ctx, val)
	if s, ok := resolved.(string); ok {
		return internYAMLScalar(s)
	}
	return resolved
}

// scalarNodeResolver transforms a ScalarNode value in its correct type
func scalarNodeResolver(ctx context.Context, val *yaml.Node) interface{} {
	if rewritten, ok := rewriteCFNShortFormIntrinsic(ctx, val, nil, nil, nil, IsLazyLineInfo(ctx)); ok {
		return rewritten
	}
	var resolved interface{}
	if err := val.Decode(&resolved); err != nil {
		filePath, _ := ctx.Value(yamlFilePathContextKey{}).(string)
		utils.WarnUnlessFixture(ctx, filePath).Msgf("failed to decode scalar in yaml parser for %s: %q", filePath, val.Value)
		return val.Value
	}
	return normalizeScalar(resolved)
}

// normalizeScalar maps a decoded scalar to what the old JSON round-trip produced:
// float64 numbers, RFC3339 timestamp strings, base64 []byte.
func normalizeScalar(resolved interface{}) interface{} {
	switch v := resolved.(type) {
	case time.Time:
		return v.Format(time.RFC3339Nano)
	case []byte:
		// json.Marshal encodes []byte as a base64 string; the JSON round-trip
		// this replaces fed that string to json.Unmarshal, so downstream saw
		// (and rules expect) the base64 text, not the raw bytes.
		return base64.StdEncoding.EncodeToString(v)
	case int:
		return float64(v)
	case int8:
		return float64(v)
	case int16:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint8:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case float32:
		return float64(v)
	case float64:
		return v
	default:
		return resolved
	}
}

// rewriteCFNShortFormIntrinsic converts a short-form CFN intrinsic to its long-form map.
// It is a no-op for documents that are not CloudFormation templates.
func rewriteCFNShortFormIntrinsic(ctx context.Context, val *yaml.Node, visited map[*yaml.Node]bool,
	shared *sharedNodes, ignore *Ignore, skipLines bool) (interface{}, bool) {
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
			seq = append(seq, decodeIntrinsicChild(ctx, child, visited, shared, ignore, skipLines))
		}
		return map[string]interface{}{longForm: seq}, true
	case yaml.MappingNode:
		v := visited
		if v == nil {
			v = make(map[*yaml.Node]bool)
		}
		return map[string]interface{}{longForm: unmarshalWithDepth(ctx, val, v, shared, ignore, skipLines)}, true
	}
	return nil, false
}

func decodeIntrinsicChild(ctx context.Context, val *yaml.Node, visited map[*yaml.Node]bool,
	shared *sharedNodes, ignore *Ignore, skipLines bool) interface{} {
	if val == nil {
		return nil
	}
	if val.Kind == yaml.AliasNode {
		if visited == nil {
			visited = make(map[*yaml.Node]bool)
		}
		if visited[val] {
			return nil
		}
		visited[val] = true
		defer delete(visited, val)
		return decodeIntrinsicChild(ctx, val.Alias, visited, shared.forAlias(), ignore, skipLines)
	}
	if rewritten, ok := rewriteCFNShortFormIntrinsic(ctx, val, visited, shared, ignore, skipLines); ok {
		return rewritten
	}
	v := visited
	if v == nil {
		v = make(map[*yaml.Node]bool)
	}
	switch val.Kind {
	case yaml.ScalarNode:
		return internedScalarNodeResolver(ctx, val)
	case yaml.MappingNode:
		return unmarshalWithDepth(ctx, val, v, shared, ignore, skipLines)
	case yaml.SequenceNode:
		seq := make([]interface{}, 0, len(val.Content))
		for _, child := range val.Content {
			seq = append(seq, decodeIntrinsicChild(ctx, child, v, shared, ignore, skipLines))
		}
		return seq
	}
	return nil
}
