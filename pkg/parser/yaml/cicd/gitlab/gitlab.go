/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package gitlab provides lightweight GitLab CI file-path and YAML structure
// helpers shared across file classification, parsing, and inventory extraction.
package gitlab

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

// Dialect identifies trusted GitLab semantic output independently of its source path.
const Dialect = model.GitLabDialect

const (
	kwAfterScript      = "after_script"
	kwArtifacts        = "artifacts"
	kwBeforeScript     = "before_script"
	kwCache            = "cache"
	kwHooks            = "hooks"
	kwDefault          = "default"
	kwWorkflow         = "workflow"
	kwIDTokens         = "id_tokens"
	kwImage            = "image"
	kwInclude          = "include"
	kwInterrupt        = "interruptible"
	kwRetry            = "retry"
	kwServices         = "services"
	kwSpec             = "spec"
	kwStage            = "stage"
	kwTags             = "tags"
	kwTimeout          = "timeout"
	kwVariables        = "variables"
	gitlabReferenceTag = "!reference"
)

// reservedTopLevelKeywords are GitLab CI global keywords that cannot be job
// names. Job-level keywords such as "release", "artifacts", "hooks", and
// "pages" are valid job names and intentionally omitted.
var reservedTopLevelKeywords = map[string]bool{
	kwAfterScript:  true,
	kwBeforeScript: true,
	kwCache:        true,
	kwDefault:      true,
	kwImage:        true,
	kwInclude:      true,
	kwServices:     true,
	kwSpec:         true,
	"stages":       true,
	"types":        true,
	kwVariables:    true,
	kwWorkflow:     true,
}

// primaryJobKeywords unambiguously mark a top-level mapping as a GitLab CI job.
var primaryJobKeywords = map[string]bool{
	kwAfterScript:  true,
	kwBeforeScript: true,
	"extends":      true,
	"run":          true,
	"script":       true,
	"trigger":      true,
}

// secondaryJobKeywords identify a GitLab CI job when paired with "stage".
var secondaryJobKeywords = map[string]bool{
	"allow_failure":      true,
	kwArtifacts:          true,
	kwCache:              true,
	"coverage":           true,
	"dast_configuration": true,
	"dependencies":       true,
	"environment":        true,
	"except":             true,
	kwHooks:              true,
	kwIDTokens:           true,
	"identity":           true,
	kwImage:              true,
	"inherit":            true,
	kwInterrupt:          true,
	"needs":              true,
	"only":               true,
	"pages":              true,
	"parallel":           true,
	"release":            true,
	"resource_group":     true,
	kwRetry:              true,
	"rules":              true,
	"secrets":            true,
	kwServices:           true,
	kwTags:               true,
	kwTimeout:            true,
	kwVariables:          true,
	"when":               true,
}

// defaultSectionKeywords are keys valid inside GitLab CI's top-level default:.
var defaultSectionKeywords = map[string]bool{
	kwAfterScript:  true,
	kwArtifacts:    true,
	kwBeforeScript: true,
	kwCache:        true,
	kwHooks:        true,
	kwIDTokens:     true,
	kwImage:        true,
	kwInterrupt:    true,
	kwRetry:        true,
	kwServices:     true,
	kwTags:         true,
	kwTimeout:      true,
}

// includeEntryKeywords are keys inside a GitLab CI include: entry mapping.
var includeEntryKeywords = map[string]bool{
	"component": true,
	"file":      true,
	"local":     true,
	"project":   true,
	"remote":    true,
	"template":  true,
}

// IsConfigFileName reports whether path has a canonical GitLab CI filename
// (.gitlab-ci.yml, .gitlab-ci.yaml, or *.gitlab-ci.yml / *.gitlab-ci.yaml).
func IsConfigFileName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml" ||
		strings.HasSuffix(base, ".gitlab-ci.yml") || strings.HasSuffix(base, ".gitlab-ci.yaml")
}

// IsCIDirPath reports whether path is a YAML file inside a .gitlab/ci/ directory.
func IsCIDirPath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	return strings.HasPrefix(lower, ".gitlab/ci/") || strings.Contains(lower, "/.gitlab/ci/")
}

// NormalizeExtension applies GitLab's filename policy to discovery and routing
// tokens without changing the source path or other platforms' extension policy.
func NormalizeExtension(path, ext string) string {
	if !strings.EqualFold(ext, ".yaml") && !strings.EqualFold(ext, ".yml") {
		return ext
	}
	if IsConfigFileName(path) || IsCIDirPath(path) {
		return strings.ToLower(ext)
	}
	return ext
}

// IsReservedTopLevelKeyword reports whether key is a GitLab CI global keyword
// rather than a job name.
func IsReservedTopLevelKeyword(key string) bool {
	return reservedTopLevelKeywords[key]
}

// IsParserMetadataKey reports whether key is a synthetic key added by the YAML
// or CI/CD parsers.
func IsParserMetadataKey(key string) bool {
	return key == "_dd_lines" || key == "_path" ||
		key == "_parsed_"+kwBeforeScript || key == "_parsed_"+kwAfterScript
}

// isJobMapping reports whether a top-level entry (key, val) in a parsed
// document represents a GitLab CI job (including hidden ".template" jobs).
func isJobMapping(key string, val interface{}) bool {
	if IsReservedTopLevelKeyword(key) {
		return false
	}
	m, ok := val.(map[string]interface{})
	if !ok || len(m) == 0 {
		return false
	}
	if needs, ok := m["needs"].(map[string]interface{}); ok {
		if pipeline, ok := needs["pipeline"].(string); ok && pipeline != "" {
			return true
		}
	}
	hasStage := false
	hasSecondary := false
	for k := range m {
		if primaryJobKeywords[k] {
			return true
		}
		if k == kwStage {
			hasStage = true
		} else if secondaryJobKeywords[k] {
			hasSecondary = true
		}
	}
	return hasStage && hasSecondary
}

// IsExecutableJob reports whether a top-level entry is a concrete GitLab CI job
// (not a hidden "." template job).
func IsExecutableJob(key string, val interface{}) bool {
	return !strings.HasPrefix(key, ".") && isJobMapping(key, val)
}

type jobNodeScan struct {
	hasStage     bool
	hasSecondary bool
	seen         map[*yaml.Node]struct{}
}

// isJobNode reports whether a top-level YAML mapping entry represents a GitLab
// CI job (including hidden ".template" jobs).
func isJobNode(key string, val *yaml.Node) bool {
	if IsReservedTopLevelKeyword(key) {
		return false
	}
	val = yamlnode.ResolveAlias(val)
	if val == nil || val.Kind != yaml.MappingNode || len(val.Content) == 0 {
		return false
	}
	var scan jobNodeScan
	return scan.mapping(val)
}

func (s *jobNodeScan) mapping(m *yaml.Node) bool {
	m = yamlnode.ResolveAlias(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	if _, visited := s.seen[m]; visited {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode {
			continue
		}
		if k.Value == "needs" && isStatusPipelineNode(m.Content[i+1]) {
			return true
		}
		if k.Value == "<<" && k.Tag != "!!str" {
			if s.seen == nil {
				s.seen = make(map[*yaml.Node]struct{})
			}
			s.seen[m] = struct{}{}
			if s.merge(m.Content[i+1]) {
				return true
			}
			continue
		}
		if s.keyword(k.Value) {
			return true
		}
	}
	return s.hasStage && s.hasSecondary
}

func isStatusPipelineNode(needs *yaml.Node) bool {
	needs = yamlnode.ResolveAlias(needs)
	pipeline := yamlnode.ResolveAlias(effectiveMappingValue(needs, "pipeline"))
	return pipeline != nil && pipeline.Kind == yaml.ScalarNode && pipeline.Tag == yamlnode.StrTag && pipeline.Value != ""
}

func (s *jobNodeScan) keyword(name string) bool {
	if primaryJobKeywords[name] {
		return true
	}
	if name == kwStage {
		s.hasStage = true
	} else if secondaryJobKeywords[name] {
		s.hasSecondary = true
	}
	return false
}

func (s *jobNodeScan) merge(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case yaml.AliasNode:
		return s.mapping(node.Alias)
	case yaml.MappingNode:
		return s.mapping(node)
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if s.merge(item) {
				return true
			}
		}
	}
	return false
}

// isGitHubCICDNode reports whether root has the shape of a GitHub Actions
// workflow (on + jobs mapping), GitHub Action manifest (runs.using scalar), or
// Dependabot config (version scalar + updates sequence).
func isGitHubCICDNode(root *yaml.Node) bool {
	root = yamlnode.ResolveAlias(root)
	if root == nil || root.Kind != yaml.MappingNode {
		return false
	}
	if on := effectiveMappingValue(root, "on"); on != nil && !isJobNode("on", on) {
		if jobs := yamlnode.ResolveAlias(effectiveMappingValue(root, "jobs")); jobs != nil && jobs.Kind == yaml.MappingNode {
			return true
		}
	}
	if runs := yamlnode.ResolveAlias(effectiveMappingValue(root, "runs")); runs != nil && runs.Kind == yaml.MappingNode {
		if using := yamlnode.ResolveAlias(effectiveMappingValue(runs, "using")); using != nil && using.Kind == yaml.ScalarNode {
			return true
		}
	}
	if ver := yamlnode.ResolveAlias(effectiveMappingValue(root, "version")); ver != nil && ver.Kind == yaml.ScalarNode {
		if updates := yamlnode.ResolveAlias(effectiveMappingValue(root, "updates")); updates != nil && updates.Kind == yaml.SequenceNode {
			return true
		}
	}
	return false
}

// isGitHubCICDDocument reports whether doc has the shape of a parsed GitHub
// Actions workflow, GitHub Action manifest, or Dependabot config.
func isGitHubCICDDocument(doc map[string]interface{}) bool {
	if doc == nil {
		return false
	}
	if on, hasOn := doc["on"]; hasOn && !isJobMapping("on", on) {
		if _, hasJobs := doc["jobs"].(map[string]interface{}); hasJobs {
			return true
		}
	}
	if runs, ok := doc["runs"].(map[string]interface{}); ok {
		if _, hasUsing := runs["using"].(string); hasUsing {
			return true
		}
	}
	if ver, hasVer := doc["version"]; hasVer {
		if _, isMap := ver.(map[string]interface{}); !isMap {
			if _, hasUpdates := doc["updates"].([]interface{}); hasUpdates {
				return true
			}
		}
	}
	return false
}

// IsSpecHeaderNode reports whether root is a GitLab CI/CD component or template
// specification header document (only "spec" containing "inputs").
func IsSpecHeaderNode(root *yaml.Node) bool {
	root = yamlnode.ResolveAlias(root)
	if root == nil || root.Kind != yaml.MappingNode || len(root.Content) != 2 {
		return false
	}
	if root.Content[0].Kind != yaml.ScalarNode || root.Content[0].Value != kwSpec {
		return false
	}
	spec := yamlnode.ResolveAlias(root.Content[1])
	return spec != nil && spec.Kind == yaml.MappingNode && yamlnode.MappingValue(spec, "inputs") != nil
}

// IsSpecHeaderDocument reports whether doc is a parsed GitLab CI spec header.
func IsSpecHeaderDocument(doc map[string]interface{}) bool {
	if doc == nil {
		return false
	}
	spec, ok := doc[kwSpec].(map[string]interface{})
	if !ok {
		return false
	}
	if _, hasInputs := spec["inputs"]; !hasInputs {
		return false
	}
	for k, value := range doc {
		if k != kwSpec && (!IsParserMetadataKey(k) || isJobMapping(k, value)) {
			return false
		}
	}
	return true
}

// IsTemplateFragmentNode recognizes non-executable fragments only in callers
// that already established a .gitlab/ci path. Other platform shapes win first.
func IsTemplateFragmentNode(root *yaml.Node) bool {
	root = yamlnode.ResolveAlias(root)
	if root == nil || root.Kind != yaml.MappingNode || isGitHubCICDNode(root) || isOtherYAMLNode(root) {
		return false
	}
	if IsSpecHeaderNode(root) {
		return true
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := yamlnode.ResolveAlias(root.Content[index])
		value := yamlnode.ResolveAlias(root.Content[index+1])
		if key == nil || value == nil || key.Kind != yaml.ScalarNode {
			continue
		}
		if isGlobalFragment(key.Value, value) {
			return true
		}
		if strings.HasPrefix(key.Value, ".") && isHiddenFragment(value) {
			return true
		}
	}
	return false
}

func isGlobalFragment(key string, value *yaml.Node) bool {
	switch key {
	case kwVariables, kwDefault, kwWorkflow:
		return value.Kind == yaml.MappingNode
	case "stages", "types", kwServices:
		return value.Kind == yaml.SequenceNode
	case kwImage:
		return value.Kind == yaml.ScalarNode || value.Kind == yaml.MappingNode
	case kwCache:
		return value.Kind == yaml.MappingNode || value.Kind == yaml.SequenceNode
	case kwBeforeScript, kwAfterScript, kwInclude:
		return value.Kind == yaml.ScalarNode || value.Kind == yaml.SequenceNode || value.Kind == yaml.MappingNode
	default:
		return false
	}
}

func isHiddenFragment(value *yaml.Node) bool {
	if value.Kind != yaml.MappingNode {
		return false
	}
	for member := 0; member+1 < len(value.Content); member += 2 {
		field := yamlnode.ResolveAlias(value.Content[member])
		if field != nil && (primaryJobKeywords[field.Value] || secondaryJobKeywords[field.Value] || field.Value == kwStage) {
			return true
		}
	}
	return false
}

// IsDocumentNode reports whether a YAML mapping root looks like a GitLab CI
// configuration document (and not GitHub Actions, Dependabot, Kubernetes, or
// CloudFormation).
func IsDocumentNode(root *yaml.Node) bool {
	root = yamlnode.ResolveAlias(root)
	if root == nil || root.Kind != yaml.MappingNode || len(root.Content) == 0 {
		return false
	}
	if isGitHubCICDNode(root) || isOtherYAMLNode(root) {
		return false
	}
	if hasReferenceTag(root, nil) {
		return true
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := yamlnode.ResolveAlias(root.Content[i])
		if key != nil && key.Kind == yaml.ScalarNode && isJobNode(key.Value, root.Content[i+1]) {
			return true
		}
	}
	return hasGitLabTopLevelStructure(root)
}

func isOtherYAMLNode(root *yaml.Node) bool {
	if services := yamlnode.ResolveAlias(effectiveMappingValue(root, kwServices)); services != nil && services.Kind == yaml.MappingNode {
		return true
	}
	if version := yamlnode.ResolveAlias(effectiveMappingValue(root, "apiVersion")); version != nil && version.Kind == yaml.ScalarNode {
		if kind := yamlnode.ResolveAlias(effectiveMappingValue(root, "kind")); kind != nil && kind.Kind == yaml.ScalarNode {
			return true
		}
	}
	resources := yamlnode.ResolveAlias(effectiveMappingValue(root, "Resources"))
	if resources == nil {
		return false
	}
	if resources.Kind == yaml.MappingNode {
		allResources := true
		types := make(map[*yaml.Node]bool)
		for i := 1; i < len(resources.Content); i += 2 {
			key := yamlnode.ResolveAlias(resources.Content[i-1])
			if key != nil && strings.HasPrefix(key.Value, "Fn::ForEach::") {
				continue
			}
			if !hasCloudFormationType(resources.Content[i], types) {
				allResources = false
				break
			}
		}
		if allResources {
			return true
		}
	}
	return !isJobNode("Resources", resources)
}

// Classifiers inspect effective YAML keys without mutating or expanding the
// anchor DAG. Explicit keys win; merge sequences use their first matching map.
func effectiveMappingValue(root *yaml.Node, name string) *yaml.Node {
	seen := make(map[*yaml.Node]bool)
	pending := []*yaml.Node{root}
	for len(pending) > 0 {
		node := yamlnode.ResolveAlias(pending[len(pending)-1])
		pending = pending[:len(pending)-1]
		if node == nil || seen[node] {
			continue
		}
		seen[node] = true
		switch node.Kind {
		case yaml.MappingNode:
			if value := explicitMappingValue(node, name); value != nil {
				return value
			}
			for index := len(node.Content) - 2; index >= 0; index -= 2 {
				if key := yamlnode.ResolveAlias(node.Content[index]); key != nil && isYAMLMergeKey(key) {
					pending = append(pending, node.Content[index+1])
				}
			}
		case yaml.SequenceNode:
			for index := len(node.Content) - 1; index >= 0; index-- {
				pending = append(pending, node.Content[index])
			}
		}
	}
	return nil
}

func explicitMappingValue(node *yaml.Node, name string) *yaml.Node {
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := yamlnode.ResolveAlias(node.Content[index])
		if key != nil && key.Kind == yaml.ScalarNode && key.Value == name {
			return node.Content[index+1]
		}
	}
	return nil
}

// Resource bodies may inherit their Type through YAML aliases and merge keys.
// Inspect only those edges, memoizing shared nodes and breaking merge cycles.
func hasCloudFormationType(node *yaml.Node, memo map[*yaml.Node]bool) bool {
	node = yamlnode.ResolveAlias(node)
	if node == nil {
		return false
	}
	if value, known := memo[node]; known {
		return value
	}
	memo[node] = false
	if node.Kind == yaml.SequenceNode {
		for _, child := range node.Content {
			if hasCloudFormationType(child, memo) {
				memo[node] = true
				return true
			}
		}
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := yamlnode.ResolveAlias(node.Content[index])
			if key == nil || key.Kind != yaml.ScalarNode {
				continue
			}
			if key.Value == "Type" || (isYAMLMergeKey(key) && hasCloudFormationType(node.Content[index+1], memo)) {
				memo[node] = true
				return true
			}
		}
	}
	return false
}

// isDocumentNodes reports whether a slice of decoded document roots represents
// a GitLab CI file (supporting a leading spec: inputs header followed by the
// pipeline document).
func isDocumentNodes(roots []*yaml.Node) bool {
	if len(roots) == 0 {
		return false
	}
	if len(roots) >= 2 && IsSpecHeaderNode(roots[0]) {
		return IsDocumentNode(roots[1])
	}
	for _, root := range roots {
		if IsDocumentNode(root) {
			return true
		}
	}
	return false
}

// IsDocument reports whether a parsed model.Document map looks like GitLab CI.
func IsDocument(doc map[string]interface{}) bool {
	if len(doc) == 0 || isGitHubCICDDocument(doc) || IsSpecHeaderDocument(doc) || isOtherYAMLDocument(doc) {
		return false
	}
	for k, v := range doc {
		if isJobMapping(k, v) {
			return true
		}
	}
	return hasGitLabDocumentTopLevel(doc)
}

func isOtherYAMLDocument(doc map[string]interface{}) bool {
	if _, services := doc[kwServices].(map[string]interface{}); services {
		return true
	}
	if _, hasAPI := doc["apiVersion"].(string); hasAPI {
		if _, hasKind := doc["kind"].(string); hasKind {
			return true
		}
	}
	resources, present := doc["Resources"]
	if !present {
		return false
	}
	if entries, ok := resources.(map[string]interface{}); ok {
		allResources := true
		for key, value := range entries {
			if strings.HasPrefix(key, "Fn::ForEach::") {
				continue
			}
			entry, mapping := value.(map[string]interface{})
			if !mapping || entry["Type"] == nil {
				allResources = false
				break
			}
		}
		if allResources {
			return true
		}
	}
	return !isJobMapping("Resources", resources)
}

func hasGitLabDocumentTopLevel(doc map[string]interface{}) bool {
	if wf, ok := doc[kwWorkflow].(map[string]interface{}); ok {
		if _, hasRules := wf["rules"]; hasRules {
			return true
		}
	}
	if def, ok := doc[kwDefault].(map[string]interface{}); ok {
		for k := range def {
			if defaultSectionKeywords[k] {
				return true
			}
		}
	}
	if inc, ok := doc[kwInclude]; ok && hasGitLabIncludeValue(inc) {
		return true
	}
	_, hasBefore := doc[kwBeforeScript]
	_, hasAfter := doc[kwAfterScript]
	return hasBefore || hasAfter
}

func hasGitLabTopLevelStructure(root *yaml.Node) bool {
	return hasGitLabWorkflowOrDefault(root) ||
		hasGitLabIncludeOrScripts(root) ||
		hasGitLabStagesWithContext(root)
}

func hasGitLabWorkflowOrDefault(root *yaml.Node) bool {
	if wf := yamlnode.ResolveAlias(yamlnode.MappingValue(root, kwWorkflow)); wf != nil && wf.Kind == yaml.MappingNode {
		if yamlnode.MappingValue(wf, "rules") != nil {
			return true
		}
	}
	if def := yamlnode.ResolveAlias(yamlnode.MappingValue(root, kwDefault)); def != nil && def.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(def.Content); i += 2 {
			if def.Content[i].Kind == yaml.ScalarNode && defaultSectionKeywords[def.Content[i].Value] {
				return true
			}
		}
	}
	return false
}

func hasGitLabIncludeOrScripts(root *yaml.Node) bool {
	if inc := yamlnode.ResolveAlias(yamlnode.MappingValue(root, kwInclude)); inc != nil && hasGitLabIncludeNode(inc) {
		return true
	}
	for _, key := range []string{kwBeforeScript, kwAfterScript} {
		n := yamlnode.ResolveAlias(yamlnode.MappingValue(root, key))
		if n != nil && (n.Kind == yaml.SequenceNode || n.Kind == yaml.ScalarNode) {
			return true
		}
	}
	return false
}

func hasGitLabStagesWithContext(root *yaml.Node) bool {
	stages := yamlnode.ResolveAlias(yamlnode.MappingValue(root, "stages"))
	if stages == nil || stages.Kind != yaml.SequenceNode {
		return false
	}
	for _, key := range []string{kwVariables, kwImage, kwServices, kwCache} {
		if yamlnode.MappingValue(root, key) != nil {
			return true
		}
	}
	return false
}

func hasGitLabIncludeNode(node *yaml.Node) bool {
	node = yamlnode.ResolveAlias(node)
	if node == nil {
		return false
	}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Kind == yaml.ScalarNode && includeEntryKeywords[node.Content[i].Value] {
				return true
			}
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			item = yamlnode.ResolveAlias(item)
			if item == nil {
				continue
			}
			if item.Kind == yaml.MappingNode && hasGitLabIncludeNode(item) {
				return true
			}
			if item.Kind == yaml.ScalarNode && isYAMLIncludeString(item.Value) {
				return true
			}
		}
	case yaml.ScalarNode:
		return isYAMLIncludeString(node.Value)
	}
	return false
}

func hasGitLabIncludeValue(val interface{}) bool {
	switch v := val.(type) {
	case string:
		return isYAMLIncludeString(v)
	case map[string]interface{}:
		for k := range v {
			if includeEntryKeywords[k] {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if hasGitLabIncludeValue(item) {
				return true
			}
		}
	}
	return false
}

func isYAMLIncludeString(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

func hasReferenceTag(node *yaml.Node, seen map[*yaml.Node]struct{}) bool {
	if node == nil {
		return false
	}
	if node.Tag == "!reference" {
		return true
	}
	if seen == nil {
		seen = make(map[*yaml.Node]struct{})
	}
	if _, ok := seen[node]; ok {
		return false
	}
	seen[node] = struct{}{}
	if node.Alias != nil && hasReferenceTag(node.Alias, seen) {
		return true
	}
	for _, child := range node.Content {
		if hasReferenceTag(child, seen) {
			return true
		}
	}
	return false
}
