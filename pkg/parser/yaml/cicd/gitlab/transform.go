/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package gitlab

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
)

var contentSignals = [][]byte{
	[]byte(gitlabReferenceTag),
	[]byte("script:"),
	[]byte("before_script:"),
	[]byte("after_script:"),
	[]byte("stages:"),
	[]byte("extends:"),
	[]byte("trigger:"),
	[]byte("needs:"),
	[]byte("workflow:"),
	[]byte("include:"),
	[]byte("spec:"),
}

// ShouldParse is the single dialect decision for cicd.Parser. Canonical GitLab
// CI filenames always use the GitLab parser; all other paths are decoded once
// when a cheap byte signal matches and routed to GitLab only when their YAML
// structure matches GitLab CI (and not GitHub Actions or Dependabot).
func ShouldParse(fileContent []byte, filePath string) bool {
	if isGitHubWorkflowFile(fileContent, filePath) {
		return false
	}
	if IsConfigFileName(filePath) {
		return true
	}
	if !IsCIDirPath(filePath) && !hasAnyByteSignal(fileContent, contentSignals) {
		return false
	}

	dec := yaml.NewDecoder(bytes.NewReader(fileContent))
	var roots []*yaml.Node
	for len(roots) < 2 {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if yamlnode.IsEmptyDocument(&doc) {
			continue
		}
		roots = append(roots, doc.Content[0])
	}
	if IsCIDirPath(filePath) && len(roots) == 2 && IsSpecHeaderNode(roots[0]) {
		body := roots[1]
		return body.Kind == yaml.MappingNode && !isGitHubCICDNode(body) && !isOtherYAMLNode(body)
	}
	return isDocumentNodes(roots) || (IsCIDirPath(filePath) && hasTemplateFragment(roots))
}

func hasTemplateFragment(roots []*yaml.Node) bool {
	for _, root := range roots {
		if IsTemplateFragmentNode(root) {
			return true
		}
	}
	return false
}

// A GitHub workflow's directory and shape take precedence over a coincidental
// GitLab filename suffix. Canonical GitLab paths otherwise retain their policy.
func isGitHubWorkflowFile(content []byte, filePath string) bool {
	dir := filepath.ToSlash(filepath.Dir(filePath))
	if dir != ".github/workflows" && !strings.HasSuffix(dir, "/.github/workflows") {
		return false
	}
	var doc yaml.Node
	if yaml.Unmarshal(content, &doc) != nil || yamlnode.IsEmptyDocument(&doc) {
		return false
	}
	root := doc.Content[0]
	if isGitHubCICDNode(root) {
		return true
	}
	jobs := yamlnode.ResolveAlias(yamlnode.MappingValue(root, "jobs"))
	return yamlnode.MappingValue(root, "on") != nil && jobs != nil && jobs.Kind == yaml.MappingNode
}

func hasAnyByteSignal(content []byte, signals [][]byte) bool {
	for _, signal := range signals {
		if bytes.Contains(content, signal) {
			return true
		}
	}
	return false
}

// FileState holds the file-wide include caches shared across every YAML
// document in one GitLab CI file. Only reusable cached include nodes are
// registered in cachedNoRefNodes; temporary per-document scopes are released
// after each TransformDocument call.
type FileState struct {
	ctx                  context.Context
	fsys                 vfs.FS
	baseDir              string
	self                 string
	baseIncludeCache     map[string]*baseInclude
	variantIncludeCache  map[string][]*yaml.Node
	compiledIncludeCache map[string][]*yaml.Node
	cachedNoRefNodes     map[*yaml.Node]bool
	pendingSpecInputs    map[string]*yaml.Node
	lineOverlays         map[*yaml.Node]*model.LineOverlay
	mergedPositions      map[overlayPair]*model.LineOverlay
	useSiteScopes        map[*model.LineOverlay]*yaml.Node
	sourceScope          *yaml.Node
	keyOverlays          map[*yaml.Node]*model.LineOverlay
	snapshots            map[string]*model.SourceSnapshot
	nodeOrigins          map[*yaml.Node]model.SourcePosition
	sequenceOrigins      map[sequenceEdge]model.SourcePosition
	sourceMerges         map[sourceMergePair]*model.LineOverlay
	mergeSourceBuilder   *positionBuilder
	existenceConditions  map[string]existenceResult
	existenceCounts      map[bool]existencePathCount // keyed by top-level-only search
	uncertainIncludes    bool
}

// NewFileState constructs the file-wide state for parsing filePath.
func NewFileState(ctx context.Context, fsys vfs.FS, repoRoot, filePath string) *FileState {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	return &FileState{
		ctx:                  ctx,
		fsys:                 fsys,
		baseDir:              repoBaseDir(fsys, repoRoot, filePath),
		self:                 filePath,
		baseIncludeCache:     make(map[string]*baseInclude),
		variantIncludeCache:  make(map[string][]*yaml.Node),
		compiledIncludeCache: make(map[string][]*yaml.Node),
		cachedNoRefNodes:     make(map[*yaml.Node]bool),
		keyOverlays:          make(map[*yaml.Node]*model.LineOverlay),
		useSiteScopes:        make(map[*model.LineOverlay]*yaml.Node),
		snapshots:            make(map[string]*model.SourceSnapshot),
		nodeOrigins:          make(map[*yaml.Node]model.SourcePosition),
		sequenceOrigins:      make(map[sequenceEdge]model.SourcePosition),
	}
}

// TransformDocument transforms one decoded YAML document root in place using
// GitLab CI's layered pipeline compilation model while sharing the file-wide
// include caches across all documents in the file.
func (s *FileState) TransformDocument(root *yaml.Node) {
	if root == nil || root.Kind != yaml.MappingNode || s.ctx.Err() != nil {
		return
	}
	// Positions for temporary resolution nodes belong to this document only.
	s.lineOverlays = make(map[*yaml.Node]*model.LineOverlay)
	s.mergedPositions = make(map[overlayPair]*model.LineOverlay)
	if !reserveGraph(s.ctx, root) {
		return
	}
	yamlnode.BreakAliasCycles(root)
	s.expandAnchors(root)
	if IsSpecHeaderNode(root) {
		s.pendingSpecInputs = extractSpecInputDefaults(root)
		return
	}

	specInputs := s.pendingSpecInputs
	s.pendingSpecInputs = nil

	if len(specInputs) > 0 {
		interpolated := s.interpolateInputs(root, specInputs, nil)
		root.Content = interpolated.Content
	}
	if s.ctx.Err() != nil {
		return
	}

	includedLayers := s.collectLocalIncludes(root)
	if s.ctx.Err() != nil {
		return
	}

	if len(includedLayers) == 0 {
		resolved := s.resolveReferences(root, root, false)
		s.resolveAllExtends(resolved, resolved)
		resolved = s.resolveReferences(resolved, resolved, true)
		s.applyDefaults(resolved)
		resolved = s.flattenLists(resolved)
		if !reserveGraph(s.ctx, resolved) {
			return
		}
		root.Content = resolved.Content
		s.sourceScope = resolved
		return
	}

	includedScope := s.mergeIncludeLayers(includedLayers)
	s.addIncludedDefinitions(root, includedScope)
	s.applyIncludedOverrides(root, includedScope)
	scope := deepMergeMappings(s.ctx, includedScope, root)
	scope = s.reachableScope(root, scope)
	resolvedRoot := s.resolveReferences(root, scope, false)

	scope = s.resolveReferences(scope, scope, false)
	s.resolveAllExtends(scope, scope)
	scope = s.resolveReferences(scope, scope, true)

	s.resolveAllExtends(resolvedRoot, scope)
	resolvedRoot = s.resolveReferences(resolvedRoot, scope, true)
	s.applyDefaults(resolvedRoot)
	resolvedRoot = s.flattenLists(resolvedRoot)
	if !reserveGraph(s.ctx, resolvedRoot) {
		return
	}
	root.Content = resolvedRoot.Content
	s.sourceScope = scope
}

func (s *FileState) mergeIncludeLayers(layers []*yaml.Node) *yaml.Node {
	ctx := s.ctx
	// Only conflicting mapping values need a deep merge. Rebuilding the entire
	// accumulated top level per layer would be quadratic for disjoint includes.
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: yamlnode.MapTag}
	index := make(map[string]int)
	for _, layer := range layers {
		for i := 0; i+1 < len(layer.Content); i += 2 {
			if ctx.Err() != nil {
				return out
			}
			key, value := layer.Content[i], layer.Content[i+1]
			if slot, exists := index[key.Value]; exists {
				previous := out.Content[slot+1]
				if previous.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
					positions := s.mergeMappingSources(previous, value, s.keyOverlays[out.Content[slot]], s.keyOverlays[key])
					key = s.keyWithSource(key, positions)
					value = deepMergeMappings(ctx, previous, value)
				}
				out.Content[slot], out.Content[slot+1] = key, value
			} else {
				if !Reserve(ctx, 1, nodeAllocationBytes+2*pointerAllocationBytes) {
					return out
				}
				index[key.Value] = len(out.Content)
				out.Content = append(out.Content, key, value)
			}
		}
	}
	return out
}

func (s *FileState) applyIncludedOverrides(root, includedScope *yaml.Node) {
	if root == nil || root.Kind != yaml.MappingNode || includedScope == nil {
		return
	}
	index := make(map[string]int, len(includedScope.Content)/2)
	for i := 0; i+1 < len(includedScope.Content); i += 2 {
		index[includedScope.Content[i].Value] = i
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.MappingNode {
			continue
		}
		position, exists := index[k.Value]
		if !exists {
			continue
		}
		incKey, incVal := includedScope.Content[position], includedScope.Content[position+1]
		if incVal.Kind != yaml.MappingNode {
			continue
		}
		positions := s.mergeMappingSources(incVal, v, s.keyOverlays[incKey], s.keyOverlays[k])
		root.Content[i] = s.keyWithSource(k, positions)
		root.Content[i+1] = deepMergeMappings(s.ctx, incVal, v)
	}
}

// reachableScope keeps included jobs lazy: only root definitions and the
// transitive parents/reference targets they use participate in resolution.
// In particular, an unused included template must not be cloned per document.
func (s *FileState) reachableScope(root, scope *yaml.Node) *yaml.Node {
	ctx := s.ctx
	references := s.referenceResolver(scope, false)
	referenceMemo := make(map[*yaml.Node]*yaml.Node)
	index := make(map[string]int, len(scope.Content)/2)
	for i := 0; i+1 < len(scope.Content); i += 2 {
		index[scope.Content[i].Value] = i
	}
	required := make(map[string]bool)
	var pending []*yaml.Node
	add := func(name string) {
		if required[name] {
			return
		}
		if i, ok := index[name]; ok {
			required[name] = true
			pending = append(pending, scope.Content[i+1])
		}
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		add(root.Content[i].Value)
	}
	visited := make(map[*yaml.Node]bool)
	for len(pending) > 0 && ctx.Err() == nil {
		n := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if n == nil || visited[n] {
			continue
		}
		visited[n] = true
		if isReferenceTagNode(n) && len(n.Content) > 0 {
			add(n.Content[0].Value)
		}
		if n.Kind == yaml.MappingNode {
			extends, _, _ := references.walk(yamlnode.MappingValue(n, "extends"), nil, referenceMemo)
			for _, name := range extractExtendsTargets(extends) {
				add(name)
			}
		}
		pending = append(pending, n.Content...)
	}
	out := *scope
	out.Content = make([]*yaml.Node, 0, len(required)*2)
	for i := 0; i+1 < len(scope.Content); i += 2 {
		if required[scope.Content[i].Value] {
			out.Content = append(out.Content, scope.Content[i:i+2]...)
		}
	}
	return &out
}

func (s *FileState) addIncludedDefinitions(root, included *yaml.Node) {
	present := make(map[string]bool, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		present[root.Content[i].Value] = true
	}
	for i := 0; i+1 < len(included.Content); i += 2 {
		key := included.Content[i]
		if present[key.Value] || strings.HasPrefix(key.Value, ".") || key.Value == kwInclude ||
			(!IsReservedTopLevelKeyword(key.Value) && !isJobNode(key.Value, included.Content[i+1]) && !isReferenceTagNode(included.Content[i+1])) {
			continue
		}
		if !Reserve(s.ctx, 0, 2*pointerAllocationBytes) {
			return
		}
		root.Content = append(root.Content, included.Content[i:i+2]...)
	}
}
