/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package gitlab

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

type refResolver struct {
	scopes             map[*model.LineOverlay]*yaml.Node
	ctx                context.Context
	scope              *yaml.Node
	finalizeUnresolved bool
	cachedNoRef        map[*yaml.Node]bool
	localNoRef         map[*yaml.Node]bool
	resolvedRefs       map[string]*yaml.Node
	keyOverlays        map[*yaml.Node]*model.LineOverlay
	origins            map[*yaml.Node]model.SourcePosition
	edges              map[sequenceEdge]model.SourcePosition
}

// markSubtreeNoRef records every node in root whose subtree contains no
// `!reference` tag. Only called on reusable cached include documents so
// temporary per-document scopes are never pinned in FileState.
func markSubtreeNoRef(root *yaml.Node, noRef map[*yaml.Node]bool) {
	visited := make(map[*yaml.Node]bool)
	var walk func(n *yaml.Node) bool
	walk = func(n *yaml.Node) bool {
		if n == nil {
			return false
		}
		if has, seen := visited[n]; seen {
			return has
		}
		visited[n] = false
		has := isReferenceTagNode(n)
		if !has && (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) {
			for _, child := range n.Content {
				if walk(child) {
					has = true
				}
			}
		}
		visited[n] = has
		if !has {
			noRef[n] = true
		}
		return has
	}
	walk(root)
}

// resolveReferences resolves GitLab CI `!reference [k0, k1, ...]` tags across
// target using scope for lookups. Sequence-valued references inside a sequence
// are kept as shared SequenceNode children during resolution (preserving DAG
// structure against doubling `!reference` bombs) and flattened in flattenLists.
// The walk is copy-on-write and uses a per-call localNoRef map alongside the
// read-only cachedNoRefNodes from cached includes, so temporary scope nodes are
// released after each document.
func (s *FileState) resolveReferences(target, scope *yaml.Node, finalizeUnresolved bool) *yaml.Node {
	r := s.referenceResolver(scope, finalizeUnresolved)
	out, _, _ := r.walk(target, nil, make(map[*yaml.Node]*yaml.Node))
	return out
}

func (s *FileState) referenceResolver(scope *yaml.Node, finalizeUnresolved bool) *refResolver {
	return &refResolver{
		ctx:                s.ctx,
		scope:              scope,
		finalizeUnresolved: finalizeUnresolved,
		cachedNoRef:        s.cachedNoRefNodes,
		localNoRef:         make(map[*yaml.Node]bool),
		resolvedRefs:       make(map[string]*yaml.Node),
		keyOverlays:        s.keyOverlays,
		scopes:             s.useSiteScopes,
		origins:            s.nodeOrigins, edges: s.sequenceOrigins,
	}
}

func (r *refResolver) hasNoRef(n *yaml.Node) bool {
	return r.cachedNoRef[n] || r.localNoRef[n]
}

func (r *refResolver) walk(
	node *yaml.Node,
	active map[string]bool,
	memo map[*yaml.Node]*yaml.Node,
) (out *yaml.Node, changed, hitCycle bool) {
	if node == nil || r.ctx.Err() != nil {
		return node, false, false
	}
	if r.hasNoRef(node) {
		return node, false, false
	}
	if memo != nil {
		if cached, ok := memo[node]; ok {
			return cached, cached != node, false
		}
	}
	if isReferenceTagNode(node) {
		return r.resolveSingle(node, active)
	}

	switch node.Kind {
	case yaml.MappingNode:
		return r.walkMapping(node, active, memo)
	case yaml.SequenceNode:
		return r.walkSequence(node, active, memo)
	default:
		r.localNoRef[node] = true
		return node, false, false
	}
}

func (r *refResolver) walkMapping(
	node *yaml.Node,
	active map[string]bool,
	memo map[*yaml.Node]*yaml.Node,
) (out *yaml.Node, changed, hitCycle bool) {
	var newContent []*yaml.Node
	anyRef := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		if r.ctx.Err() != nil {
			return node, false, false
		}
		val := node.Content[i+1]
		newVal, ch, cyc := r.walk(val, active, memo)
		if !r.hasNoRef(val) {
			anyRef = true
		}
		hitCycle = hitCycle || cyc
		if ch {
			if newContent == nil {
				if !Reserve(r.ctx, 1, len(node.Content)*pointerAllocationBytes) {
					return node, false, false
				}
				newContent = make([]*yaml.Node, len(node.Content))
				copy(newContent, node.Content)
			}
			newContent[i] = r.referenceKey(node.Content[i], val, newVal)
			newContent[i+1] = newVal
		}
	}
	if !anyRef {
		r.localNoRef[node] = true
		return node, false, false
	}
	res := node
	if newContent != nil {
		cp := *node
		cp.Content = newContent
		res = &cp
		r.origins[res] = r.origins[node]
	}
	if memo != nil && !hitCycle {
		memo[node] = res
	}
	return res, newContent != nil, hitCycle
}

func (r *refResolver) referenceKey(key, original, resolved *yaml.Node) *yaml.Node {
	site, ok := r.wholeReferencePosition(original)
	if !ok || isReferenceTagNode(resolved) || r.keyOverlays[key] != nil {
		return key
	}
	if !Reserve(r.ctx, 1, nodeAllocationBytes) {
		return key
	}
	owned := *key
	r.origins[&owned] = r.origins[key]
	r.keyOverlays[&owned] = scopedSourceOverlay(site, resolved, r.scopes)
	return &owned
}

func (r *refResolver) walkSequence(
	node *yaml.Node,
	active map[string]bool,
	memo map[*yaml.Node]*yaml.Node,
) (out *yaml.Node, changed, hitCycle bool) {
	var items []*yaml.Node
	anyRef := false
	for idx, elem := range node.Content {
		if r.ctx.Err() != nil {
			return node, false, false
		}
		newElem, ch, cyc := r.walk(elem, active, memo)
		if !r.hasNoRef(elem) {
			anyRef = true
		}
		hitCycle = hitCycle || cyc
		if ch {
			if items == nil {
				if !Reserve(r.ctx, 1, len(node.Content)*pointerAllocationBytes) {
					return node, false, false
				}
				items = make([]*yaml.Node, len(node.Content))
				copy(items, node.Content)
			}
			items[idx] = newElem
		}
	}
	if !anyRef {
		r.localNoRef[node] = true
		return node, false, false
	}
	res := node
	if items != nil {
		cp := *node
		cp.Content = items
		res = &cp
		r.origins[res] = r.origins[node]
	}
	for index, old := range node.Content {
		if position, exists := r.sequencePosition(node, index, old); exists {
			r.edges[sequenceEdge{res, index}] = position
		}
	}
	if memo != nil && !hitCycle {
		memo[node] = res
	}
	return res, items != nil, hitCycle
}

func (r *refResolver) sequencePosition(sequence *yaml.Node, index int, value *yaml.Node) (model.SourcePosition, bool) {
	if position, exists := r.edges[sequenceEdge{sequence, index}]; exists {
		return position, true
	}
	return r.origins[value], isReferenceTagNode(value)
}

func isReferenceTagNode(n *yaml.Node) bool {
	return n != nil && n.Tag == gitlabReferenceTag
}

func (r *refResolver) resolveSingle(
	refNode *yaml.Node,
	active map[string]bool,
) (out *yaml.Node, changed, hitCycle bool) {
	if len(active) > maxGraphDepth {
		ExceedLimit(r.ctx, "reference nesting depth")
		return refNode, false, false
	}
	selector, ok := parseReferenceArgs(refNode)
	if !ok {
		return finalizeOrKeepRef(refNode, r.finalizeUnresolved), r.finalizeUnresolved, false
	}
	refID := strings.Join(selector, "\x00")
	if active[refID] {
		return finalizeOrKeepRef(refNode, r.finalizeUnresolved), r.finalizeUnresolved, true
	}
	if cached, ok := r.resolvedRefs[refID]; ok {
		return r.finalizeResolvedRef(cached, refNode), true, false
	}

	nextActive := copyBoolMap(active)
	nextActive[refID] = true
	sourceVal, lookupCycle := r.lookupByPath(selector, nextActive)
	if sourceVal == nil {
		return finalizeOrKeepRef(refNode, r.finalizeUnresolved), r.finalizeUnresolved, lookupCycle
	}

	resolved, _, cyc := r.walk(sourceVal, nextActive, make(map[*yaml.Node]*yaml.Node))
	if !cyc && r.ctx.Err() == nil {
		r.resolvedRefs[refID] = resolved
	}
	return r.finalizeResolvedRef(resolved, refNode), true, cyc
}

func (r *refResolver) wholeReferencePosition(node *yaml.Node) (model.SourcePosition, bool) {
	var useSite model.SourcePosition
	for node != nil && node.Kind == yaml.SequenceNode && !isReferenceTagNode(node) && len(node.Content) == 1 {
		if position, exists := r.edges[sequenceEdge{node, 0}]; exists && useSite.Line == 0 {
			useSite = position
		}
		node = node.Content[0]
	}
	if isReferenceTagNode(node) {
		if useSite.Line > 0 {
			return useSite, true
		}
		return r.origins[node], true
	}
	return model.SourcePosition{}, false
}

// Container reference values are immutable shared nodes; their mapping keys
// carry use-site positions separately from the semantic graph.
func (r *refResolver) finalizeResolvedRef(resolved, site *yaml.Node) *yaml.Node {
	if resolved != nil && resolved.Kind == yaml.ScalarNode {
		out := cloneScalarAtLine(resolved, site.Line)
		r.origins[out] = r.origins[site]
		return out
	}
	return resolved
}

func finalizeOrKeepRef(refNode *yaml.Node, finalize bool) *yaml.Node {
	if finalize {
		return unresolvedReferenceMapping(refNode)
	}
	return refNode
}

func parseReferenceArgs(refNode *yaml.Node) ([]string, bool) {
	if refNode == nil || refNode.Kind != yaml.SequenceNode || len(refNode.Content) < 1 {
		return nil, false
	}
	path := make([]string, 0, len(refNode.Content))
	for _, elem := range refNode.Content {
		if elem.Kind != yaml.ScalarNode || elem.Value == "" {
			return nil, false
		}
		path = append(path, elem.Value)
	}
	return path, true
}

func (r *refResolver) lookupByPath(path []string, active map[string]bool) (*yaml.Node, bool) {
	current := r.scope
	for _, key := range path {
		if isReferenceTagNode(current) {
			resolved, _, cycle := r.resolveSingle(current, active)
			if cycle {
				return nil, true
			}
			current = resolved
		}
		if current == nil || current.Kind != yaml.MappingNode {
			return nil, false
		}
		current = yamlnode.MappingValue(current, key)
	}
	return current, false
}

func unresolvedReferenceMapping(refNode *yaml.Node) *yaml.Node {
	seq := &yaml.Node{
		Kind: yaml.SequenceNode,
		Tag:  yamlnode.SeqTag,
		Line: refNode.Line,
	}
	for _, child := range refNode.Content {
		if child.Kind == yaml.ScalarNode {
			seq.Content = append(seq.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   yamlnode.StrTag,
				Value: child.Value,
				Line:  refNode.Line,
			})
		}
	}
	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  yamlnode.MapTag,
		Line: refNode.Line,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: yamlnode.StrTag, Value: gitlabReferenceTag, Line: refNode.Line},
			seq,
		},
	}
}

// resolveAllExtends resolves GitLab CI `extends:` inheritance on every
// top-level job mapping in target, looking parent definitions up in scope.
// Resolves transitive parents with cycle checks and the file-wide safety allowance.
func (s *FileState) resolveAllExtends(target, scope *yaml.Node) {
	ctx := s.ctx
	if target == nil || target.Kind != yaml.MappingNode {
		return
	}
	index := make(map[string]*yaml.Node, len(scope.Content)/2)
	for i := 0; i+1 < len(scope.Content); i += 2 {
		index[scope.Content[i].Value] = scope.Content[i+1]
	}
	resolvedCache := make(map[string]*yaml.Node)
	for i := 0; i+1 < len(target.Content); i += 2 {
		if ctx.Err() != nil {
			return
		}
		keyNode := target.Content[i]
		valNode := target.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode || valNode.Kind != yaml.MappingNode {
			continue
		}
		if IsReservedTopLevelKeyword(keyNode.Value) {
			continue
		}
		if yamlnode.MappingValue(valNode, "extends") == nil {
			continue
		}
		if !Reserve(ctx, 1, nodeAllocationBytes) {
			return
		}
		owned := *valNode
		s.nodeOrigins[&owned] = s.nodeOrigins[valNode]
		s.lineOverlays[&owned] = s.combineLineOverlays(s.lineOverlays[valNode], s.keyOverlays[keyNode])
		merged, _ := s.resolveJobExtends(index, keyNode.Value, &owned, map[string]bool{keyNode.Value: true}, resolvedCache)
		if merged != nil {
			target.Content[i+1] = merged
			target.Content[i] = s.keyWithSource(keyNode, s.lineOverlays[merged])
		}
	}
}

func (s *FileState) resolveJobExtends(
	scope map[string]*yaml.Node,
	jobName string,
	jobNode *yaml.Node,
	active map[string]bool,
	cache map[string]*yaml.Node,
) (*yaml.Node, bool) {
	ctx, overlays, origins := s.ctx, s.lineOverlays, s.nodeOrigins
	if len(active) > maxGraphDepth {
		ExceedLimit(ctx, "inheritance nesting depth")
	}
	if ctx.Err() != nil {
		return jobNode, false
	}
	if cached, ok := cache[jobName]; ok {
		return cached, false
	}
	extendsKey, extendsVal := yamlnode.MappingEntry(jobNode, "extends")
	if extendsVal == nil {
		return jobNode, false
	}

	parents := extractExtendsTargets(extendsVal)
	if len(parents) == 0 {
		return jobNode, false
	}

	acc, hitCycle := s.mergeExtendsParents(scope, parents, active, cache)
	if acc == nil {
		return jobNode, hitCycle
	}

	site := origins[extendsKey]
	site.Line = extendsKey.Line
	if inherited := overlays[jobNode].LookupSource([]string{"extends"}); inherited.Line > 0 {
		site = inherited
	}
	result := deepMergeMappings(ctx, acc, jobNode)
	origins[result] = origins[jobNode]
	overlay := s.inheritedLineOverlay(acc, jobNode, site, make(map[mergePair]*model.LineOverlay))
	overlays[result] = s.combineLineOverlays(overlays[jobNode], overlay)

	if !hitCycle && ctx.Err() == nil {
		cache[jobName] = result
	}
	return result, hitCycle
}

func (s *FileState) mergeExtendsParents(
	scope map[string]*yaml.Node,
	parents []string,
	active map[string]bool,
	cache map[string]*yaml.Node,
) (*yaml.Node, bool) {
	ctx, origins := s.ctx, s.nodeOrigins
	var acc *yaml.Node
	hitCycle := false
	for _, parentName := range parents {
		if ctx.Err() != nil {
			return acc, hitCycle
		}
		if active[parentName] {
			hitCycle = true
			continue
		}
		parentNode := scope[parentName]
		if parentNode == nil || parentNode.Kind != yaml.MappingNode {
			continue
		}
		nextActive := copyBoolMap(active)
		nextActive[parentName] = true
		resolvedParent, subCyc := s.resolveJobExtends(scope, parentName, parentNode, nextActive, cache)
		hitCycle = hitCycle || subCyc
		if !Reserve(ctx, 1, nodeAllocationBytes+len(resolvedParent.Content)*pointerAllocationBytes) {
			return acc, hitCycle
		}
		parentCopy := *resolvedParent
		parentCopy.Content = append([]*yaml.Node(nil), resolvedParent.Content...)
		origins[&parentCopy] = origins[resolvedParent]
		yamlnode.RemoveMappingKey(&parentCopy, "extends")
		if acc == nil {
			acc = &parentCopy
		} else {
			acc = deepMergeMappings(ctx, acc, &parentCopy)
		}
	}
	return acc, hitCycle
}

func extractExtendsTargets(n *yaml.Node) []string {
	if n == nil || isReferenceTagNode(n) {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value != "" {
			return []string{n.Value}
		}
	case yaml.SequenceNode:
		out := make([]string, 0, len(n.Content))
		for _, item := range n.Content {
			if item.Kind == yaml.ScalarNode && item.Value != "" {
				out = append(out, item.Value)
			}
		}
		return out
	}
	return nil
}

// MaxFlattenedListEntries bounds materialization of one list field. A compact
// shared graph can represent exponentially many logical occurrences, which must
// either all be preserved or rejected explicitly. The file-wide allowance also
// accounts for cumulative materialization across fields and documents.
const MaxFlattenedListEntries = 100_000

type listContext uint8

const (
	rootLists listContext = iota
	defaultLists
	workflowLists
	hookLists
	jobLists
)

type normalizedMapping struct {
	node *yaml.Node
	kind listContext
}

type listNormalizer struct {
	state     *FileState
	values    map[*yaml.Node]*yaml.Node
	positions map[*yaml.Node][]model.SourceRange
	mappings  map[normalizedMapping]*yaml.Node
}

// Included mappings and aliases may also occur as literal input data. Own
// only the containers we normalize, preserving the immutable list DAG.
func (n *listNormalizer) mapping(node *yaml.Node, kind listContext) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return node
	}
	key := normalizedMapping{node, kind}
	if cached := n.mappings[key]; cached != nil {
		return cached
	}
	if !Reserve(n.state.ctx, 1, nodeAllocationBytes+len(node.Content)*pointerAllocationBytes) {
		return node
	}
	owned := *node
	owned.Content = append([]*yaml.Node(nil), node.Content...)
	n.mappings[key] = &owned
	n.state.nodeOrigins[&owned] = n.state.nodeOrigins[node]
	var keys []string
	switch kind {
	case rootLists:
		keys = []string{kwBeforeScript, kwAfterScript, "stages"}
	case defaultLists:
		keys = []string{kwBeforeScript, kwAfterScript}
	case workflowLists:
		keys = []string{"rules"}
	case hookLists:
		keys = []string{"pre_get_sources_script"}
	case jobLists:
		keys = []string{"script", kwBeforeScript, kwAfterScript, "needs", "rules"}
	}
	n.state.flattenListKeysInMapping(&owned, n.values, n.positions, keys...)
	if kind == jobLists || kind == defaultLists {
		if index := yamlnode.MappingKeyIndex(&owned, kwHooks); index >= 0 {
			owned.Content[index+1] = n.mapping(owned.Content[index+1], hookLists)
		}
	}
	return &owned
}

// flattenLists flattens nested YAML sequences inside GitLab CI list fields
// that accept nested arrays via anchors, !reference, or array input
// substitution: stages, script, before_script, after_script,
// hooks.pre_get_sources_script, needs, and rules.
//
// Each nested sequence node is flattened once and memoized so repeated
// references to a command group (flat or nested) preserve every occurrence in
// execution order up to MaxFlattenedListEntries while cyclic or exponential
// sequence graphs cannot exhaust memory.
func (s *FileState) flattenLists(root *yaml.Node) *yaml.Node {
	ctx := s.ctx
	if root == nil || root.Kind != yaml.MappingNode || ctx.Err() != nil {
		return root
	}
	normalizer := listNormalizer{
		state: s, values: make(map[*yaml.Node]*yaml.Node),
		positions: make(map[*yaml.Node][]model.SourceRange), mappings: make(map[normalizedMapping]*yaml.Node),
	}
	root = normalizer.mapping(root, rootLists)
	for i := 0; i+1 < len(root.Content); i += 2 {
		if ctx.Err() != nil {
			return root
		}
		k, v := root.Content[i], root.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.MappingNode {
			continue
		}
		kind := jobLists
		switch k.Value {
		case kwDefault:
			kind = defaultLists
		case kwWorkflow:
			kind = workflowLists
		default:
			if IsReservedTopLevelKeyword(k.Value) {
				continue
			}
		}
		root.Content[i+1] = normalizer.mapping(v, kind)
	}
	return root
}

func (s *FileState) flattenListKeysInMapping(
	m *yaml.Node, memo map[*yaml.Node]*yaml.Node, positions map[*yaml.Node][]model.SourceRange, keys ...string,
) {
	for _, key := range keys {
		index := yamlnode.MappingKeyIndex(m, key)
		if index < 0 {
			continue
		}
		value := m.Content[index+1]
		if value == nil || value.Kind != yaml.SequenceNode {
			continue
		}
		flat, seen := memo[value]
		if !seen {
			if hasNestedSequence(value.Content) {
				flat = flattenSequenceNode(s.ctx, value, map[*yaml.Node]struct{}{}, memo)
			} else {
				flat = value
				memo[value] = flat
			}
		}
		if flat == nil {
			ExceedLimit(s.ctx, "flattened list entries")
			return
		}
		ranges := s.flattenSourceRanges(value, memo, positions)
		if len(ranges) > 0 {
			if !Reserve(s.ctx, 1, nodeAllocationBytes) {
				return
			}
			field := m.Content[index]
			useSite := *field
			s.nodeOrigins[&useSite] = s.nodeOrigins[field]
			s.keyOverlays[&useSite] = s.combineLineOverlays(&model.LineOverlay{Ranges: ranges}, s.keyOverlays[field])
			m.Content[index] = &useSite
		}
		if _, known := s.nodeOrigins[flat]; !known {
			s.nodeOrigins[flat] = s.nodeOrigins[value]
		}
		m.Content[index+1] = flat
	}
}

func hasNestedSequence(items []*yaml.Node) bool {
	for _, item := range items {
		if item != nil && item.Kind == yaml.SequenceNode {
			return true
		}
	}
	return false
}

// A memoized nil records failure; a non-nil sequence (including an empty one)
// is a complete result. Shared groups therefore need no duplicate result state.
func flattenSequenceNode(
	ctx context.Context, seq *yaml.Node,
	inProgress map[*yaml.Node]struct{}, memo map[*yaml.Node]*yaml.Node,
) *yaml.Node {
	if seq == nil || ctx.Err() != nil {
		return nil
	}
	if cached, seen := memo[seq]; seen {
		return cached
	}
	if _, gray := inProgress[seq]; gray {
		return &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlnode.SeqTag, Line: seq.Line}
	}
	if len(seq.Content) > MaxFlattenedListEntries {
		memo[seq] = nil
		return nil
	}
	inProgress[seq] = struct{}{}
	defer delete(inProgress, seq)
	if len(seq.Content) == 1 && seq.Content[0] != nil && seq.Content[0].Kind == yaml.SequenceNode {
		node := flattenSequenceNode(ctx, seq.Content[0], inProgress, memo)
		memo[seq] = node
		return node
	}
	items, ok := flattenSequenceItems(ctx, seq.Content, inProgress, memo)
	if !ok {
		memo[seq] = nil
		return nil
	}
	result := &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlnode.SeqTag, Line: seq.Line, Content: items}
	memo[seq] = result
	return result
}

func flattenSequenceItems(
	ctx context.Context, items []*yaml.Node,
	inProgress map[*yaml.Node]struct{}, memo map[*yaml.Node]*yaml.Node,
) ([]*yaml.Node, bool) {
	var out []*yaml.Node
	for _, item := range items {
		if ctx.Err() != nil {
			return nil, false
		}
		next := []*yaml.Node{item}
		if item != nil && item.Kind == yaml.SequenceNode {
			flattened := flattenSequenceNode(ctx, item, inProgress, memo)
			if flattened == nil {
				return nil, false
			}
			next = flattened.Content
		}
		if len(next) > MaxFlattenedListEntries-len(out) {
			return nil, false
		}
		if !Reserve(ctx, len(next), len(next)*pointerAllocationBytes) {
			return nil, false
		}
		out = append(out, next...)
	}
	return out, true
}

func copyBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *FileState) inheritedLineOverlay(
	base, own *yaml.Node, site model.SourcePosition, memo map[mergePair]*model.LineOverlay,
) *model.LineOverlay {
	pair := mergePair{base, own}
	if cached := memo[pair]; cached != nil {
		return cached
	}
	if !Reserve(s.ctx, 1, nodeAllocationBytes+len(own.Content)*sourcePositionAllocationBytes) {
		return nil
	}
	out := sourceOverlay(site)
	out.Children = make(map[string]*model.LineOverlay)
	memo[pair] = out
	index := make(map[string]*yaml.Node, len(base.Content)/2)
	for i := 0; i+1 < len(base.Content); i += 2 {
		index[base.Content[i].Value] = base.Content[i+1]
	}
	for i := 0; i+1 < len(own.Content); i += 2 {
		key, value := own.Content[i], own.Content[i+1]
		previous := index[key.Value]
		child := &model.LineOverlay{}
		if previous != nil && previous.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
			child = s.inheritedLineOverlay(previous, value, site, memo)
		}
		out.Children[key.Value] = child
	}
	return out
}

// LineOverlay returns the compiled document's immutable per-field source tree.
func (s *FileState) LineOverlay(root *yaml.Node) *model.LineOverlay {
	builder := positionBuilder{
		state: s, nodes: make(map[*yaml.Node]*model.LineOverlay),
		leaves: make(map[model.SourcePosition]*model.LineOverlay),
	}
	return builder.edge(root, s.at(root))
}

type overlayPair struct{ base, own *model.LineOverlay }

func (s *FileState) combineLineOverlays(base, own *model.LineOverlay) *model.LineOverlay {
	if own == nil {
		return base
	}
	if base == nil {
		return own
	}
	if own.Line == 0 && len(own.Children) == 0 && len(own.Ranges) == 0 && !own.InheritedDefault {
		return base
	}
	pair := overlayPair{base, own}
	if previous := s.mergedPositions[pair]; previous != nil {
		return previous
	}
	children := len(own.Children)
	if (own.Line == 0 || own.Partial) && children > 0 {
		children += len(base.Children)
	}
	if !Reserve(s.ctx, 1, nodeAllocationBytes+sourcePositionAllocationBytes*(children+1)) {
		return base
	}
	if s.mergedPositions == nil {
		s.mergedPositions = make(map[overlayPair]*model.LineOverlay)
	}
	if len(own.Children) == 0 {
		out := combineDefaultPosition(base, own)
		s.mergedPositions[pair] = out
		return out
	}
	return s.mergeOverlayChildren(base, own, pair, children)
}

func (s *FileState) mergeOverlayChildren(base, own *model.LineOverlay, pair overlayPair, capacity int) *model.LineOverlay {
	out := *own
	out.InheritedDefault = base.InheritedDefault || own.InheritedDefault
	out.Children = make(map[string]*model.LineOverlay, capacity)
	s.mergedPositions[pair] = &out
	if own.Line == 0 || own.Partial {
		if own.Line == 0 {
			out.Line = base.Line
			out.Snapshot = base.Snapshot
			out.DocumentIndex = base.DocumentIndex
		}
		out.Ranges = base.Ranges
		for key, child := range base.Children {
			out.Children[key] = child
		}
	} else if own.Snapshot == nil {
		out.Snapshot = base.Snapshot
		out.DocumentIndex = base.DocumentIndex
	}
	if len(own.Ranges) > 0 {
		out.Ranges = own.Ranges
	}
	var fallback *model.LineOverlay
	for key, child := range own.Children {
		previous := base.Children[key]
		if previous == nil {
			if fallback == nil {
				fallback = sourceOverlay(base.Position())
			}
			previous = fallback
		}
		out.Children[key] = s.combineLineOverlays(previous, child)
	}
	return &out
}

// A whole-field use site overrides its descendants; a range-only overlay keeps
// the shared child tree. Neither case needs to copy a potentially large map.
func combineDefaultPosition(base, own *model.LineOverlay) *model.LineOverlay {
	if own.Line == 0 || own.Partial {
		out := *base
		out.InheritedDefault = base.InheritedDefault || own.InheritedDefault
		if own.Partial {
			out.Line = own.Line
			out.Snapshot = own.Snapshot
			out.DocumentIndex = own.DocumentIndex
		}
		if len(own.Ranges) > 0 {
			out.Ranges = own.Ranges
		}
		return &out
	}
	out := *own
	out.InheritedDefault = base.InheritedDefault || own.InheritedDefault
	if out.Snapshot == nil {
		out.Snapshot = base.Snapshot
		out.DocumentIndex = base.DocumentIndex
	}
	return &out
}
