/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */
package gitlab

import (
	"path/filepath"
	"sort"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
)

const sourcePositionAllocationBytes = 64

type sequenceEdge struct {
	node  *yaml.Node
	index int
}

type sourceMergePair struct {
	base, own             *yaml.Node
	baseSource, ownSource *model.LineOverlay
}

// Merge source overrides alongside mapping values. Whole-alias defaults stay
// compact; only fields contributed by later layers need exceptions. Natural
// node positions are left to the final document index, after references and
// list normalization have established the effective structure.
func (s *FileState) mergeMappingSources(base, own *yaml.Node, baseSource, ownSource *model.LineOverlay) *model.LineOverlay {
	baseSource = s.mappingSourceMask(base, baseSource)
	ownSource = s.mappingSourceMask(own, ownSource)
	if base == own && baseSource == ownSource {
		return baseSource
	}
	pair := sourceMergePair{base, own, baseSource, ownSource}
	if s.sourceMerges == nil {
		s.sourceMerges = make(map[sourceMergePair]*model.LineOverlay)
	}
	if cached, seen := s.sourceMerges[pair]; seen {
		return cached
	}
	if !Reserve(s.ctx, 1, sourcePositionAllocationBytes) {
		return nil
	}
	s.sourceMerges[pair] = nil
	index := make(map[string]int, len(base.Content)/2)
	for i := 0; i+1 < len(base.Content); i += 2 {
		index[base.Content[i].Value] = i
	}
	out := baseSource
	owned := false
	for i := 0; i+1 < len(own.Content); i += 2 {
		key := own.Content[i]
		child := s.mergedFieldSource(base, own, index, i, baseSource, ownSource)
		if child == nil && !sourceMaskContains(baseSource, key.Value) {
			continue
		}
		if !owned {
			if !Reserve(s.ctx, 1, nodeAllocationBytes+len(own.Content)*sourcePositionAllocationBytes) {
				return nil
			}
			out = &model.LineOverlay{Partial: true}
			copySourceMask(out, baseSource, len(own.Content)/2)
			owned = true
		}
		if child == nil {
			child = &model.LineOverlay{}
		}
		out.Children[key.Value] = child
	}
	s.sourceMerges[pair] = out
	return out
}

func copySourceMask(out, base *model.LineOverlay, capacity int) {
	if base != nil {
		*out = *base
	}
	out.Children = make(map[string]*model.LineOverlay, capacity)
	if base != nil {
		for name, child := range base.Children {
			out.Children[name] = child
		}
	}
}

func (s *FileState) mergedFieldSource(
	base, own *yaml.Node, index map[string]int, slot int, baseSource, ownSource *model.LineOverlay,
) *model.LineOverlay {
	key, value := own.Content[slot], own.Content[slot+1]
	child := s.mappingFieldSource(own, slot, ownSource)
	if previous, exists := index[key.Value]; exists && base.Content[previous+1].Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
		return s.mergeMappingSources(base.Content[previous+1], value, s.mappingFieldSource(base, previous, baseSource), child)
	}
	return child
}

func sourceMaskContains(mask *model.LineOverlay, name string) bool {
	if mask == nil {
		return false
	}
	_, explicit := mask.Children[name]
	return explicit || (mask.Line > 0 && !mask.Partial)
}

func (s *FileState) mappingSourceMask(node *yaml.Node, overlay *model.LineOverlay) *model.LineOverlay {
	provided := s.useSiteScopes[overlay]
	if provided == nil {
		return overlay
	}
	return s.sourceMergePositions().mappingUseSite(node, provided, overlay.Position())
}

func (s *FileState) sourceMergePositions() *positionBuilder {
	if s.mergeSourceBuilder == nil {
		s.mergeSourceBuilder = &positionBuilder{
			state: s, scoped: make(map[scopedPair]*model.LineOverlay),
			leaves: make(map[model.SourcePosition]*model.LineOverlay),
		}
	}
	return s.mergeSourceBuilder
}

func (s *FileState) mappingFieldSource(node *yaml.Node, index int, parent *model.LineOverlay) *model.LineOverlay {
	key, value := node.Content[index], node.Content[index+1]
	field := s.mappingSourceMask(value, s.keyOverlays[key])
	if parent == nil {
		return field
	}
	if child, exists := parent.Children[key.Value]; exists {
		return s.combineLineOverlays(field, child)
	}
	if parent.Line > 0 && !parent.Partial {
		if len(parent.Children) == 0 && len(parent.Ranges) == 0 {
			return parent
		}
		return s.sourceMergePositions().sourceLeaf(parent.Position())
	}
	return field
}

func (s *FileState) keyWithSource(key *yaml.Node, overlay *model.LineOverlay) *yaml.Node {
	if overlay == nil || !Reserve(s.ctx, 1, nodeAllocationBytes) {
		return key
	}
	owned := *key
	s.nodeOrigins[&owned] = s.nodeOrigins[key]
	s.keyOverlays[&owned] = overlay
	return &owned
}

func (s *FileState) sourceSnapshot(path, content string) *model.SourceSnapshot {
	key := filepath.ToSlash(filepath.Clean(path))
	if snapshot := s.snapshots[key]; snapshot != nil {
		return snapshot
	}
	snapshot := &model.SourceSnapshot{Path: path, Content: content}
	snapshot.IgnoreLines = model.GetIgnoreLines(&model.FileMetadata{FilePath: path, OriginalData: content})
	sort.Ints(snapshot.IgnoreLines)
	s.snapshots[key] = snapshot
	return snapshot
}

// RegisterSource associates original YAML nodes with one file/document snapshot.
func (s *FileState) RegisterSource(root *yaml.Node, path, content string, index int) *model.SourceSnapshot {
	snapshot := s.sourceSnapshot(path, content)
	if root != nil && root.Kind == yaml.MappingNode {
		if !Reserve(s.ctx, 0, len(root.Content)/2*pointerAllocationBytes) {
			return snapshot
		}
		starts := make([]int, 0, len(root.Content)/2)
		for i := 0; i+1 < len(root.Content); i += 2 {
			starts = append(starts, root.Content[i].Line)
		}
		snapshot.RecordDeclarations(index, starts)
	}
	pending := []*yaml.Node{root}
	for len(pending) > 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if node == nil {
			continue
		}
		if _, seen := s.nodeOrigins[node]; seen {
			continue
		}
		if !Reserve(s.ctx, 0, sourcePositionAllocationBytes) {
			return snapshot
		}
		s.nodeOrigins[node] = model.SourcePosition{Snapshot: snapshot, DocumentIndex: index, Line: node.Line}
		pending = append(pending, node.Content...)
	}
	return snapshot
}

func (s *FileState) at(node *yaml.Node) model.SourcePosition {
	position := s.nodeOrigins[node]
	if node != nil {
		position.Line = node.Line
	}
	return position
}

func sourceOverlay(position model.SourcePosition) *model.LineOverlay {
	return &model.LineOverlay{Line: position.Line, Snapshot: position.Snapshot, DocumentIndex: position.DocumentIndex}
}

func scopedSourceOverlay(position model.SourcePosition, node *yaml.Node, scopes map[*model.LineOverlay]*yaml.Node) *model.LineOverlay {
	overlay := sourceOverlay(position)
	if node != nil && node.Kind == yaml.MappingNode {
		scopes[overlay] = node
	}
	return overlay
}

func (s *FileState) useSiteOverlay(node *yaml.Node, position model.SourcePosition) *model.LineOverlay {
	if s.useSiteScopes == nil {
		s.useSiteScopes = make(map[*model.LineOverlay]*yaml.Node)
	}
	return scopedSourceOverlay(position, node, s.useSiteScopes)
}

// Sources returns each input file once, shared by every compiled document.
func (s *FileState) Sources() []*model.SourceSnapshot {
	paths := make([]string, 0, len(s.snapshots))
	for path := range s.snapshots {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	out := make([]*model.SourceSnapshot, 0, len(paths))
	for _, path := range paths {
		out = append(out, s.snapshots[path])
	}
	return out
}

func (s *FileState) Dependencies() []string {
	var paths []string
	self := filepath.ToSlash(filepath.Clean(s.self))
	for key, snapshot := range s.snapshots {
		if key != self {
			paths = append(paths, snapshot.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

type positionBuilder struct {
	scoped        map[scopedPair]*model.LineOverlay
	scopeValues   map[*yaml.Node]*yaml.Node
	references    *refResolver
	referenceMemo map[*yaml.Node]*yaml.Node
	state         *FileState
	nodes         map[*yaml.Node]*model.LineOverlay
	leaves        map[model.SourcePosition]*model.LineOverlay
}

func (b *positionBuilder) edge(node *yaml.Node, position model.SourcePosition) *model.LineOverlay {
	raw := b.node(node)
	if len(raw.Children) == 0 && len(raw.Ranges) == 0 && b.state.lineOverlays[node] == nil {
		if leaf := b.leaves[position]; leaf != nil {
			return leaf
		}
		leaf := sourceOverlay(position)
		b.leaves[position] = leaf
		return leaf
	}
	out := *raw
	out.Line = position.Line
	out.Snapshot = position.Snapshot
	out.DocumentIndex = position.DocumentIndex
	return b.state.combineLineOverlays(&out, b.state.lineOverlays[node])
}

func (b *positionBuilder) node(node *yaml.Node) *model.LineOverlay {
	if node == nil {
		return &model.LineOverlay{}
	}
	if cached := b.nodes[node]; cached != nil {
		return cached
	}
	out := &model.LineOverlay{Children: make(map[string]*model.LineOverlay)}
	b.nodes[node] = out
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			child := b.edge(value, b.state.at(key))
			out.Children[key.Value] = b.state.combineLineOverlays(child, b.scopedOverlay(value, b.state.keyOverlays[key]))
		}
	case yaml.SequenceNode:
		for i, value := range node.Content {
			if position, exists := b.state.sequenceOrigins[sequenceEdge{node, i}]; exists {
				out.Ranges = b.state.appendSourceRange(out.Ranges, model.SourceRange{Start: i, End: i + 1, Position: position})
				continue
			}
			out.Children[strconv.Itoa(i)] = b.edge(value, b.state.at(value))
		}
	}
	return out
}

// flattenSourceRanges mirrors list flattening while keeping one interval per
// contributing alias/reference occurrence instead of copying command nodes.
func (s *FileState) flattenSourceRanges(
	sequence *yaml.Node, values map[*yaml.Node]*yaml.Node, memo map[*yaml.Node][]model.SourceRange,
) []model.SourceRange {
	if ranges, seen := memo[sequence]; seen {
		return ranges
	}
	memo[sequence] = nil
	var ranges []model.SourceRange
	offset := 0
	for index, child := range sequence.Content {
		count := 1
		var nested []model.SourceRange
		if child.Kind == yaml.SequenceNode {
			flattened := values[child]
			if flattened == nil {
				flattened = flattenSequenceNode(s.ctx, child, map[*yaml.Node]struct{}{}, values)
			}
			if flattened == nil {
				return nil
			}
			count = len(flattened.Content)
			nested = s.flattenSourceRanges(child, values, memo)
		}
		if position, exists := s.sequenceOrigins[sequenceEdge{sequence, index}]; exists {
			ranges = s.appendSourceRange(ranges, model.SourceRange{Start: offset, End: offset + count, Position: position})
		} else {
			for _, span := range nested {
				span.Start += offset
				span.End += offset
				ranges = s.appendSourceRange(ranges, span)
			}
		}
		offset += count
	}
	memo[sequence] = ranges
	return ranges
}

func (s *FileState) appendSourceRange(ranges []model.SourceRange, span model.SourceRange) []model.SourceRange {
	if span.Start == span.End {
		return ranges
	}
	if len(ranges) > 0 {
		last := &ranges[len(ranges)-1]
		if last.End == span.Start && last.Position == span.Position {
			last.End = span.End
			return ranges
		}
	}
	if !Reserve(s.ctx, 1, sourcePositionAllocationBytes) {
		return ranges
	}
	return append(ranges, span)
}

type scopedPair struct {
	actual, provided *yaml.Node
	position         model.SourcePosition
}

// A mapping use site relocates the fields it supplies. Fields contributed by
// an earlier include or parent keep their own coordinates after a deep merge.
func (b *positionBuilder) scopedOverlay(actual *yaml.Node, overlay *model.LineOverlay) *model.LineOverlay {
	provided := b.state.useSiteScopes[overlay]
	if overlay == nil || provided == nil || actual.Kind != yaml.MappingNode {
		return overlay
	}
	if b.references == nil {
		b.references = b.state.referenceResolver(b.state.sourceScope, false)
		b.referenceMemo = make(map[*yaml.Node]*yaml.Node)
		b.scopeValues = make(map[*yaml.Node]*yaml.Node)
		b.scoped = make(map[scopedPair]*model.LineOverlay)
	}
	if resolved, ok := b.scopeValues[provided]; ok {
		provided = resolved
	} else {
		original := provided
		provided, _, _ = b.references.walk(provided, nil, b.referenceMemo)
		b.scopeValues[original] = provided
	}
	return b.mappingUseSite(actual, provided, overlay.Position())
}
func (b *positionBuilder) mappingUseSite(actual, provided *yaml.Node, position model.SourcePosition) *model.LineOverlay {
	if actual == provided || provided.Kind != yaml.MappingNode || actual.Kind != yaml.MappingNode {
		return b.sourceLeaf(position)
	}
	pair := scopedPair{actual, provided, position}
	if cached := b.scoped[pair]; cached != nil {
		return cached
	}
	if !Reserve(b.state.ctx, 1, nodeAllocationBytes+sourcePositionAllocationBytes*(len(actual.Content)+len(provided.Content))) {
		return nil
	}
	out := sourceOverlay(position)
	out.Partial = true
	out.Children = make(map[string]*model.LineOverlay, len(provided.Content)/2)
	b.scoped[pair] = out
	actualValues := make(map[string]*yaml.Node, len(actual.Content)/2)
	for index := 0; index+1 < len(actual.Content); index += 2 {
		actualValues[actual.Content[index].Value] = actual.Content[index+1]
	}
	for index := 0; index+1 < len(provided.Content); index += 2 {
		key, value := provided.Content[index], provided.Content[index+1]
		if own := actualValues[key.Value]; own != nil {
			out.Children[key.Value] = b.mappingUseSite(own, value, position)
		}
	}
	return out
}

func (b *positionBuilder) sourceLeaf(position model.SourcePosition) *model.LineOverlay {
	if leaf := b.leaves[position]; leaf != nil {
		return leaf
	}
	leaf := sourceOverlay(position)
	b.leaves[position] = leaf
	return leaf
}
