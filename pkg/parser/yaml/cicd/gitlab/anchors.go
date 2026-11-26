/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package gitlab

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

const (
	yamlMergeKey = "<<"
	yamlBoolTag  = "!!bool"
	yamlTrue     = "true"
	yamlFalse    = "false"
)

// expandAnchors expands YAML merge keys (<<: *a, <<: [*a, *b]) and
// resolves direct alias nodes (*a) in mappings and sequences in place.
// Container targets are shared directly in the YAML AST DAG (each unique node
// is expanded once) so stacked anchor reuse stays linear in unique nodes, while
// scalar aliases and merged keys receive O(1) scalar copies stamped with the
// use-site line so findings point at the referencing job rather than the anchor
// definition.
func (s *FileState) expandAnchors(root *yaml.Node) {
	s.expandAliasesAndMerges(root, map[*yaml.Node]struct{}{}, map[*yaml.Node]struct{}{})
	normalizeBooleanValues(root)
}

// Psych resolves these plain scalar values as booleans. Quoted strings and
// explicit string tags retain their type; mapping keys retain their spelling.
func normalizeBooleanValues(root *yaml.Node) {
	seen := make(map[*yaml.Node]bool)
	pending := []*yaml.Node{root}
	for len(pending) > 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if node == nil || seen[node] {
			continue
		}
		seen[node] = true
		switch node.Kind {
		case yaml.MappingNode:
			for i := 1; i < len(node.Content); i += 2 {
				pending = append(pending, node.Content[i])
			}
		case yaml.SequenceNode:
			pending = append(pending, node.Content...)
		case yaml.ScalarNode:
			if node.Tag != yamlBoolTag && (node.Tag != yamlnode.StrTag || node.Style != 0) {
				continue
			}
			switch strings.ToLower(node.Value) {
			case "yes", "on", yamlTrue:
				node.Tag, node.Value = yamlBoolTag, yamlTrue
			case "no", "off", yamlFalse:
				node.Tag, node.Value = yamlBoolTag, yamlFalse
			}
		}
	}
}

func (s *FileState) expandAliasesAndMerges(
	n *yaml.Node,
	inProgress, done map[*yaml.Node]struct{},
) {
	ctx := s.ctx
	if n == nil || ctx.Err() != nil {
		return
	}
	if _, ok := done[n]; ok {
		return
	}
	if _, gray := inProgress[n]; gray {
		return
	}
	inProgress[n] = struct{}{}
	defer func() {
		delete(inProgress, n)
		done[n] = struct{}{}
	}()

	switch n.Kind {
	case yaml.MappingNode:
		s.expandMappingAliasesAndMerges(n, inProgress, done)
	case yaml.SequenceNode:
		for i, child := range n.Content {
			if ctx.Err() != nil {
				return
			}
			if child == nil {
				continue
			}
			if child.Kind == yaml.AliasNode {
				if target := yamlnode.ResolveAlias(child); target != nil && target.Kind != yaml.ScalarNode {
					s.sequenceOrigins[sequenceEdge{n, i}] = s.at(child)
				}
				n.Content[i] = s.resolveAndExpandAlias(child, inProgress, done)
				continue
			}
			s.expandAliasesAndMerges(child, inProgress, done)
		}
	}
}

func (s *FileState) resolveAndExpandAlias(
	alias *yaml.Node,
	inProgress, done map[*yaml.Node]struct{},
) *yaml.Node {
	target := yamlnode.ResolveAlias(alias)
	if target == nil {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlnode.NullTag, Line: alias.Line}
	}
	if _, gray := inProgress[target]; gray {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlnode.NullTag, Line: alias.Line}
	}
	if target.Kind == yaml.ScalarNode {
		out := cloneScalarAtLine(target, alias.Line)
		s.nodeOrigins[out] = s.at(alias)
		return out
	}
	s.expandAliasesAndMerges(target, inProgress, done)
	return target
}

func cloneScalarAtLine(src *yaml.Node, line int) *yaml.Node {
	return &yaml.Node{
		Kind:  src.Kind,
		Style: src.Style,
		Tag:   src.Tag,
		Value: src.Value,
		Line:  line,
	}
}

func isYAMLMergeKey(key *yaml.Node) bool {
	return key.Kind == yaml.ScalarNode && key.Value == yamlMergeKey && key.Tag != yamlnode.StrTag
}

func (s *FileState) expandMappingAliasesAndMerges(
	m *yaml.Node,
	inProgress, done map[*yaml.Node]struct{},
) {
	ctx := s.ctx
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	explicit := make(map[string]bool, len(m.Content)/2)
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.AliasNode {
			k = s.resolveAndExpandAlias(k, inProgress, done)
			m.Content[i] = k
		}
		if k.Kind == yaml.ScalarNode && !isYAMLMergeKey(k) {
			explicit[k.Value] = true
		}
	}

	out := make([]*yaml.Node, 0, len(m.Content))
	mergedSeen := make(map[string]bool)
	seenMerge := make(map[*yaml.Node]struct{})
	for i := 0; i+1 < len(m.Content); i += 2 {
		if ctx.Err() != nil {
			return
		}
		k, v := m.Content[i], m.Content[i+1]
		if isYAMLMergeKey(k) {
			s.appendMergedEntries(v, s.at(k), explicit, mergedSeen, seenMerge, &out, inProgress, done)
			continue
		}
		if v != nil && v.Kind == yaml.AliasNode {
			if target := yamlnode.ResolveAlias(v); target != nil && (target.Kind != yaml.ScalarNode || v.Line != k.Line) {
				s.keyOverlays[k] = s.useSiteOverlay(target, s.at(v))
			}
			v = s.resolveAndExpandAlias(v, inProgress, done)
		} else {
			s.expandAliasesAndMerges(v, inProgress, done)
		}
		out = append(out, k, v)
	}
	m.Content = out
}

func (s *FileState) appendMergedEntries(
	mergeVal *yaml.Node,
	mergeSite model.SourcePosition,
	explicit map[string]bool,
	mergedSeen map[string]bool,
	seenMerge map[*yaml.Node]struct{},
	out *[]*yaml.Node,
	inProgress, done map[*yaml.Node]struct{},
) {
	ctx := s.ctx
	if mergeVal == nil || ctx.Err() != nil {
		return
	}
	switch mergeVal.Kind {
	case yaml.AliasNode:
		if target := yamlnode.ResolveAlias(mergeVal); target != nil {
			s.appendMergedEntries(target, mergeSite, explicit, mergedSeen, seenMerge, out, inProgress, done)
		}
	case yaml.MappingNode:
		s.appendMergedMapping(mergeVal, mergeSite, explicit, mergedSeen, seenMerge, out, inProgress, done)
	case yaml.SequenceNode:
		if _, visited := seenMerge[mergeVal]; visited {
			return
		}
		seenMerge[mergeVal] = struct{}{}
		for _, item := range mergeVal.Content {
			if ctx.Err() != nil {
				return
			}
			s.appendMergedEntries(item, mergeSite, explicit, mergedSeen, seenMerge, out, inProgress, done)
		}
	}
}

func (s *FileState) appendMergedMapping(
	mergeVal *yaml.Node,
	mergeSite model.SourcePosition,
	explicit, mergedSeen map[string]bool,
	seenMerge map[*yaml.Node]struct{},
	out *[]*yaml.Node,
	inProgress, done map[*yaml.Node]struct{},
) {
	ctx := s.ctx
	if _, gray := inProgress[mergeVal]; gray {
		return
	}
	if _, visited := seenMerge[mergeVal]; visited {
		return
	}
	seenMerge[mergeVal] = struct{}{}
	s.expandAliasesAndMerges(mergeVal, inProgress, done)
	for i := 0; i+1 < len(mergeVal.Content); i += 2 {
		ck, cv := mergeVal.Content[i], mergeVal.Content[i+1]
		if ck.Kind != yaml.ScalarNode || explicit[ck.Value] || mergedSeen[ck.Value] {
			continue
		}
		if !Reserve(ctx, 2, 2*nodeAllocationBytes) {
			return
		}
		mergedSeen[ck.Value] = true
		if mergeSite.Line > 0 {
			ck = cloneScalarAtLine(ck, mergeSite.Line)
			s.nodeOrigins[ck] = mergeSite
			s.keyOverlays[ck] = s.useSiteOverlay(cv, mergeSite)
			if cv != nil && cv.Kind == yaml.ScalarNode {
				cv = cloneScalarAtLine(cv, mergeSite.Line)
				s.nodeOrigins[cv] = mergeSite
			}
		}
		*out = append(*out, ck, cv)
	}
}
