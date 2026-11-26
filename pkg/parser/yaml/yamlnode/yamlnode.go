/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package yamlnode provides shared yaml.v3 AST helpers used by YAML platform
// parsers (such as Docker Compose and GitLab CI): cycle breaking, memoized
// copying, mapping lookups/edits, structural equality, and deep merging.
package yamlnode

import "gopkg.in/yaml.v3"

const (
	NullTag = "!!null"
	StrTag  = "!!str"
	SeqTag  = "!!seq"
	MapTag  = "!!map"
)

// IsEmptyDocument reports whether a decoded YAML document holds nothing
// (an empty or comment-only document).
func IsEmptyDocument(doc *yaml.Node) bool {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0] == nil {
		return true
	}
	n := doc.Content[0]
	return n.Kind == yaml.ScalarNode && (n.Value == "" || n.Tag == NullTag)
}

// IsImplicitEmptyDocument excludes explicit nulls and quoted empty scalars.
// Compilers that require mapping roots must validate those written values.
func IsImplicitEmptyDocument(doc *yaml.Node) bool {
	if doc == nil || len(doc.Content) == 0 || doc.Content[0] == nil {
		return true
	}
	n := doc.Content[0]
	return n.Kind == yaml.ScalarNode && n.Tag == NullTag && n.Value == "" && n.Style == 0
}

// ResolveAlias follows AliasNode pointers until reaching a non-alias node,
// returning nil if a cycle is encountered.
func ResolveAlias(n *yaml.Node) *yaml.Node {
	var seen map[*yaml.Node]struct{}
	for n != nil && n.Kind == yaml.AliasNode {
		if seen == nil {
			seen = make(map[*yaml.Node]struct{})
		}
		if _, ok := seen[n]; ok {
			return nil
		}
		seen[n] = struct{}{}
		n = n.Alias
	}
	return n
}

// BreakAliasCycles cuts alias back-edges in place: any alias whose target is
// an ancestor of the alias occurrence is replaced with a null node. In yaml.v3
// an alias node carries no Content — the back-edge runs through its .Alias
// pointer — so the walk follows both Content children and alias targets.
// Fully-walked (black) nodes are skipped on later visits so shared anchors stay
// linear.
func BreakAliasCycles(root *yaml.Node) {
	inProgress := map[*yaml.Node]struct{}{}
	done := map[*yaml.Node]struct{}{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if _, black := done[n]; black {
			return
		}
		inProgress[n] = struct{}{}
		if a := n.Alias; a != nil {
			if _, gray := inProgress[a]; gray {
				line, column := n.Line, n.Column
				*n = yaml.Node{Kind: yaml.ScalarNode, Tag: NullTag, Line: line, Column: column}
			} else {
				walk(a)
			}
		}
		for i, child := range n.Content {
			if child == nil {
				continue
			}
			if _, gray := inProgress[child]; gray {
				n.Content[i] = &yaml.Node{
					Kind:   yaml.ScalarNode,
					Tag:    NullTag,
					Line:   child.Line,
					Column: child.Column,
				}
				continue
			}
			walk(child)
		}
		delete(inProgress, n)
		done[n] = struct{}{}
	}
	walk(root)
}

// RewriteLines sets every node's Line in subtree n to line, visiting each
// shared DAG node at most once.
func RewriteLines(n *yaml.Node, line int) {
	rewriteLinesVisited(n, line, map[*yaml.Node]struct{}{})
}

func rewriteLinesVisited(n *yaml.Node, line int, visited map[*yaml.Node]struct{}) {
	if n == nil {
		return
	}
	if _, seen := visited[n]; seen {
		return
	}
	visited[n] = struct{}{}
	n.Line = line
	for _, child := range n.Content {
		rewriteLinesVisited(child, line, visited)
	}
}

// MappingKeyIndex returns the index of the key node for key in a mapping
// node's content slice, or -1 when absent.
func MappingKeyIndex(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// MappingEntry returns the key and value nodes for key in a mapping node, or
// (nil, nil) when absent.
func MappingEntry(m *yaml.Node, key string) (keyNode, valNode *yaml.Node) {
	if idx := MappingKeyIndex(m, key); idx >= 0 {
		return m.Content[idx], m.Content[idx+1]
	}
	return nil, nil
}

// MappingValue returns the value node for key in a mapping node, or nil.
func MappingValue(m *yaml.Node, key string) *yaml.Node {
	if idx := MappingKeyIndex(m, key); idx >= 0 {
		return m.Content[idx+1]
	}
	return nil
}

// RemoveMappingKey deletes key (and its value) from a mapping node.
func RemoveMappingKey(m *yaml.Node, key string) {
	idx := MappingKeyIndex(m, key)
	if idx < 0 {
		return
	}
	m.Content = append(m.Content[:idx], m.Content[idx+2:]...)
}

type nodePair struct {
	a, b *yaml.Node
}

// Equal compares kind, tag, value and children in order; positions and
// comments are ignored. Shared DAG node pairs are memoized so structural
// comparison stays linear on shared subtrees.
func Equal(a, b *yaml.Node) bool {
	return equalMemo(a, b, map[nodePair]bool{})
}

func equalMemo(a, b *yaml.Node, memo map[nodePair]bool) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	pair := nodePair{a: a, b: b}
	if eq, seen := memo[pair]; seen {
		return eq
	}
	if a.Kind != b.Kind || a.Tag != b.Tag || a.Value != b.Value || len(a.Content) != len(b.Content) {
		memo[pair] = false
		return false
	}
	memo[pair] = true
	for i := range a.Content {
		if !equalMemo(a.Content[i], b.Content[i], memo) {
			memo[pair] = false
			return false
		}
	}
	return true
}

// CopyNode deep-copies n with positions intact while memoizing shared DAG
// subtrees so stacked anchor reuse stays linear instead of exponential. Cyclic
// back-edges are dropped defensively.
func CopyNode(n *yaml.Node) *yaml.Node {
	return copyNodeGuarded(n, map[*yaml.Node]struct{}{}, map[*yaml.Node]*yaml.Node{})
}

func copyNodeGuarded(n *yaml.Node, inProgress map[*yaml.Node]struct{}, memo map[*yaml.Node]*yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if _, gray := inProgress[n]; gray {
		return nil
	}
	if out, ok := memo[n]; ok {
		return out
	}
	inProgress[n] = struct{}{}
	out := &yaml.Node{
		Kind:        n.Kind,
		Style:       n.Style,
		Tag:         n.Tag,
		Value:       n.Value,
		Anchor:      n.Anchor,
		Alias:       copyNodeGuarded(n.Alias, inProgress, memo),
		Content:     make([]*yaml.Node, len(n.Content)),
		HeadComment: n.HeadComment,
		LineComment: n.LineComment,
		FootComment: n.FootComment,
		Line:        n.Line,
		Column:      n.Column,
	}
	memo[n] = out
	for i, child := range n.Content {
		out.Content[i] = copyNodeGuarded(child, inProgress, memo)
	}
	delete(inProgress, n)
	return out
}

// CloneExpanded copies n into a DAG with all AliasNodes resolved to their
// targets, memoizing shared subtrees so stacked anchor reuse stays linear in
// unique nodes instead of expanding exponentially. Cyclic back-edges are
// neutralized to null scalars. When line > 0, every copied node is relocated
// to line and its YAML comments are cleared.
func CloneExpanded(n *yaml.Node, line int) *yaml.Node {
	return cloneExpandedGuarded(n, line, map[*yaml.Node]struct{}{}, map[*yaml.Node]*yaml.Node{})
}

func cloneExpandedGuarded(
	n *yaml.Node,
	line int,
	inProgress map[*yaml.Node]struct{},
	memo map[*yaml.Node]*yaml.Node,
) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode {
		target := ResolveAlias(n)
		if target == nil {
			l := line
			if l == 0 {
				l = n.Line
			}
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: NullTag, Line: l}
		}
		return cloneExpandedGuarded(target, line, inProgress, memo)
	}
	if _, gray := inProgress[n]; gray {
		l := line
		if l == 0 {
			l = n.Line
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: NullTag, Line: l}
	}
	if out, ok := memo[n]; ok {
		return out
	}
	inProgress[n] = struct{}{}
	cp := *n
	cp.Anchor = ""
	cp.Alias = nil
	if line > 0 {
		cp.Line = line
		cp.HeadComment = ""
		cp.LineComment = ""
		cp.FootComment = ""
	}
	memo[n] = &cp
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, child := range n.Content {
			cp.Content[i] = cloneExpandedGuarded(child, line, inProgress, memo)
		}
	}
	delete(inProgress, n)
	return &cp
}

// DeepMergeMappings returns a new mapping node combining base and overlay:
// nested mappings merge recursively, while sequences and scalars in overlay
// replace base. Shared (base, overlay) pairs are memoized so merging two YAML
// DAGs stays linear in unique pairs instead of expanding exponentially.
func DeepMergeMappings(base, overlay *yaml.Node) *yaml.Node {
	return deepMergeMappingsMemo(base, overlay, map[nodePair]*yaml.Node{})
}

func deepMergeMappingsMemo(base, overlay *yaml.Node, memo map[nodePair]*yaml.Node) *yaml.Node {
	if base == nil || base.Kind != yaml.MappingNode {
		return overlay
	}
	if overlay == nil || overlay.Kind != yaml.MappingNode {
		return base
	}
	if base == overlay {
		return overlay
	}
	pair := nodePair{a: base, b: overlay}
	if existing, ok := memo[pair]; ok {
		return existing
	}

	line := overlay.Line
	if line == 0 {
		line = base.Line
	}
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: MapTag, Line: line}
	memo[pair] = out

	overlayIndex := indexMappingKeys(overlay)
	usedOverlay := make(map[string]bool, len(overlayIndex))

	for i := 0; i+1 < len(base.Content); i += 2 {
		bk, bv := base.Content[i], base.Content[i+1]
		if bk.Kind != yaml.ScalarNode {
			continue
		}
		if oi, ok := overlayIndex[bk.Value]; ok {
			usedOverlay[bk.Value] = true
			out.Content = append(out.Content, overlay.Content[oi], mergeMappingValue(bv, overlay.Content[oi+1], memo))
			continue
		}
		out.Content = append(out.Content, bk, bv)
	}
	appendRemainingMappingEntries(out, overlay, usedOverlay)
	return out
}

func indexMappingKeys(m *yaml.Node) map[string]int {
	idx := make(map[string]int, len(m.Content)/2)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode {
			idx[m.Content[i].Value] = i
		}
	}
	return idx
}

func mergeMappingValue(baseVal, overlayVal *yaml.Node, memo map[nodePair]*yaml.Node) *yaml.Node {
	if baseVal.Kind == yaml.MappingNode && overlayVal.Kind == yaml.MappingNode {
		return deepMergeMappingsMemo(baseVal, overlayVal, memo)
	}
	return overlayVal
}

func appendRemainingMappingEntries(out, overlay *yaml.Node, used map[string]bool) {
	for i := 0; i+1 < len(overlay.Content); i += 2 {
		okNode, ovNode := overlay.Content[i], overlay.Content[i+1]
		if okNode.Kind == yaml.ScalarNode && used[okNode.Value] {
			continue
		}
		out.Content = append(out.Content, okNode, ovNode)
	}
}
