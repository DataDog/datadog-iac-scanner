package helm

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// keyMatch is the line a key of a search key matched; a selector key matched
// its value too, and so picks an item of a list.
type keyMatch struct {
	key      string
	selector bool
	value    string // the value a selector key must hold
	line     int
}

// keyNode is a mapping key of the rendered YAML.
type keyNode struct {
	key     *yaml.Node
	mapping *yaml.Node
}

// keyTree indexes the mapping keys of rendered YAML by the line they are
// written at, and links every node to its parent.
type keyTree struct {
	parent map[*yaml.Node]*yaml.Node
	byLine map[int][]keyNode
	byName map[string][]keyNode
	roots  []*yaml.Node
}

// lastTree keeps the tree of the rendered document checked last: a finding
// looks the same document up again and again, and the parse is the cost.
var lastTree struct {
	sync.Mutex
	content string
	tree    *keyTree
	ok      bool
}

// cachedKeyTree returns the key tree of lines, parsed once for the same content.
// A tree is only read after it is built, so concurrent findings share it.
func cachedKeyTree(lines []string) (*keyTree, bool) {
	content := strings.Join(lines, "\n")
	lastTree.Lock()
	defer lastTree.Unlock()
	if lastTree.tree != nil && lastTree.content == content {
		return lastTree.tree, lastTree.ok
	}
	tree, ok := parseKeyTree(lines)
	lastTree.content, lastTree.tree, lastTree.ok = content, tree, ok
	return tree, ok
}

func parseKeyTree(lines []string) (*keyTree, bool) {
	tree := &keyTree{parent: map[*yaml.Node]*yaml.Node{}, byLine: map[int][]keyNode{}, byName: map[string][]keyNode{}}
	decoder := yaml.NewDecoder(bytes.NewReader([]byte(strings.Join(lines, "\n"))))
	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return tree, true
		}
		if err != nil {
			return nil, false
		}
		tree.roots = append(tree.roots, &doc)
		tree.add(&doc)
	}
}

func (t *keyTree) add(node *yaml.Node) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			k := keyNode{key: key, mapping: node}
			t.byLine[key.Line-1] = append(t.byLine[key.Line-1], k)
			t.byName[key.Value] = append(t.byName[key.Value], k)
		}
	case yaml.DocumentNode, yaml.SequenceNode:
	default:
		return
	}
	for _, child := range node.Content {
		t.parent[child] = node
		t.add(child)
	}
}

// at returns the key written at line, as a YAML key and not as text of a
// comment or a scalar.
func (t *keyTree) at(line int, key string) (keyNode, bool) {
	for _, candidate := range t.byLine[line] {
		if candidate.key.Value == key {
			return candidate, true
		}
	}
	return keyNode{}, false
}

// holdsValue reports whether the key has the scalar value, or a value that is
// not a scalar and so cannot be told from it.
func (t *keyTree) holdsValue(k keyNode, value string) bool {
	for i := 0; i+1 < len(k.mapping.Content); i += 2 {
		if k.mapping.Content[i] == k.key {
			v := k.mapping.Content[i+1]
			return v.Kind != yaml.ScalarNode || v.Value == value
		}
	}
	return true
}

// within reports whether node sits inside scope.
func (t *keyTree) within(node, scope *yaml.Node) bool {
	for ; node != nil; node = t.parent[node] {
		if node == scope {
			return true
		}
	}
	return false
}

// direct reports whether the key sits right under scope: in its mapping, or in
// an item of its list.
func (t *keyTree) direct(k keyNode, scope *yaml.Node) bool {
	return k.mapping == scope || scope.Kind == yaml.SequenceNode && t.parent[k.mapping] == scope
}

// scopeOf returns the node a following key must sit inside: the value of the
// key, or the list item of a selector key. It is nil when nothing constrains
// the next key.
func (t *keyTree) scopeOf(k keyNode, selector bool) *yaml.Node {
	if !selector {
		for i := 0; i+1 < len(k.mapping.Content); i += 2 {
			if k.mapping.Content[i] == k.key {
				return k.mapping.Content[i+1]
			}
		}
		return nil
	}
	if parent := t.parent[k.mapping]; parent != nil && parent.Kind == yaml.SequenceNode {
		return k.mapping
	}
	return nil
}

// childrenNamed returns the keys named key directly under scope.
func (t *keyTree) childrenNamed(scope *yaml.Node, key string) []keyNode {
	var found []keyNode
	for _, k := range t.byName[key] {
		if t.direct(k, scope) {
			found = append(found, k)
		}
	}
	return found
}

// keyPathHolds reports whether the keys of path matched YAML keys, each one
// under the one before: a key matched in a comment, in a block scalar or under
// another parent does not locate the finding. A search key may skip levels,
// and a selector that picks no list item starts over.
func keyPathHolds(lines []string, path []keyMatch) bool {
	tree, ok := cachedKeyTree(lines)
	if !ok {
		return false
	}
	var scope *yaml.Node
	for _, match := range path {
		if isIDLine(lines[match.line]) {
			continue
		}
		k, ok := tree.at(match.line, match.key)
		if !ok {
			return false
		}
		if match.selector && match.value != "" && !tree.holdsValue(k, match.value) {
			return false
		}
		if scope != nil {
			if !tree.within(k.key, scope) {
				return false
			}
			if !match.selector && !tree.direct(k, scope) {
				for _, other := range tree.childrenNamed(scope, match.key) {
					if other.key != k.key {
						return false
					}
				}
			}
		}
		scope = tree.scopeOf(k, match.selector)
	}
	return true
}

// directKeyLine returns the line of the last of keys when each one is a key
// written directly under the one before it, from the top of a single document.
// It answers when the keys matched by walking the text do not hold, as a
// nested key of the same name came first.
func directKeyLine(lines, keys []string) (int, bool) {
	tree, ok := cachedKeyTree(lines)
	if !ok || len(keys) == 0 {
		return 0, false
	}
	line, matches := -1, 0
	for _, root := range tree.roots {
		scope := root
		if scope.Kind == yaml.DocumentNode && len(scope.Content) > 0 {
			scope = scope.Content[0]
		}
		at := -1
		for _, key := range keys {
			value, keyLine, found := directChild(scope, key)
			if !found {
				at = -1
				break
			}
			scope, at = value, keyLine
		}
		if at >= 0 {
			line, matches = at, matches+1
		}
	}
	return line, matches == 1
}

// directChild returns the value of the one key named key directly under the
// mapping scope, and the line the key is written at.
func directChild(scope *yaml.Node, key string) (*yaml.Node, int, bool) {
	if scope.Kind != yaml.MappingNode {
		return nil, 0, false
	}
	var value *yaml.Node
	line, count := 0, 0
	for i := 0; i+1 < len(scope.Content); i += 2 {
		if scope.Content[i].Value == key {
			value, line, count = scope.Content[i+1], scope.Content[i].Line-1, count+1
		}
	}
	return value, line, count == 1
}

// pathKeys returns the keys of path, without the ID stamps, or none when a key
// selects a list item.
func pathKeys(lines []string, path []keyMatch) []string {
	var keys []string
	for _, match := range path {
		if isIDLine(lines[match.line]) {
			continue
		}
		if match.selector {
			return nil
		}
		keys = append(keys, match.key)
	}
	return keys
}
