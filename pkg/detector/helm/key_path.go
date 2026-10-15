package helm

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// keyMatch is the line a key of a search key matched; a selector key matched
// its value too, and so picks an item of a list.
type keyMatch struct {
	key      string
	selector bool
	value    string // the value a selector key must hold
	index    bool   // the key is the position of an item in the list the key before holds
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

// maxCachedDocuments bounds the rendered documents whose lines and key tree are
// kept: the findings of a document are looked up one after the other, and the
// parse is the cost.
const maxCachedDocuments = 16

type cachedDocument struct {
	attribution *model.HelmAttribution
	lines       []string
	once        sync.Once
	tree        *keyTree
	ok          bool
}

var documents struct {
	sync.Mutex
	entries []*cachedDocument
}

// cachedDocumentOf returns the entry of the rendered document of attribution,
// whose lines are split once.
func cachedDocumentOf(attribution *model.HelmAttribution) *cachedDocument {
	documents.Lock()
	defer documents.Unlock()
	for _, entry := range documents.entries {
		if entry.attribution == attribution {
			return entry
		}
	}
	entry := &cachedDocument{attribution: attribution, lines: strings.Split(attribution.RenderedContent, "\n")}
	if len(documents.entries) == maxCachedDocuments {
		documents.entries = documents.entries[1:]
	}
	documents.entries = append(documents.entries, entry)
	return entry
}

// cachedKeyTree returns the key tree of lines, parsed once for the same lines
// of a cached document. A tree is only read after it is built, so concurrent
// findings share it.
func cachedKeyTree(lines []string) (*keyTree, bool) {
	if len(lines) == 0 {
		return parseKeyTree(lines)
	}
	documents.Lock()
	var entry *cachedDocument
	for _, candidate := range documents.entries {
		if len(candidate.lines) == len(lines) && &candidate.lines[0] == &lines[0] {
			entry = candidate
			break
		}
	}
	documents.Unlock()
	if entry == nil {
		return parseKeyTree(lines)
	}
	entry.once.Do(func() { entry.tree, entry.ok = parseKeyTree(entry.lines) })
	return entry.tree, entry.ok
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
		if match.index {
			item, ok := tree.item(scope, match.key)
			if !ok || item.Line-1 != match.line {
				return false
			}
			scope = item
			continue
		}
		k, ok := tree.at(match.line, match.key)
		if !ok || !tree.sits(k, match, scope) ||
			match.selector && match.value != "" && !tree.holdsValue(k, match.value) {
			return false
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
		if match.selector || match.index {
			return nil
		}
		keys = append(keys, match.key)
	}
	return keys
}

// nextStart returns the line the node after scope starts at, or end when
// nothing follows it: where the output of scope stops.
func (t *keyTree) nextStart(scope *yaml.Node, end int) int {
	for node := scope; node != nil; {
		parent := t.parent[node]
		if parent == nil {
			return end
		}
		for i, child := range parent.Content {
			if child == node && i+1 < len(parent.Content) {
				return parent.Content[i+1].Line - 1
			}
		}
		node = parent
	}
	return end
}

// item returns the item of the list scope at the position position.
func (t *keyTree) item(scope *yaml.Node, position string) (*yaml.Node, bool) {
	n, err := strconv.Atoi(position)
	if scope == nil || scope.Kind != yaml.SequenceNode || err != nil || n < 0 || n >= len(scope.Content) {
		return nil, false
	}
	return scope.Content[n], true
}

// itemLine returns the line of the item at position of the list the last key of
// path holds.
func itemLine(lines []string, path []keyMatch, position string) (int, bool) {
	tree, ok := cachedKeyTree(lines)
	if !ok || len(path) == 0 {
		return 0, false
	}
	last := path[len(path)-1]
	k, ok := tree.at(last.line, last.key)
	if !ok || last.index {
		return 0, false
	}
	item, ok := tree.item(tree.scopeOf(k, last.selector), position)
	if !ok {
		return 0, false
	}
	return item.Line - 1, true
}

// selectsOneItem reports whether no other item of the list holds the selector
// key k with the same value: otherwise the key does not tell which item it picks.
func (t *keyTree) selectsOneItem(k keyNode) bool {
	list := t.parent[k.mapping]
	if list == nil || list.Kind != yaml.SequenceNode {
		return true
	}
	value := scalarOf(k.mapping, k.key)
	for _, item := range list.Content {
		if item != k.mapping && item.Kind == yaml.MappingNode && value != "" && scalarOf(item, k.key) == value {
			return false
		}
	}
	return true
}

// scalarOf returns the value of the scalar key written in mapping, named as
// key, or "".
func scalarOf(mapping, key *yaml.Node) string {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key.Value && mapping.Content[i+1].Kind == yaml.ScalarNode {
			return mapping.Content[i+1].Value
		}
	}
	return ""
}

// sits reports whether the key k that match found sits where a key of its path
// does: inside scope, once, and picking one item when it is a selector.
func (t *keyTree) sits(k keyNode, match keyMatch, scope *yaml.Node) bool {
	if match.selector && !t.selectsOneItem(k) {
		return false
	}
	if scope == nil {
		return true
	}
	if !t.within(k.key, scope) {
		return false
	}
	if !match.selector && !t.direct(k, scope) {
		for _, other := range t.childrenNamed(scope, match.key) {
			if other.key != k.key {
				return false
			}
		}
	}
	return true
}
