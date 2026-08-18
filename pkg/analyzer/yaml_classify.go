package analyzer

import (
	"bytes"

	yamlParser "gopkg.in/yaml.v3"
)

// yamlPlatformRootKeys are top-level mapping keys that can identify a platform
// when no regex-based type matched during classification.
var yamlPlatformRootKeys = []string{
	listKeywordsGoogleDeployment[0], // resources
	playBooks,                       // playbooks
	ansibleHost[0],                  // all
	ansibleHost[1],                  // ungrouped
}

// yamlRootHasAnyKey reports whether content appears to declare any of keys at
// the document root, without parsing the full YAML tree.
func yamlRootHasAnyKey(content []byte, keys ...string) bool {
	if len(content) == 0 {
		return false
	}
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})
	rootIndent, matchIndent := -1, -1
	for _, line := range bytes.Split(content, []byte("\n")) {
		indent, trimmed := yamlLineContent(line)
		if len(trimmed) == 0 {
			continue
		}
		if rootIndent < 0 || indent < rootIndent {
			rootIndent = indent
		}
		if yamlRootContentHasAnyKey(trimmed, keys...) && (matchIndent < 0 || indent < matchIndent) {
			matchIndent = indent
		}
	}
	return matchIndent >= 0 && matchIndent == rootIndent
}

func yamlRootContentHasAnyKey(trimmed []byte, keys ...string) bool {
	// A root-level sequence is the shape of an Ansible playbook, where the
	// keywords live on the plays rather than on the document root.
	if trimmed[0] == '-' && (len(trimmed) == 1 || trimmed[1] == ' ' || trimmed[1] == '\t') {
		return true
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return true
	}
	if quote := trimmed[0]; quote == '"' || quote == '\'' {
		return quotedRootKeyIsAny(trimmed, quote, keys...)
	}
	return plainRootKeyIsAny(trimmed, keys...) || plainRootKeyIsAny(trimmed, "<<")
}

func yamlLineContent(line []byte) (indent int, content []byte) {
	for indent < len(line) && (line[indent] == ' ' || line[indent] == '\t') {
		indent++
	}
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[0] == '#' {
		return 0, nil
	}
	if bytes.HasPrefix(trimmed, []byte("---")) {
		trimmed = bytes.TrimSpace(trimmed[3:])
		if len(trimmed) == 0 || trimmed[0] == '#' {
			return 0, nil
		}
	}
	return indent, trimmed
}

func plainRootKeyIsAny(trimmed []byte, keys ...string) bool {
	for _, key := range keys {
		if !bytes.HasPrefix(trimmed, []byte(key)) {
			continue
		}
		afterKey := bytes.TrimLeft(trimmed[len(key):], " \t")
		if len(afterKey) > 0 && afterKey[0] == ':' {
			return true
		}
	}
	return false
}

// quotedRootKeyIsAny reports whether a quoted root key equals one of keys.
// Only the plain form is decoded; an unterminated or escaped quote makes the
// key ambiguous, so those lines are reported as a possible match and left for
// the parser to resolve.
func quotedRootKeyIsAny(trimmed []byte, quote byte, keys ...string) bool {
	rest := trimmed[1:]
	end := bytes.IndexByte(rest, quote)
	if end < 0 {
		return true
	}
	if quote == '"' && bytes.IndexByte(rest[:end], '\\') >= 0 {
		return true
	}
	// Without a colon the line is a scalar rather than a mapping key.
	if after := bytes.TrimLeft(rest[end+1:], " \t"); len(after) == 0 || after[0] != ':' {
		return false
	}
	name := rest[:end]
	for _, key := range keys {
		if string(name) == key {
			return true
		}
	}
	return false
}

func yamlDocumentRoot(content []byte) (*yamlParser.Node, error) {
	var node yamlParser.Node
	if err := yamlParser.Unmarshal(content, &node); err != nil {
		return nil, err
	}
	contentNode := &node
	if node.Kind == yamlParser.DocumentNode && len(node.Content) > 0 {
		contentNode = node.Content[0]
	}
	if contentNode.Kind == yamlParser.ScalarNode {
		return nil, nil
	}
	return contentNode, nil
}

func yamlRootIsMapping(root *yamlParser.Node) bool {
	return root != nil && root.Kind == yamlParser.MappingNode
}

func yamlMapKeyNode(m *yamlParser.Node, key string) *yamlParser.Node {
	return yamlMapKeyNodeSeen(m, key, nil)
}

// yamlMapKeyNodeSeen looks key up in m, following merge keys into the mappings
// they pull in. seen guards against alias cycles and may be nil; it is only
// allocated once a merge key is actually found, since the overwhelmingly common
// case is a mapping with none and this runs for every keyword of every play.
func yamlMapKeyNodeSeen(m *yamlParser.Node, key string, seen map[*yamlParser.Node]struct{}) *yamlParser.Node {
	if m != nil && m.Kind == yamlParser.AliasNode {
		m = m.Alias
	}
	if m == nil || m.Kind != yamlParser.MappingNode {
		return nil
	}
	if _, ok := seen[m]; ok {
		return nil
	}

	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yamlParser.ScalarNode && k.Value == key {
			return m.Content[i+1]
		}
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yamlParser.ScalarNode || k.Value != "<<" || k.Tag == "!!str" {
			continue
		}
		if seen == nil {
			seen = make(map[*yamlParser.Node]struct{})
		}
		seen[m] = struct{}{}
		if found := yamlMergedMapKeyNode(m.Content[i+1], key, seen); found != nil {
			return found
		}
	}
	return nil
}

func yamlMergedMapKeyNode(merge *yamlParser.Node, key string, seen map[*yamlParser.Node]struct{}) *yamlParser.Node {
	if merge == nil {
		return nil
	}
	switch merge.Kind {
	case yamlParser.AliasNode:
		return yamlMapKeyNodeSeen(merge.Alias, key, seen)
	case yamlParser.MappingNode:
		return yamlMapKeyNodeSeen(merge, key, seen)
	case yamlParser.SequenceNode:
		for _, item := range merge.Content {
			if found := yamlMergedMapKeyNode(item, key, seen); found != nil {
				return found
			}
		}
	}
	return nil
}

func ansiblePlayKeywordsFromNode(play *yamlParser.Node) bool {
	if play == nil || play.Kind != yamlParser.MappingNode {
		return false
	}
	for _, keyword := range listKeywordsAnsible {
		if yamlMapKeyNode(play, keyword) != nil {
			return true
		}
	}
	return false
}

func ansibleFromYAMLNode(root *yamlParser.Node) bool {
	if root == nil {
		return false
	}
	if root.Kind == yamlParser.SequenceNode {
		for _, item := range root.Content {
			if ansiblePlayKeywordsFromNode(item) {
				return true
			}
		}
		return false
	}
	if root.Kind != yamlParser.MappingNode {
		return false
	}
	playbooks := yamlMapKeyNode(root, playBooks)
	if playbooks != nil && playbooks.Kind == yamlParser.SequenceNode {
		for _, item := range playbooks.Content {
			if ansiblePlayKeywordsFromNode(item) {
				return true
			}
		}
	}
	for _, hostKey := range ansibleHost {
		hosts := yamlMapKeyNode(root, hostKey)
		if hosts == nil || hosts.Kind != yamlParser.MappingNode {
			continue
		}
		for _, keyword := range listKeywordsAnsibleHots {
			if yamlMapKeyNode(hosts, keyword) != nil {
				return true
			}
		}
	}
	return false
}
