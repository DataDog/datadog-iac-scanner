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
	for _, line := range bytes.Split(content, []byte("\n")) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if trimmed[0] == '#' {
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("---")) {
			continue
		}
		if trimmed[0] == '-' && (len(trimmed) == 1 || trimmed[1] == ' ' || trimmed[1] == '\t') {
			return true
		}
		for _, key := range keys {
			prefix := key + ":"
			if bytes.HasPrefix(trimmed, []byte(prefix)) {
				return true
			}
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

func yamlMapKeyNode(m *yamlParser.Node, key string) *yamlParser.Node {
	return yamlMapKeyNodeSeen(m, key, make(map[*yamlParser.Node]struct{}))
}

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
	seen[m] = struct{}{}

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
