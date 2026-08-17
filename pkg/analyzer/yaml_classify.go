package analyzer

import (
	"bytes"

	yamlParser "gopkg.in/yaml.v3"
)

// yamlPlatformRootKeys are top-level mapping keys that can identify a platform
// when no regex-based type matched during classification.
var yamlPlatformRootKeys = []string{
	listKeywordsGoogleDeployment[0], // resources
	playBooks,                         // playbooks
	ansibleHost[0],                    // all
	ansibleHost[1],                    // ungrouped
}

// yamlRootHasAnyKey reports whether content appears to declare any of keys at
// the document root, without parsing the full YAML tree.
func yamlRootHasAnyKey(content []byte, keys ...string) bool {
	if len(content) == 0 {
		return false
	}
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})
	inDoc := false
	for _, line := range bytes.Split(content, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if trimmed[0] == '#' {
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("---")) {
			inDoc = true
			continue
		}
		if !inDoc {
			inDoc = true
		}
		if trimmed[0] == ' ' || trimmed[0] == '\t' {
			continue
		}
		if trimmed[0] == '-' {
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
	if m == nil || m.Kind != yamlParser.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yamlParser.ScalarNode && k.Value == key {
			return m.Content[i+1]
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
