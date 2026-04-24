package kustomize

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/rootfile"
	yamlv3 "gopkg.in/yaml.v3"
)

// directSourceDetectLine maps a finding to a plain resources: file when render diverges from source YAML.
// Tries AST walk along searchKey, then a simple key-tail line match.
func directSourceDetectLine(srcPath, searchKey string, outputLines int) model.VulnerabilityLines {
	srcPath = filepath.Clean(srcPath)
	data, err := rootfile.ReadFile(srcPath)
	if err != nil {
		return model.VulnerabilityLines{Line: -1}
	}
	norm := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(norm, "\n")

	if ln := astLineForSearchKey([]byte(norm), searchKey); ln > 0 && ln <= len(lines) {
		trim := strings.TrimSpace(lines[ln-1])
		return model.VulnerabilityLines{
			Line:                  ln,
			VulnLines:             detector.GetAdjacentVulnLines(ln-1, outputLines, lines),
			LineWithVulnerability: trim,
			ResolvedFile:          srcPath,
			VulnerablilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: ln, Col: 1},
				End:   model.ResourceLine{Line: ln, Col: 1},
			},
		}
	}

	tail := searchKey
	if i := strings.LastIndex(searchKey, "."); i >= 0 {
		tail = searchKey[i+1:]
	}
	tail = strings.TrimSpace(tail)
	if idx := strings.Index(tail, "["); idx >= 0 {
		tail = tail[:idx]
	}
	if tail == "" {
		return model.VulnerabilityLines{Line: -1}
	}
	for i, line := range lines {
		trim := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(trim, tail+":") || strings.HasPrefix(trim, tail+" :") {
			return model.VulnerabilityLines{
				Line:                  i + 1,
				VulnLines:             detector.GetAdjacentVulnLines(i, outputLines, lines),
				LineWithVulnerability: trim,
				ResolvedFile:          srcPath,
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: i + 1, Col: 1},
					End:   model.ResourceLine{Line: i + 1, Col: 1},
				},
			}
		}
	}
	return model.VulnerabilityLines{Line: -1}
}

// astLineForSearchKey returns the 1-based line for searchKey in multi-doc YAML (dotted path with optional [i]); 0 if none.
func astLineForSearchKey(src []byte, searchKey string) int {
	if len(src) == 0 || strings.TrimSpace(searchKey) == "" {
		return 0
	}
	parts := splitSearchKeyPath(searchKey)
	if len(parts) == 0 {
		return 0
	}
	dec := yamlv3.NewDecoder(bytes.NewReader(src))
	for {
		var doc yamlv3.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if ln := walkYAMLPath(&doc, parts); ln > 0 {
			return ln
		}
	}
	return 0
}

type yamlPathPart struct {
	key   string
	index *int
}

const yamlPathPartInitialCap = 8

func splitSearchKeyPath(searchKey string) []yamlPathPart {
	out := make([]yamlPathPart, 0, yamlPathPartInitialCap)
	for _, raw := range strings.Split(searchKey, ".") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		p := yamlPathPart{key: part}
		if idx := strings.Index(part, "["); idx >= 0 {
			p.key = part[:idx]
			if end := strings.Index(part[idx:], "]"); end > 1 {
				if n, err := strconv.Atoi(part[idx+1 : idx+end]); err == nil {
					p.index = &n
				}
			}
		}
		out = append(out, p)
	}
	return out
}

func walkYAMLPath(node *yamlv3.Node, parts []yamlPathPart) int {
	if node == nil || len(parts) == 0 {
		return 0
	}
	cur := unwrapDocumentNode(node)
	var matchLine int
	for _, p := range parts {
		if cur == nil || p.key == "" {
			return 0
		}
		switch cur.Kind {
		case yamlv3.MappingNode:
			next := lookupMappingValue(cur, p.key)
			if next == nil {
				return matchLine
			}
			matchLine = next.Line
			cur = unwrapDocumentNode(next)
			if p.index != nil {
				cur = lookupSequenceIndex(cur, *p.index)
				if cur == nil {
					return matchLine
				}
				matchLine = cur.Line
			}
		case yamlv3.SequenceNode:
			cur = lookupSequenceElement(cur, p.key, p.index)
			if cur == nil {
				return matchLine
			}
			matchLine = cur.Line
		default:
			return matchLine
		}
	}
	return matchLine
}

func unwrapDocumentNode(n *yamlv3.Node) *yamlv3.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yamlv3.DocumentNode && len(n.Content) > 0 {
		return n.Content[0]
	}
	return n
}

func lookupMappingValue(node *yamlv3.Node, key string) *yamlv3.Node {
	if node == nil || node.Kind != yamlv3.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func lookupSequenceIndex(node *yamlv3.Node, idx int) *yamlv3.Node {
	if node == nil || node.Kind != yamlv3.SequenceNode || idx < 0 || idx >= len(node.Content) {
		return nil
	}
	return node.Content[idx]
}

func lookupSequenceElement(node *yamlv3.Node, key string, idx *int) *yamlv3.Node {
	if node == nil || node.Kind != yamlv3.SequenceNode {
		return nil
	}
	if idx != nil {
		if elem := lookupSequenceIndex(node, *idx); elem != nil {
			if mapped := lookupMappingValue(unwrapDocumentNode(elem), key); mapped != nil {
				return mapped
			}
			return elem
		}
	}
	for _, elem := range node.Content {
		elem = unwrapDocumentNode(elem)
		if elem == nil {
			continue
		}
		if mapped := lookupMappingValue(elem, key); mapped != nil {
			return mapped
		}
		if nameNode := lookupMappingValue(elem, "name"); nameNode != nil && nameNode.Value == key {
			return elem
		}
	}
	return nil
}
