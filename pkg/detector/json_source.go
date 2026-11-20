/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// JSON uses encoding/json, like the document parser. Keep only structure and
// source positions: scalar values are neither retained nor interpreted as YAML.
type jsonSourceNode struct {
	kind      json.Delim
	line      int
	members   map[string]jsonSourceMember
	elements  []*jsonSourceNode
	reference bool
}

type jsonSourceMember struct {
	node *jsonSourceNode
	line int
}

type jsonSourceDecoder struct {
	decoder      *json.Decoder
	source       string
	offset, line int
}

func (cache *sourceDocumentCache) jsonLine(ctx context.Context, file *model.FileMetadata, path model.SourcePath) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	lines := file.Lines()
	if cache.jsonDocuments == nil || cache.kind != model.KindJSON || !sameSourceLines(lines, cache.lines) {
		documents, err := decodeWrittenJSON(ctx, strings.Join(lines, "\n"))
		if err != nil {
			return 0, err
		}
		cache.kind, cache.lines, cache.jsonDocuments = model.KindJSON, lines, documents
		cache.documents, cache.mappings = nil, nil
	} else {
		cache.lines = lines
	}
	index := file.SourceDocumentIndex
	if index < 0 || index >= len(cache.jsonDocuments) {
		return 0, fmt.Errorf("source document index unavailable")
	}
	root := cache.jsonDocuments[index]
	if root.kind != '{' {
		return 0, fmt.Errorf("JSON source document is not an object")
	}
	return root.lineAtPath(path)
}

func decodeWrittenJSON(ctx context.Context, source string) ([]*jsonSourceNode, error) {
	// Unlike YAML streams, the JSON document parser rejects an invalid suffix.
	if !json.Valid([]byte(source)) {
		return nil, fmt.Errorf("original JSON source unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(source))
	decoder.UseNumber()
	parser := jsonSourceDecoder{decoder: decoder, source: source, line: 1}
	root, err := parser.node(ctx)
	if err != nil {
		return nil, err
	}
	if root.kind == '[' {
		return root.elements, nil
	}
	return []*jsonSourceNode{root}, nil
}

// InputOffset includes separators before the next token. Locate its actual
// beginning and count each source byte at most once, including JSON whitespace.
func (p *jsonSourceDecoder) token(ctx context.Context) (json.Token, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	start := int(p.decoder.InputOffset())
	for start < len(p.source) && strings.IndexByte(" \t\r\n,:", p.source[start]) >= 0 {
		start++
	}
	for p.offset < start {
		if p.source[p.offset] == '\n' {
			p.line++
		}
		p.offset++
	}
	token, err := p.decoder.Token()
	return token, p.line, err
}

func (p *jsonSourceDecoder) node(ctx context.Context) (*jsonSourceNode, error) {
	token, line, err := p.token(ctx)
	if err != nil {
		return nil, err
	}
	node := &jsonSourceNode{line: line}
	node.kind, _ = token.(json.Delim)
	switch node.kind {
	case '{':
		node.members = make(map[string]jsonSourceMember)
		for p.decoder.More() {
			key, keyLine, err := p.token(ctx)
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("JSON object key is not a string")
			}
			child, err := p.node(ctx)
			if err != nil {
				return nil, err
			}
			// Duplicate decoded keys use the last property, as json.Unmarshal does.
			node.members[name] = jsonSourceMember{node: child, line: keyLine}
			node.reference = node.reference || name == sourceReferenceKey
		}
	case '[':
		for p.decoder.More() {
			child, err := p.node(ctx)
			if err != nil {
				return nil, err
			}
			node.elements = append(node.elements, child)
		}
	default:
		return node, nil
	}
	_, _, err = p.token(ctx) // Closing delimiter; syntax was validated above.
	return node, err
}

func (node *jsonSourceNode) lineAtPath(path model.SourcePath) (int, error) {
	line := node.line
	for index, segment := range path {
		switch node.kind {
		case '{':
			if segment.IsIndex {
				return 0, fmt.Errorf("array index applied to object")
			}
			member, found := node.members[segment.Key]
			if !found {
				if node.reference {
					return 0, fmt.Errorf("resolved source property unavailable")
				}
				if index != len(path)-1 {
					return 0, fmt.Errorf("missing intermediate source property")
				}
				return line, nil
			}
			node, line = member.node, member.line
		case '[':
			if !segment.IsIndex {
				return 0, fmt.Errorf("object key applied to array")
			}
			if segment.Index < 0 || segment.Index >= len(node.elements) {
				return 0, fmt.Errorf("array index out of bounds")
			}
			node = node.elements[segment.Index]
			line = node.line
		default:
			return 0, fmt.Errorf("source traversal through scalar unsupported")
		}
	}
	return line, nil
}
