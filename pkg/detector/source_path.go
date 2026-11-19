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
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
)

type pathDetector interface {
	DetectPath(context.Context, *model.FileMetadata, model.SourcePath, int) (model.VulnerabilityLines, error)
}

// sourceDocumentCache retains only the current source snapshot. It is populated
// exclusively by structured findings; legacy marker trees are not source authority.
type sourceDocumentCache struct {
	mu        sync.Mutex
	kind      model.FileKind
	lines     []string
	documents []*yaml.Node
	mappings  map[*yaml.Node]*sourceMapping
}

type sourceMember struct {
	value *yaml.Node
	line  int
}
type sourceMapping struct {
	members              map[string]sourceMember
	transformed, complex bool
}

// DetectPath resolves written syntax without interpreting legacy search keys or
// reading markers from a resolved/transformed document.
func (d *DetectLine) DetectPath(ctx context.Context, file *model.FileMetadata, path model.SourcePath) (model.VulnerabilityLines, error) {
	if err := ctx.Err(); err != nil {
		return model.VulnerabilityLines{}, err
	}
	if impl, ok := d.detectors[file.Kind].(pathDetector); ok {
		return impl.DetectPath(ctx, file, path, d.outputLines)
	}
	if file.Kind != model.KindYAML && file.Kind != model.KindJSON {
		return model.VulnerabilityLines{}, fmt.Errorf("structured source paths unsupported for %s", file.Kind)
	}
	d.source.mu.Lock()
	defer d.source.mu.Unlock()
	documents, err := d.source.load(ctx, file)
	if err != nil {
		return model.VulnerabilityLines{}, err
	}
	index := file.SourceDocumentIndex
	if index < 0 || index >= len(documents) {
		return model.VulnerabilityLines{}, fmt.Errorf("source document index unavailable")
	}
	if file.Kind == model.KindJSON && documents[index].Kind != yaml.MappingNode {
		return model.VulnerabilityLines{}, fmt.Errorf("JSON source document is not an object")
	}
	line, err := d.source.writtenNodeLine(ctx, documents[index], path)
	if err != nil {
		return model.VulnerabilityLines{}, err
	}
	return sourceLines(file, line, d.outputLines)
}

func (cache *sourceDocumentCache) load(ctx context.Context, file *model.FileMetadata) ([]*yaml.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lines := file.Lines()
	// Lines are immutable snapshots and stay available after OriginalData is
	// released. Most findings reuse the same slice; multi-document files may
	// have separate slices with the same content.
	if cache.documents != nil && cache.kind == file.Kind && sameSourceLines(lines, cache.lines) {
		cache.lines = lines
		return cache.documents, nil
	}
	source := strings.Join(lines, "\n")
	if file.Kind == model.KindJSON && !json.Valid([]byte(source)) {
		return nil, fmt.Errorf("original JSON source unavailable")
	}
	documents, err := decodeWrittenDocuments(ctx, source, file.Kind)
	if err != nil {
		return nil, err
	}
	cache.kind, cache.lines, cache.documents, cache.mappings = file.Kind, lines, documents, nil
	return documents, nil
}

func decodeWrittenDocuments(ctx context.Context, source string, kind model.FileKind) ([]*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(source))
	var documents []*yaml.Node
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(document.Content) == 0 {
			continue
		}
		root := document.Content[0]
		if kind == model.KindJSON && root.Kind == yaml.SequenceNode {
			documents = append(documents, root.Content...)
			continue
		}
		if root.Kind == yaml.ScalarNode {
			continue
		}
		documents = append(documents, root)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return documents, nil
}

func (cache *sourceDocumentCache) writtenNodeLine(ctx context.Context, node *yaml.Node, path model.SourcePath) (int, error) {
	line := node.Line
	for index, segment := range path {
		next, position, err := cache.writtenNodeChild(ctx, node, segment)
		if err != nil {
			return 0, err
		}
		if next == nil {
			if index != len(path)-1 {
				return 0, fmt.Errorf("missing intermediate source property")
			}
			return line, nil
		}
		node, line = next, position
	}
	return line, nil
}

func (cache *sourceDocumentCache) writtenNodeChild(
	ctx context.Context, node *yaml.Node, segment model.PathSegment,
) (*yaml.Node, int, error) {
	switch node.Kind {
	case yaml.MappingNode:
		if segment.IsIndex {
			return nil, 0, fmt.Errorf("array index applied to object")
		}
		return cache.writtenMappingChild(ctx, node, segment.Key)
	case yaml.SequenceNode:
		if !segment.IsIndex {
			return nil, 0, fmt.Errorf("object key applied to array")
		}
		if segment.Index < 0 || segment.Index >= len(node.Content) {
			return nil, 0, fmt.Errorf("array index out of bounds")
		}
		child := node.Content[segment.Index]
		return child, child.Line, nil
	default:
		return nil, 0, fmt.Errorf("source traversal through scalar, alias or generated structure unsupported")
	}
}

// Index only mapping nodes actually visited by a finding. Values and keys are
// borrowed from the syntax tree; no second document/value tree is constructed.
func (cache *sourceDocumentCache) writtenMappingChild(ctx context.Context, node *yaml.Node, key string) (*yaml.Node, int, error) {
	index := cache.mappings[node]
	if index == nil {
		var err error
		index, err = indexWrittenMapping(ctx, node)
		if err != nil {
			return nil, 0, err
		}
		if cache.mappings == nil {
			cache.mappings = make(map[*yaml.Node]*sourceMapping)
		}
		cache.mappings[node] = index
	}
	if member, found := index.members[key]; found {
		return member.value, member.line, nil
	}
	if index.complex {
		return nil, 0, fmt.Errorf("complex source keys unsupported")
	}
	if index.transformed {
		return nil, 0, fmt.Errorf("inherited or resolved source property unavailable")
	}
	return nil, 0, nil
}

func indexWrittenMapping(ctx context.Context, node *yaml.Node) (*sourceMapping, error) {
	index := &sourceMapping{members: make(map[string]sourceMember, len(node.Content)/2)}
	// Source parsers retain the last property for duplicate mapping keys.
	for position := 0; position < len(node.Content); position += 2 {
		if position%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		name, value := node.Content[position], node.Content[position+1]
		if name.Kind != yaml.ScalarNode {
			index.complex = true
			continue
		}
		index.members[name.Value] = sourceMember{value: value, line: name.Line}
		if name.Tag == "!!merge" || name.Value == "$ref" {
			index.transformed = true
		}
	}
	return index, nil
}

func sourceLines(file *model.FileMetadata, line, output int) (model.VulnerabilityLines, error) {
	lines := file.Lines()
	if line < 1 || line > len(lines) {
		return model.VulnerabilityLines{}, fmt.Errorf("source location unavailable")
	}
	loc := model.ResourceLocation{
		Start: model.ResourceLine{Line: line, Col: 1}, End: model.ResourceLine{Line: line, Col: len(lines[line-1]) + 1},
	}
	return model.VulnerabilityLines{
		Line: line, ResolvedFile: file.FilePath, VulnLines: GetAdjacentVulnLines(line-1, output, lines),
		LineWithVulnerability: lines[line-1], VulnerablilityLocation: loc, BlockLocation: loc,
	}, nil
}

func sameSourceLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return len(a) == 0 || &a[0] == &b[0] || slices.Equal(a, b)
}
