/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

type pathDetector interface {
	DetectPath(context.Context, *model.FileMetadata, model.SourcePath, int) (model.VulnerabilityLines, error)
}

// DetectPath resolves a structured source path without passing it through the
// legacy search-key syntax. A kind must explicitly support this protocol.
func (d *DetectLine) DetectPath(ctx context.Context, file *model.FileMetadata, path model.SourcePath) (model.VulnerabilityLines, error) {
	if err := ctx.Err(); err != nil {
		return model.VulnerabilityLines{}, err
	}
	if impl, ok := d.detectors[file.Kind].(pathDetector); ok {
		return impl.DetectPath(ctx, file, path, d.outputLines)
	}
	if file.Kind != model.KindYAML && file.Kind != model.KindJSON && file.Kind != model.KindTerraformPlan {
		return model.VulnerabilityLines{}, fmt.Errorf("structured source paths unsupported for %s", file.Kind)
	}
	return detectDocumentPath(file, path, d.outputLines)
}

func detectDocumentPath(file *model.FileMetadata, path model.SourcePath, output int) (model.VulnerabilityLines, error) {
	var node interface{} = file.LineInfoDocument
	components := make([]string, 0, len(path))
	line := -1

	for index, seg := range path {
		next, found, err := sourceChild(node, seg)
		if err != nil {
			return model.VulnerabilityLines{}, err
		}
		if !found {
			if index != len(path)-1 {
				return model.VulnerabilityLines{}, fmt.Errorf("missing intermediate source property")
			}
			break
		} // A missing property belongs to its nearest written parent.
		component := seg.Key
		if seg.IsIndex {
			component = strconv.Itoa(seg.Index)
		}
		components = append(components, component)
		var candidate int
		if len(components) == 1 {
			// Root properties carry their markers on the document itself.
			candidate = lineAtPath(file.LineInfoDocument, []string{"_dd_lines", "_dd_" + component, "_dd_line"})
		} else {
			candidate = GetLineBySearchLine(components, file)
		}
		if candidate > 0 {
			line = candidate
		}
		node = next
	}
	if line < 1 {
		// The first written root property anchors this document, which may be the
		// second or later document in a YAML stream. Line 1 is not a safe default.
		for key := range file.LineInfoDocument {
			candidate := lineAtPath(file.LineInfoDocument, []string{"_dd_lines", "_dd_" + key, "_dd_line"})
			if candidate > 0 && (line < 0 || candidate < line) {
				line = candidate
			}
		}
	}
	return sourceLines(file, line, output)
}

func sourceLines(file *model.FileMetadata, line, output int) (model.VulnerabilityLines, error) {
	lines := file.Lines()
	if line < 1 || line > len(lines) {
		return model.VulnerabilityLines{}, fmt.Errorf("source location unavailable")
	}
	loc := model.ResourceLocation{
		Start: model.ResourceLine{Line: line, Col: 1},
		End:   model.ResourceLine{Line: line, Col: len(lines[line-1]) + 1},
	}
	return model.VulnerabilityLines{
		Line: line, ResolvedFile: file.FilePath, VulnLines: GetAdjacentVulnLines(line-1, output, lines),
		LineWithVulnerability: lines[line-1], VulnerablilityLocation: loc, BlockLocation: loc,
	}, nil
}

func sourceChild(node interface{}, seg model.PathSegment) (next interface{}, found bool, err error) {
	switch value := node.(type) {
	case map[string]interface{}:
		if _, resolved := value["RefMetadata"]; resolved {
			return nil, false, fmt.Errorf("structured resolved reference locations unsupported")
		}
		if seg.IsIndex {
			return nil, false, fmt.Errorf("array index applied to object")
		}
		next, found = value[seg.Key]
	case model.Document:
		if _, resolved := value["RefMetadata"]; resolved {
			return nil, false, fmt.Errorf("structured resolved reference locations unsupported")
		}
		if seg.IsIndex {
			return nil, false, fmt.Errorf("array index applied to object")
		}
		next, found = value[seg.Key]
	case []interface{}:
		if !seg.IsIndex {
			return nil, false, fmt.Errorf("object key applied to array")
		}
		if seg.Index < 0 || seg.Index >= len(value) {
			return nil, false, fmt.Errorf("array index out of bounds")
		}
		next, found = value[seg.Index], true
	default:
		return nil, false, fmt.Errorf("path continues through scalar")
	}
	return next, found, nil
}
