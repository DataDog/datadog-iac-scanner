package kustomize

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/rootfile"
)

// DetectKindLine maps Kustomize-rendered findings back to source lines.
type DetectKindLine struct{}

// DetectLine: direct sources use default YAML tracing; generators/transformers use kustomization lines.
func (DetectKindLine) DetectLine(
	ctx context.Context,
	file *model.FileMetadata,
	searchKey string,
	outputLines int,
) model.VulnerabilityLines {
	o := file.KustomizeOrigin
	if o != nil && o.OriginKind == model.KustomizeOriginDirect && o.SourceFile != "" && o.SourceRepo == "" {
		if v := directSourceDetectLine(o.SourceFile, searchKey, outputLines); v.Line > 0 {
			return v
		}
	}
	if o == nil || !o.RequiresDetailedLineMapping() {
		return detector.DefaultYAMLDetectLine{}.DetectLine(ctx, file, searchKey, outputLines)
	}
	cfg := o.GeneratorConfigFile
	if cfg == "" {
		return detector.DefaultYAMLDetectLine{}.DetectLine(ctx, file, searchKey, outputLines)
	}
	data, err := rootfile.ReadFile(filepath.Clean(cfg))
	if err != nil {
		return detector.DefaultYAMLDetectLine{}.DetectLine(ctx, file, searchKey, outputLines)
	}
	lines := strings.Split(string(data), "\n")
	if v, ok := mappedLineFromKustomizeOrigin(ctx, file, o, searchKey, outputLines, lines); ok {
		return v
	}
	return detector.DefaultYAMLDetectLine{}.DetectLine(ctx, file, searchKey, outputLines)
}

func mappedLineFromKustomizeOrigin(
	ctx context.Context,
	file *model.FileMetadata,
	o *model.KustomizeOrigin,
	searchKey string,
	outputLines int,
	lines []string,
) (model.VulnerabilityLines, bool) {
	switch o.OriginKind {
	case model.KustomizeOriginGenerator:
		name := o.ResourceName
		if name == "" {
			name = metadataNameFromDoc(file.Document)
		}
		line1, p := generatorConfigLine(o, name)
		return buildMappedVulnLines(line1-1, p, lines, outputLines), true
	case model.KustomizeOriginTransformer:
		if v := transformerPatchFileLine(ctx, o, searchKey, outputLines); v.Line > 0 {
			return v, true
		}
		if o.OriginalSourceFile != "" && o.OriginalSourceRepo == "" {
			if v := directSourceDetectLine(o.OriginalSourceFile, searchKey, outputLines); v.Line > 0 {
				return v, true
			}
		}
		line1, p := transformerLineForOrigin(o)
		return buildMappedVulnLines(line1-1, p, lines, outputLines), true
	default:
		return model.VulnerabilityLines{}, false
	}
}

func buildMappedVulnLines(lineIdx int, resolvedPath string, lines []string, outputLines int) model.VulnerabilityLines {
	if lineIdx < 0 {
		lineIdx = 0
	}
	if lineIdx >= len(lines) {
		lineIdx = 0
	}
	return model.VulnerabilityLines{
		Line:                  lineIdx + 1,
		VulnLines:             detector.GetAdjacentVulnLines(lineIdx, outputLines, lines),
		LineWithVulnerability: strings.TrimSpace(lines[lineIdx]),
		ResolvedFile:          resolvedPath,
		VulnerablilityLocation: model.ResourceLocation{
			Start: model.ResourceLine{Line: lineIdx + 1, Col: 1},
			End:   model.ResourceLine{Line: lineIdx + 1, Col: 1},
		},
	}
}

func metadataNameFromDoc(doc model.Document) string {
	if doc == nil {
		return ""
	}
	m, ok := doc["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	n, _ := m["name"].(string)
	return n
}
