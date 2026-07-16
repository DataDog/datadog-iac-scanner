/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/rs/zerolog"
)

type kindDetectLine interface {
	DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int) model.VulnerabilityLines
}

// kindEnrichLine adds source and remediation context to a resolved line.
type kindEnrichLine interface {
	EnrichLine(ctx context.Context, file *model.FileMetadata, line, outputLines int) model.VulnerabilityLines
}

// kindRefinePathLine adjusts metadata-based line resolution.
type kindRefinePathLine interface {
	RefinePathLine(ctx context.Context, file *model.FileMetadata, path model.Path, line int) int
}

// kindDetectPathLine resolves structured paths with kind-specific metadata.
type kindDetectPathLine interface {
	DetectLineByPath(ctx context.Context, file *model.FileMetadata, path model.Path, outputLines int) model.VulnerabilityLines
}

// DetectLine routes line detection by file kind.
type DetectLine struct {
	detectors       map[model.FileKind]kindDetectLine
	outputLines     int
	logWithFields   *zerolog.Logger
	defaultDetector kindDetectLine
}

// NewDetectLine creates a line detector.
func NewDetectLine(outputLines int) *DetectLine {
	return &DetectLine{
		detectors:       make(map[model.FileKind]kindDetectLine),
		logWithFields:   &zerolog.Logger{},
		outputLines:     outputLines,
		defaultDetector: defaultDetectLine{},
	}
}

// SetupLogs sets the detector logger.
func (d *DetectLine) SetupLogs(logger *zerolog.Logger) {
	d.logWithFields = logger
}

// Add registers a detector for a file kind.
func (d *DetectLine) Add(detector kindDetectLine, kind model.FileKind) *DetectLine {
	d.detectors[kind] = detector
	return d
}

// DetectLine resolves a legacy search key.
func (d *DetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string) model.VulnerabilityLines {
	if det, ok := d.detectors[file.Kind]; ok {
		return det.DetectLine(ctx, file, searchKey, d.outputLines)
	}
	return d.defaultDetector.DetectLine(ctx, file, searchKey, d.outputLines)
}

// DetectLineByPath resolves a structured path and enriches its source location.
func (d *DetectLine) DetectLineByPath(ctx context.Context, file *model.FileMetadata, path model.Path) model.VulnerabilityLines {
	lines, _ := d.DetectLineByPathWithResolution(ctx, file, path)
	return lines
}

func (d *DetectLine) DetectLineByPathWithResolution(
	ctx context.Context,
	file *model.FileMetadata,
	path model.Path,
) (model.VulnerabilityLines, PathResolution) {
	det, hasDet := d.detectors[file.Kind]
	if hasDet {
		if pathDetector, ok := det.(kindDetectPathLine); ok {
			_, resolution, _ := GetLineByPathWithResolution(path, file)
			return pathDetector.DetectLineByPath(ctx, file, path, d.outputLines), resolution
		}
	}

	lineNr, resolution, err := GetLineByPathWithResolution(path, file)
	empty := model.VulnerabilityLines{
		Line:         -1,
		VulnLines:    &[]model.CodeLine{},
		ResolvedFile: file.FilePath,
	}
	if err != nil || lineNr <= 0 {
		return empty, resolution
	}

	if hasDet {
		if refiner, ok := det.(kindRefinePathLine); ok {
			if refined := refiner.RefinePathLine(ctx, file, path, lineNr); refined > 0 {
				lineNr = refined
			}
		}
	}

	if enricher, ok := det.(kindEnrichLine); hasDet && ok {
		enriched := enricher.EnrichLine(ctx, file, lineNr, d.outputLines)
		if enriched.Line > 0 {
			return enriched, resolution
		}
	}

	if file.LinesOriginalData == nil || lineNr > len(*file.LinesOriginalData) {
		return model.VulnerabilityLines{
			Line:         lineNr,
			VulnLines:    &[]model.CodeLine{},
			ResolvedFile: file.FilePath,
			VulnerablilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: lineNr},
				End:   model.ResourceLine{Line: lineNr},
			},
		}, resolution
	}
	lines := *file.LinesOriginalData
	return model.VulnerabilityLines{
		Line:                  lineNr,
		VulnLines:             GetAdjacentVulnLines(lineNr-1, d.outputLines, lines),
		ResolvedFile:          file.FilePath,
		FileSource:            lines,
		LineWithVulnerability: strings.TrimSpace(lines[lineNr-1]),
		VulnerablilityLocation: model.ResourceLocation{
			Start: model.ResourceLine{Line: lineNr},
			End:   model.ResourceLine{Line: lineNr},
		},
	}, resolution
}
