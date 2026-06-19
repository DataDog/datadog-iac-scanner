/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package detector

import (
	"context"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const (
	undetectedVulnerabilityLine = -1
)

type defaultDetectLine struct {
}

// DetectLine searches vulnerability line if kindDetectLine is not in detectors
func (d defaultDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)
	detector := &DefaultDetectLineResponse{
		CurrentLine:     0,
		IsBreak:         false,
		FoundAtLeastOne: false,
		ResolvedFile:    file.FilePath,
		ResolvedFiles:   d.prepareResolvedFiles(file.ResolvedFiles),
	}

	var extractedString [][]string
	extractedString = GetBracketValues(searchKey, extractedString, "")
	sanitizedSubstring := searchKey
	for idx, str := range extractedString {
		sanitizedSubstring = strings.ReplaceAll(sanitizedSubstring, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}

	lines := *file.LinesOriginalData
	splitSanitized := strings.Split(sanitizedSubstring, ".")

	// Re-join $ref segments split by dot (e.g. "$ref=#/schemas/v1.0.Foo" → ["v1","0","Foo"])
	// before the numeric-index check runs.
	for index, split := range splitSanitized {
		if strings.Contains(split, "$ref") {
			splitSanitized[index] = strings.Join(splitSanitized[index:], ".")
			splitSanitized = splitSanitized[:index+1]
			break
		}
	}

	// Numeric segments (e.g. "0" in "rules.0.apiGroups") have no literal text in the
	// source file, so the text-matcher cannot advance through them. handleArrayIndex
	// tries a structured gjson lookup first; on failure it strips numerics and falls
	// back to the text-matcher.
	if result, remaining := handleArrayIndex(splitSanitized, extractedString, file, detector.ResolvedFile, outputLines, lines); result != nil {
		return *result
	} else if remaining != nil {
		splitSanitized = remaining
	}

	start, end := model.ResourceLine{}, model.ResourceLine{}
	for _, key := range splitSanitized {
		substr1, substr2 := GenerateSubstrings(ctx, key, extractedString, lines, detector.CurrentLine)

		// BICEP-specific tweaks in order to make bicep files compatible with ARM queries
		if file.Kind == "BICEP" {
			substr1 = strings.ReplaceAll(substr1, "resources", "resource")
			substr1 = strings.ReplaceAll(substr1, "parameters", "param")
			substr1 = strings.ReplaceAll(substr1, "variables", "variable")
		}
		detector, start, end, lines = detector.DetectCurrentLine(substr1, substr2, 0, lines, file.Kind)

		if detector.IsBreak {
			break
		}
	}

	if detector.FoundAtLeastOne {
		return model.VulnerabilityLines{
			Line:         detector.CurrentLine + 1,
			VulnLines:    GetAdjacentVulnLines(detector.CurrentLine, outputLines, lines),
			ResolvedFile: detector.ResolvedFile,
			VulnerablilityLocation: model.ResourceLocation{
				Start: start,
				End:   end,
			},
		}
	}

	var filePathSplit = strings.Split(file.FilePath, "/")
	contextLogger.Warn().Msgf("Failed to detect line associated with identified result in file %s", filePathSplit[len(filePathSplit)-1])

	return model.VulnerabilityLines{
		Line:         undetectedVulnerabilityLine,
		VulnLines:    &[]model.CodeLine{},
		ResolvedFile: detector.ResolvedFile,
	}
}

// handleArrayIndex handles paths that contain numeric segments. It first attempts a
// structured gjson lookup (precise, handles array indices and numeric map keys). On
// failure it strips numerics and returns the remainder for the text-matcher fallback.
// Returns (nil, nil) when no numeric segment is present.
func handleArrayIndex(
	splitSanitized []string,
	extractedString [][]string,
	file *model.FileMetadata,
	resolvedFile string,
	outputLines int,
	lines []string,
) (result *model.VulnerabilityLines, remaining []string) {
	hasNumeric := false
	for _, seg := range splitSanitized {
		if _, err := strconv.Atoi(seg); err == nil {
			hasNumeric = true
			break
		}
	}
	if !hasNumeric {
		return nil, nil
	}

	// Strip value anchors (key=value → key) so gjson receives a pure key path.
	// Paths with mid-path anchors (e.g. "meta.name={{pod}}.spec...") resolve to a
	// nonexistent gjson path and return -1, falling through to the text-matcher.
	structPath := extractStructuralPath(splitSanitized, extractedString)
	if lineNr, err := GetLineBySearchLine(structPath, file); err == nil && lineNr > 0 && lineNr <= len(lines) {
		result := model.VulnerabilityLines{
			Line:         lineNr,
			VulnLines:    GetAdjacentVulnLines(lineNr-1, outputLines, lines),
			ResolvedFile: resolvedFile,
			VulnerablilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: lineNr},
				End:   model.ResourceLine{Line: lineNr},
			},
		}
		return &result, nil
	}

	filtered := splitSanitized[:0]
	for _, s := range splitSanitized {
		if _, err := strconv.Atoi(s); err != nil {
			filtered = append(filtered, s)
		}
	}
	return nil, filtered
}

// extractStructuralPath converts a sanitized segment list into a plain key path for
// GetLineBySearchLine: resolves {{N}} placeholders, strips value anchors (key=value →
// key), and preserves numeric indices.
func extractStructuralPath(segments []string, extracted [][]string) []string {
	result := make([]string, 0, len(segments))
	for _, seg := range segments {
		for i, ext := range extracted {
			seg = strings.ReplaceAll(seg, `{{`+strconv.Itoa(i)+`}}`, ext[1])
		}
		if idx := strings.Index(seg, "="); idx >= 0 {
			seg = seg[:idx]
		}
		if seg != "" {
			result = append(result, seg)
		}
	}
	return result
}

func (d defaultDetectLine) prepareResolvedFiles(resFiles map[string]model.ResolvedFile) map[string]model.ResolvedFileSplit {
	resolvedFiles := make(map[string]model.ResolvedFileSplit)
	for f, res := range resFiles {
		resolvedFiles[f] = model.ResolvedFileSplit{
			Path:  res.Path,
			Lines: *res.LinesContent,
		}
	}
	return resolvedFiles
}
