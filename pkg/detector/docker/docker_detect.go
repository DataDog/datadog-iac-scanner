package docker

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/dockerfile"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// DetectKindLine defines a kindDetectLine type
type DetectKindLine struct {
}

const (
	undetectedVulnerabilityLine = -1
)

// DetectLine searches vulnerability line in docker files
func (d DetectKindLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	var extractedString [][]string
	extractedString = detector.GetBracketValues(searchKey, extractedString, "")
	sKey := searchKey
	for idx, str := range extractedString {
		sKey = strings.ReplaceAll(sKey, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}

	unchangedText := file.Lines()
	source := file.DetectionLines(dockerfile.SourceViewKey, dockerfile.InstructionLines)
	normalized := file.DetectionLines("docker.instructions", func(_ []string) []string {
		var lines []string
		for i, line := range source {
			normalized := normalizeInstruction(line)
			if normalized != line {
				if lines == nil {
					lines = slices.Clone(source)
				}
				lines[i] = normalized
			}
		}
		if lines == nil {
			return source
		}
		return lines
	})
	// When no transformation was needed, keep the original file's index and
	// avoid retaining a second FileMetadata and lazy cache for identical lines.
	match := file
	if len(normalized) > 0 && &normalized[0] != &unchangedText[0] {
		match = file.DetectionView("docker.instructions", func([]string) []string { return normalized })
	}
	lines := match.Lines()
	det := &detector.DefaultDetectLineResponse{
		File:          match,
		ResolvedFile:  file.FilePath,
		ResolvedFiles: make(map[string]model.ResolvedFileSplit),
	}
	start, end := model.ResourceLine{}, model.ResourceLine{}
	for _, key := range strings.Split(sKey, ".") {
		substr1, substr2 := detector.GenerateSubstrings(ctx, key, extractedString, lines, det.CurrentLine)
		substr1, substr2, det.AcceptLine = instructionSearch(match, substr1, substr2)
		det, start, end, _ = det.DetectCurrentLine(substr1, substr2, 0, lines, model.KindDOCKER)
		if det.IsBreak {
			break
		}
	}

	if det.FoundAtLeastOne {
		return model.VulnerabilityLines{
			Line:                  det.CurrentLine + 1,
			LineWithVulnerability: source[det.CurrentLine],
			VulnLines:             detector.GetAdjacentVulnLines(det.CurrentLine, outputLines, unchangedText),
			ResolvedFile:          file.FilePath,
			VulnerablilityLocation: model.ResourceLocation{
				Start: start,
				End:   end,
			},
		}
	}

	return model.VulnerabilityLines{
		Line:                  undetectedVulnerabilityLine,
		VulnLines:             &[]model.CodeLine{},
		LineWithVulnerability: "",
		ResolvedFile:          file.FilePath,
	}
}
