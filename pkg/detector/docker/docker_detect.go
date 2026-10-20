package docker

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
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
	source := file.DetectionLines("docker.source", func(original []string) []string {
		// The engine releases Document before evaluation, but loads line info
		// under its lock before invoking a detector. Direct callers may instead
		// supply the original parsed document.
		document := file.LineInfoDocument
		if document == nil {
			document = file.Document
		}
		return prepareInstructionLines(original, document)
	})
	match := file.DetectionView("docker.instructions", func(_ []string) []string {
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
	lines := match.Lines()
	det := &detector.DefaultDetectLineResponse{
		File:          match,
		ResolvedFile:  file.FilePath,
		ResolvedFiles: make(map[string]model.ResolvedFileSplit),
	}
	start, end := model.ResourceLine{}, model.ResourceLine{}
	for _, key := range strings.Split(sKey, ".") {
		substr1, substr2 := detector.GenerateSubstrings(ctx, key, extractedString, lines, det.CurrentLine)
		substr1 = normalizeSearchText(match, substr1)
		// Only ONBUILD/HEALTHCHECK values can begin with a nested instruction.
		// Other values, even keyword-looking ones, retain their literal case.
		if strings.EqualFold(substr1, command.Onbuild) || strings.EqualFold(substr1, command.Healthcheck) {
			substr2 = normalizeSearchText(match, substr2)
		}
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

// prepareInstructionLines uses BuildKit's logical instruction text, retaining
// physical start-line offsets while excluding continuations and heredoc payloads.
// Prefer already-loaded line-info metadata to parsing again for each finding.
func prepareInstructionLines(original []string, document model.Document) []string {
	lines := make([]string, len(original))
	if documentInstructionLines(document, lines) {
		return lines
	}
	clear(lines)
	parsed, err := parser.Parse(strings.NewReader(strings.Join(original, "\n")))
	if err != nil {
		return original
	}
	for _, node := range parsed.AST.Children {
		lines[node.StartLine-1] = node.Original
	}
	return lines
}

func documentInstructionLines(document model.Document, lines []string) bool {
	stages, ok := document["command"].(map[string]interface{})
	if !ok {
		return false
	}
	for _, commands := range stages {
		if !copyInstructionLines(commands, lines) {
			return false
		}
	}
	if args := document["args"]; args != nil {
		return copyInstructionLines(args, lines)
	}
	return true
}

func copyInstructionLines(value interface{}, lines []string) bool {
	commands, ok := value.([]interface{})
	if !ok {
		return false
	}
	for _, value := range commands {
		cmd, ok := value.(map[string]interface{})
		if !ok {
			return false
		}
		line, ok := cmd["_dd_line"].(float64)
		if !ok || line < 1 || line > float64(len(lines)) || line != float64(int(line)) {
			return false
		}
		original, ok := cmd["Original"].(string)
		if !ok || original == "" {
			return false
		}
		lines[int(line)-1] = original
	}
	return true
}
