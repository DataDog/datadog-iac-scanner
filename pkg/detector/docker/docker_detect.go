package docker

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// DetectKindLine defines a kindDetectLine type
type DetectKindLine struct {
}

const (
	undetectedVulnerabilityLine = -1
)

var (
	nameRegexDockerFileML = regexp.MustCompile(`.+\s+\\$`)
	commentRegex          = regexp.MustCompile(`^\s*#.*`)
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
	lines := file.DetectionLines(func(original []string) []string {
		// The engine releases Document before evaluation, but loads line info
		// under its lock before invoking a detector. Direct callers may instead
		// supply the original parsed document.
		document := file.LineInfoDocument
		if document == nil {
			document = file.Document
		}
		return prepareInstructionLines(original, document)
	})
	det := &detector.DefaultDetectLineResponse{
		ResolvedFile:  file.FilePath,
		ResolvedFiles: make(map[string]model.ResolvedFileSplit),
	}
	start, end := model.ResourceLine{}, model.ResourceLine{}
	for _, key := range strings.Split(sKey, ".") {
		substr1, substr2 := detector.GenerateSubstrings(ctx, key, extractedString, lines, det.CurrentLine)
		det, start, end, _ = det.DetectCurrentLine(substr1, substr2, 0, lines, model.KindDOCKER)
		if det.IsBreak {
			break
		}
	}

	if det.FoundAtLeastOne {
		return model.VulnerabilityLines{
			Line:                  det.CurrentLine + 1,
			LineWithVulnerability: lines[det.CurrentLine],
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

// prepareInstructionLines keeps only actual instruction starts searchable.
// Parsed documents already carry source locations. BuildKit supplies the same
// heredoc/continuation boundaries for callers without that metadata.
func prepareInstructionLines(original []string, document model.Document) []string {
	lines := prepareDockerFileLines(slices.Clone(original))
	starts := make([]bool, len(lines))
	if !documentInstructionStarts(document, starts) {
		clear(starts)
		parsed, err := parser.Parse(strings.NewReader(strings.Join(original, "\n")))
		if err != nil {
			return lines
		}
		for _, node := range parsed.AST.Children {
			starts[node.StartLine-1] = true
		}
	}
	for i := range lines {
		if !starts[i] {
			lines[i] = ""
		}
	}
	return lines
}

func documentInstructionStarts(document model.Document, starts []bool) bool {
	stages, ok := document["command"].(map[string]interface{})
	if !ok {
		return false
	}
	for _, commands := range stages {
		if !markInstructionStarts(commands, starts) {
			return false
		}
	}
	if args := document["args"]; args != nil {
		return markInstructionStarts(args, starts)
	}
	return true
}

func markInstructionStarts(value interface{}, starts []bool) bool {
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
		if !ok || line < 1 || line > float64(len(starts)) || line != float64(int(line)) {
			return false
		}
		starts[int(line)-1] = true
	}
	return true
}

func prepareDockerFileLines(text []string) []string {
	for idx, key := range text {
		if !commentRegex.MatchString(key) {
			text[idx] = multiLineSpliter(text, key, idx)
		}
	}
	return text
}

func multiLineSpliter(textSplit []string, key string, idx int) string {
	if !nameRegexDockerFileML.MatchString(key) {
		return textSplit[idx]
	}

	i := idx + 1
	for i < len(textSplit) && textSplit[i] == "" {
		i++
	}
	if i >= len(textSplit) {
		return textSplit[idx]
	}

	var b strings.Builder
	line := textSplit[idx]
	b.WriteString(line[:len(line)-1])

	for {
		next := textSplit[i]
		if commentRegex.MatchString(next) {
			next += " \\"
		}
		if nameRegexDockerFileML.MatchString(next) {
			b.WriteString(next[:len(next)-1])
		} else {
			b.WriteString(next)
		}
		textSplit[i] = ""
		if !nameRegexDockerFileML.MatchString(next) {
			break
		}
		i++
		for i < len(textSplit) && textSplit[i] == "" {
			i++
		}
		if i >= len(textSplit) {
			break
		}
	}

	result := b.String()
	textSplit[idx] = result
	return result
}
