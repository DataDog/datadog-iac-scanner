package docker

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
	splitRegex            = regexp.MustCompile(`\s\\`)
)

// DetectLine searches vulnerability line in docker files
func (d DetectKindLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	det := &detector.DefaultDetectLineResponse{
		CurrentLine:     0,
		IsBreak:         false,
		FoundAtLeastOne: false,
		ResolvedFile:    file.FilePath,
		ResolvedFiles:   make(map[string]model.ResolvedFileSplit),
	}

	var extractedString [][]string
	extractedString = detector.GetBracketValues(searchKey, extractedString, "")
	sKey := searchKey
	for idx, str := range extractedString {
		sKey = strings.ReplaceAll(sKey, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}

	unchangedText := make([]string, len(*file.LinesOriginalData))
	copy(unchangedText, *file.LinesOriginalData)

	lines := *file.LinesOriginalData

	start, end := model.ResourceLine{}, model.ResourceLine{}
	for _, key := range strings.Split(sKey, ".") {
		substr1, substr2 := detector.GenerateSubstrings(ctx, key, extractedString, lines, det.CurrentLine)

		det, start, end, _ = det.DetectCurrentLine(substr1, substr2, 0, prepareDockerFileLines(lines), model.KindDOCKER)

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

func prepareDockerFileLines(text []string) []string {
	for idx, key := range text {
		if !commentRegex.MatchString(key) {
			text[idx] = multiLineSpliter(text, key, idx)
		}
	}
	return text
}

func multiLineSpliter(textSplit []string, key string, idx int) string {
	if nameRegexDockerFileML.MatchString(key) {
		i := idx + 1
		if i >= len(textSplit) {
			return textSplit[idx]
		}
		for textSplit[i] == "" {
			i++
			if i >= len(textSplit) {
				return textSplit[idx]
			}
		}
		if commentRegex.MatchString(textSplit[i]) {
			textSplit[i] += " \\"
		}
		textSplit[idx] = splitRegex.ReplaceAllLiteralString(textSplit[idx], " "+textSplit[i])
		textSplit[i] = ""
		textSplit[idx] = multiLineSpliter(textSplit, textSplit[idx], idx)
	}
	return textSplit[idx]
}
