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

	unchangedText := make([]string, len(file.Lines()))
	copy(unchangedText, file.Lines())

	// prepareDockerFileLines mutates this slice in place (multi-line continuation
	// rewriting). It must operate on a private copy.
	lines := make([]string, len(file.Lines()))
	copy(lines, file.Lines())

	// Instructions are case-insensitive while search keys spell them in
	// uppercase, so match against lines whose instruction is uppercased. The
	// reported line keeps its original spelling.
	matchLines := upperInstructions(prepareDockerFileLines(lines))

	start, end := model.ResourceLine{}, model.ResourceLine{}
	for _, key := range strings.Split(sKey, ".") {
		substr1, substr2 := detector.GenerateSubstrings(ctx, key, extractedString, lines, det.CurrentLine)

		det, start, end, _ = det.DetectCurrentLine(upperInstruction(substr1), substr2, 0, matchLines, model.KindDOCKER)

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

// dockerInstructions lists the Dockerfile instruction keywords.
var dockerInstructions = map[string]bool{
	"ADD": true, "ARG": true, "CMD": true, "COPY": true, "ENTRYPOINT": true, "ENV": true,
	"EXPOSE": true, "FROM": true, "HEALTHCHECK": true, "LABEL": true, "MAINTAINER": true,
	"ONBUILD": true, "RUN": true, "SHELL": true, "STOPSIGNAL": true, "USER": true,
	"VOLUME": true, "WORKDIR": true,
}

// upperInstruction uppercases the instruction keyword s starts with, if any.
func upperInstruction(s string) string {
	trimmed := strings.TrimLeft(s, " \t")
	word := trimmed
	if end := strings.IndexAny(trimmed, " \t"); end >= 0 {
		word = trimmed[:end]
	}
	upper := strings.ToUpper(word)
	if upper == word || !dockerInstructions[upper] {
		return s
	}
	return s[:len(s)-len(trimmed)] + upper + trimmed[len(word):]
}

func upperInstructions(lines []string) []string {
	upper := make([]string, len(lines))
	for i, line := range lines {
		upper[i] = upperInstruction(line)
	}
	return upper
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
