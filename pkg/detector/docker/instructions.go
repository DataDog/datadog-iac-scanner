/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package docker

import (
	"slices"
	"strings"
	"unicode"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/command"
	buildkit "github.com/moby/buildkit/frontend/dockerfile/parser"
)

const (
	sourceViewKey   = "docker.source"
	healthcheckNone = "none"
)

type instructionWord struct {
	start, end int
}

// instructionLines builds a physically indexed logical instruction view using
// BuildKit, which joins continuations (honoring `# escape=`), masks comments
// and blank lines, and excludes heredoc payloads from node.Original.
func instructionLines(original []string) []string {
	parsed, err := buildkit.Parse(strings.NewReader(strings.Join(original, "\n")))
	if err != nil {
		return original
	}
	var lines []string
	child := 0
	children := parsed.AST.Children
	for i, physical := range original {
		lineNum := i + 1
		for child < len(children) && children[child].StartLine < lineNum {
			child++
		}
		text := ""
		if child < len(children) && children[child].StartLine == lineNum {
			logical := strings.ReplaceAll(children[child].Original, "\r", "")
			cleanPhysical := strings.ReplaceAll(physical, "\r", "")
			// If BuildKit's complete instruction already occurs verbatim on its
			// first source line, retain that line's indentation, trailing
			// whitespace, and EOF escape. Joined instructions use BuildKit's
			// logical text; a leading BOM is parser metadata and stays stripped.
			if strings.Contains(cleanPhysical, logical) && !strings.HasPrefix(cleanPhysical, "\ufeff") {
				text = cleanPhysical
			} else {
				text = logical
			}
		}
		if text != physical && lines == nil {
			lines = slices.Clone(original)
		}
		if lines != nil {
			lines[i] = text
		}
	}
	if lines == nil {
		return original
	}
	return lines
}

// fromArguments returns the raw arguments of a FROM instruction, including
// flags and an optional alias. Non-instructions and keyword prefixes return "".
func fromArguments(original string) string {
	original = strings.TrimSpace(original)
	end := strings.IndexAny(original, " \t\r\n\v\f")
	if end < 0 || !strings.EqualFold(original[:end], command.From) {
		return ""
	}
	return strings.TrimSpace(original[end:])
}

func isFromInstruction(line string) bool {
	word := dockerWordAt(line, 0)
	return strings.EqualFold(line[word.start:word.end], command.From)
}

// normalizeInstruction uppercases only instruction keywords, including nested
// ONBUILD and HEALTHCHECK keywords. Argument bytes and offsets stay unchanged.
func normalizeInstruction(line string) string {
	words, count := dockerInstructionWords(line)
	var result strings.Builder
	pos := 0
	for _, word := range words[:count] {
		keyword := line[word.start:word.end]
		upper := strings.ToUpper(keyword)
		if upper == keyword {
			continue
		}
		result.WriteString(line[pos:word.start])
		result.WriteString(upper)
		pos = word.end
	}
	if pos == 0 {
		return line
	}
	result.WriteString(line[pos:])
	return result.String()
}

func startsAtInstruction(line, text string) bool {
	if text == "" {
		return false
	}
	words, count := dockerInstructionWords(line)
	for _, word := range words[:count] {
		if strings.HasPrefix(line[word.start:], text) {
			return true
		}
	}
	return false
}

// Normalized source lines already contain uppercase keywords. Derive their
// canonical names from BuildKit once instead of allocating lowercase strings
// for every candidate and every finding. Mixed-case search keys use the fallback.
var normalizedCommands = func() map[string]string {
	names := make(map[string]string, len(command.Commands)+1)
	for name := range command.Commands {
		names[strings.ToUpper(name)] = name
	}
	names["NONE"] = healthcheckNone
	return names
}()

func instructionName(word string) string {
	if name, ok := normalizedCommands[word]; ok {
		return name
	}
	return strings.ToLower(word)
}

func dockerInstructionWords(line string) (words [3]instructionWord, count int) {
	pos, healthcheck := 0, false
	for count < len(words) {
		span := dockerWordAt(line, pos)
		word := instructionName(line[span.start:span.end])
		if _, known := command.Commands[word]; !known && (!healthcheck || word != healthcheckNone) {
			break
		}
		words[count] = span
		count++
		pos = span.end
		switch word {
		case command.Onbuild:
			continue
		case command.Healthcheck:
			healthcheck = true
			// Flags precede the nested CMD, and their spelling stays literal.
			span = dockerWordAt(line, pos)
			for strings.HasPrefix(line[span.start:span.end], "--") {
				span = dockerWordAt(line, span.end)
			}
			pos = span.start
		default:
			return words, count
		}
	}
	return words, count
}

func dockerWordAt(line string, pos int) instructionWord {
	rest := strings.TrimLeftFunc(line[pos:], unicode.IsSpace)
	start := len(line) - len(rest)
	end := strings.IndexAny(rest, " \t\r\n\v\f")
	if end < 0 {
		end = len(strings.TrimRightFunc(rest, unicode.IsSpace))
	}
	return instructionWord{start: start, end: start + end}
}

func stageStartLines(view *model.FileMetadata) []int {
	return view.LinesMatching("docker.stages", isFromInstruction)
}
