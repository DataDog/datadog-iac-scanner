/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package docker

import (
	"strings"
	"unicode"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/command"
)

const healthcheckNone = "none"

type instructionWord struct {
	start, end int
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

// normalizeSearchText prefers instruction boundaries to occurrences inside
// arguments. With no instruction match, keyword-looking literals keep their case.
func normalizeSearchText(view *model.FileMetadata, text string) (string, bool) {
	if text == "" {
		return text, false
	}
	normalized := normalizeInstruction(text)
	indexes, indexed := view.LinesContaining(normalized)
	lines := view.Lines()
	if !indexed {
		for _, line := range lines {
			if startsAtInstruction(line, normalized) {
				return normalized, true
			}
		}
		return text, false
	}
	for _, index := range indexes {
		if startsAtInstruction(lines[index], normalized) {
			return normalized, true
		}
	}
	return text, false
}

func startsAtInstruction(line, text string) bool {
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

// instructionSearch applies keyword normalization only at instruction boundaries.
// Nested keywords have the same rule; ordinary argument values remain literal.
func instructionSearch(view *model.FileMetadata, first, second string) (
	str1, str2 string, accept func(int, string) bool) {
	first, instruction := normalizeSearchText(view, first)
	nested := false
	if strings.EqualFold(first, command.Onbuild) || strings.EqualFold(first, command.Healthcheck) {
		second, nested = normalizeSearchText(view, second)
	}
	if !instruction && !nested {
		return first, second, nil
	}
	return first, second, func(_ int, line string) bool {
		return (!instruction || startsAtInstruction(line, first)) && (!nested || startsAtInstruction(line, second))
	}
}

func stageStartLines(view *model.FileMetadata) []int {
	return view.LinesMatching("docker.stages", isFromInstruction)
}
