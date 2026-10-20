/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package docker

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/command"
)

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

// normalizeSearchText prefers exact literal values (e.g. {{add user}} inside
// RUN), otherwise canonicalizing instruction spelling just as in the line view.
func normalizeSearchText(view *model.FileMetadata, text string) string {
	if text == "" {
		return text
	}
	if indexes, _ := view.LinesContaining(text); len(indexes) > 0 {
		return text
	}
	normalized := normalizeInstruction(text)
	if normalized == text {
		return text
	}
	indexes, _ := view.LinesContaining(normalized)
	lines := view.Lines()
	for _, index := range indexes {
		words, count := dockerInstructionWords(lines[index])
		for _, word := range words[:count] {
			if strings.HasPrefix(lines[index][word.start:], normalized) {
				return normalized
			}
		}
	}
	// A keyword-looking literal inside an argument must remain case-sensitive.
	return text
}

func dockerInstructionWords(line string) (words [3]instructionWord, count int) {
	pos, healthcheck := 0, false
	for count < len(words) {
		span := dockerWordAt(line, pos)
		word := strings.ToLower(line[span.start:span.end])
		if _, known := command.Commands[word]; !known && (!healthcheck || word != "none") {
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
	rest := strings.TrimLeft(line[pos:], " \t")
	start := len(line) - len(rest)
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		end = len(rest)
	}
	return instructionWord{start: start, end: start + end}
}
