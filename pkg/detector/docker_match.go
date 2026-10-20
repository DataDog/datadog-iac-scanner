/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
)

type instructionWord struct {
	start, end int
}

// dockerMatchText preserves literal values, folding case only at instruction
// keyword positions. In particular, RUN arguments are always case-sensitive.
func dockerMatchText(line, text string) string {
	if text == "" || strings.Contains(line, text) {
		return text
	}
	words, count := dockerInstructionWords(line)
	for i := 0; i < count; i++ {
		start := words[i].start
		end := start + len(text)
		if end > len(line) || end < words[i].end {
			continue
		}
		pos, matches := start, true
		for j := i; j < count && words[j].start < end; j++ {
			word := words[j]
			if word.end > end || line[pos:word.start] != text[pos-start:word.start-start] ||
				!strings.EqualFold(line[word.start:word.end], text[word.start-start:word.end-start]) {
				matches = false
				break
			}
			pos = word.end
		}
		if matches && line[pos:end] == text[pos-start:] {
			return line[start:end]
		}
	}
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
