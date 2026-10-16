/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"regexp"
	"strings"
)

// suppressionDirective matches a comment line that starts a dd-iac-scan
// command, as opposed to one that only mentions the scanner.
var suppressionDirective = regexp.MustCompile(`(?i)^(?://|#|;)*\s*dd-iac-scan\s+(ignore|disable|enable)`)

// blockScalarStart matches the end of a line that opens a block scalar.
var blockScalarStart = regexp.MustCompile(`(^|[:\-])\s*[|>][+\-0-9]*\s*(#.*)?$`)

// blankPlainComments blanks the blocks of comment lines that hold no
// dd-iac-scan command, keeping the line numbers. The parser marks the lines
// above the node that follows an ordinary comment as ignored, taking them for
// the comment's own, but in a template the lines between the comment and the
// node may be actions, blanked for the parse: a finding on an include would be
// suppressed by an unrelated comment above it. Lines that are part of a
// multiline scalar are not comments and are left alone.
func blankPlainComments(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	scalar := scalarLines(lines)
	isComment := func(i int) bool {
		return !scalar[i] && strings.HasPrefix(strings.TrimSpace(lines[i]), "#")
	}
	for start := 0; start < len(lines); {
		if !isComment(start) {
			start++
			continue
		}
		end, command := start, false
		for ; end < len(lines) && isComment(end); end++ {
			command = command || suppressionDirective.MatchString(strings.TrimSpace(lines[end]))
		}
		if !command {
			for i := start; i < end; i++ {
				lines[i] = ""
			}
		}
		start = end
	}
	return []byte(strings.Join(lines, "\n"))
}

// scalarLines reports, for each line, whether it continues a scalar opened on
// an earlier line: a block scalar, or a quoted scalar left open at the end of
// a line. Its text may start with '#' without being a comment.
func scalarLines(lines []string) []bool {
	inScalar := make([]bool, len(lines))
	var quote byte
	blockIndent := -1
	for i, line := range lines {
		if quote != 0 {
			inScalar[i] = true
			rest, closed := afterClosingQuote(line, quote)
			if !closed {
				continue
			}
			line = rest
		} else if blockIndent >= 0 {
			if strings.TrimSpace(line) == "" || indentOf(line) > blockIndent {
				inScalar[i] = true
				continue
			}
			blockIndent = -1
		}
		var opened bool
		quote, opened = scanLine(line)
		if quote == 0 && opened {
			blockIndent = indentOf(line)
		}
	}
	return inScalar
}

// scanLine walks one line outside any scalar. It returns the quote left open
// at its end, and whether the line opens a block scalar.
func scanLine(line string) (quote byte, blockScalar bool) {
	code := line
	for j := 0; j < len(line); j++ {
		switch c := line[j]; {
		case c == '#' && (j == 0 || line[j-1] == ' ' || line[j-1] == '\t'):
			code = line[:j]
			j = len(line)
		case (c == '"' || c == '\'') && opensScalar(line[:j]):
			rest, closed := afterClosingQuote(line[j+1:], c)
			if !closed {
				return c, false
			}
			j = len(line) - len(rest) - 1
		}
	}
	return 0, blockScalarStart.MatchString(strings.TrimRight(code, " \t\r"))
}

// opensScalar reports whether a quote after before starts a quoted scalar,
// rather than being a character of a plain one.
func opensScalar(before string) bool {
	before = strings.TrimRight(before, " \t")
	if before == "" {
		return true
	}
	switch before[len(before)-1] {
	case ':', '-', ',', '[', '{', '?':
		return true
	}
	return false
}

// afterClosingQuote returns the text after the quote closing a scalar quoted
// with quote, and whether the line closes it. A double-quoted scalar escapes a
// quote with a backslash, a single-quoted one by doubling it.
func afterClosingQuote(line string, quote byte) (string, bool) {
	for j := 0; j < len(line); j++ {
		switch {
		case quote == '"' && line[j] == '\\':
			j++
		case line[j] == quote && quote == '\'' && j+1 < len(line) && line[j+1] == quote:
			j++
		case line[j] == quote:
			return line[j+1:], true
		}
	}
	return "", false
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}
