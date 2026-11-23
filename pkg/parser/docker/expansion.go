package docker

import (
	"regexp"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

var unbracedReference = regexp.MustCompile(`^\$(?:\p{Nd}+|[\p{L}_][\p{L}\p{Nd}_]*|[-@*#?$!])`)

func expandWord(value string, variables dockerfileVariables, lexer *shell.Lex) string {
	expanded, _, err := lexer.ProcessWord(value, variables)
	if err != nil {
		return value
	}
	return expanded
}

func expandCommandWord(value string, variables dockerfileVariables, lexer *shell.Lex, escape byte) string {
	expanded, _, err := lexer.ProcessWord(value, variables)
	if err == nil {
		return expanded
	}

	// Let BuildKit expand each independent reference when another part of the
	// command uses syntax it does not understand.
	var result strings.Builder
	result.Grow(len(value))
	inDoubleQuotes := false
	for value != "" {
		size := 1
		switch value[0] {
		case escape:
			size = min(2, len(value))
		case '"':
			inDoubleQuotes = !inDoubleQuotes
		case '\'':
			if !inDoubleQuotes {
				size = quotedLength(value, escape)
			}
		case '$':
			size = referenceLength(value, escape)
		}
		part := value[:size]
		if part[0] == '$' {
			part = expandWord(part, variables, lexer)
		}
		result.WriteString(part)
		value = value[size:]
	}
	return result.String()
}

func referenceLength(value string, escape byte) int {
	if !strings.HasPrefix(value, "${") {
		return max(1, len(unbracedReference.FindString(value)))
	}

	depth := 1
	for i := 2; i < len(value); i++ {
		switch value[i] {
		case escape:
			i++
		case '\'', '"':
			i += quotedLength(value[i:], escape) - 1
		case '$':
			if strings.HasPrefix(value[i:], "${") {
				depth++
				i++
			}
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	// Keep a braced reference with no closing delimiter intact.
	return len(value)
}

func quotedLength(value string, escape byte) int {
	quote := value[0]
	for i := 1; i < len(value); i++ {
		if value[i] == quote {
			return i + 1
		}
		if quote == '"' && value[i] == escape {
			i++
		}
	}
	// An unmatched quote is literal when recovering a command.
	return 1
}
