package model

import (
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

var topLevelAttributeRegex = regexp.MustCompile(`(?s)^["']?[A-Za-z_][\w-]*["']?\s*=\s*[^=\s]`)

func parseAlternatives(before string) []string {
	if strings.Contains(before, " or ") {
		parts := strings.Split(before, " or ")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			_, val := splitKeyValue(part)
			result = append(result, normalizeListItem(val))
		}
		return result
	}
	_, val := splitKeyValue(before)
	return []string{normalizeListItem(val)}
}

func normalizeListItem(val string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
		val = val[1 : len(val)-1]
		val = strings.TrimSpace(val)
	}
	if strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) {
		val = val[1 : len(val)-1]
	}
	return normalize(val)
}

// nolint:gocritic,unparam
func splitKeyValue(expr string) (string, string) {
	parts := strings.SplitN(expr, "=", 2)
	if len(parts) == 2 {
		return normalize(strings.TrimSpace(parts[0])), normalize(strings.TrimSpace(parts[1]))
	}
	return "", normalize(expr)
}

func isTopLevelAttribute(s string) bool {
	trimmed := strings.TrimSpace(s)
	if !topLevelAttributeRegex.MatchString(trimmed) {
		return false
	}
	return !isNonAssignmentExpression(trimmed)
}

func isNonAssignmentExpression(s string) bool {
	trimmed := strings.TrimSpace(s)
	if strings.Contains(trimmed, "==") {
		return true
	}
	for _, r := range trimmed {
		if r == '=' {
			return false
		}
		if r == ':' {
			return true
		}
	}
	return false
}

type lineScanState struct {
	inDouble, inSingle, inBlockComment bool
}

func (s *lineScanState) skipNonCode(line string, i int) (next int, skip, done bool) {
	if s.inBlockComment {
		return s.skipBlockComment(line, i)
	}
	if s.inDouble || s.inSingle {
		return s.skipQuoted(line, i)
	}
	return s.startNonCode(line, i)
}

func (s *lineScanState) skipBlockComment(line string, i int) (next int, skip, done bool) {
	if line[i] == '*' && i+1 < len(line) && line[i+1] == '/' {
		s.inBlockComment = false
		return i + 1, true, false
	}
	return i, true, false
}

func (s *lineScanState) skipQuoted(line string, i int) (next int, skip, done bool) {
	c := line[i]
	if c == '\\' && i+1 < len(line) {
		return i + 1, true, false
	}
	if (s.inDouble && c == '"') || (s.inSingle && c == '\'') {
		s.inDouble = false
		s.inSingle = false
	}
	return i, true, false
}

func (s *lineScanState) startNonCode(line string, i int) (next int, skip, done bool) {
	switch c := line[i]; {
	case c == '"':
		s.inDouble = true
		return i, true, false
	case c == '\'':
		s.inSingle = true
		return i, true, false
	case c == '#':
		return i, true, true
	case c == '/' && i+1 < len(line) && line[i+1] == '/':
		return i, true, true
	case c == '/' && i+1 < len(line) && line[i+1] == '*':
		s.inBlockComment = true
		return i + 1, true, false
	default:
		return i, false, false
	}
}

func structuralClosingBrace(line string) int {
	last := -1
	var state lineScanState
	for i := 0; i < len(line); i++ {
		next, skip, done := state.skipNonCode(line, i)
		if done {
			break
		}
		if skip {
			i = next
			continue
		}
		if line[i] == '}' {
			last = i
		}
	}
	return last
}

func lineIndent(fileLines []string, line int) string {
	if line < 1 || line > len(fileLines) {
		return ""
	}
	content := fileLines[line-1]
	return content[:len(content)-len(strings.TrimLeft(content, " \t"))]
}

func blockBodyIndent(fileLines []string, blockStartLine, blockEndLine int) string {
	headerIndent := lineIndent(fileLines, blockStartLine)
	start := max(blockStartLine+1, 1)
	end := min(blockEndLine, len(fileLines))
	for line := start; line <= end; line++ {
		trimmed := strings.TrimSpace(fileLines[line-1])
		if trimmed == "" || trimmed == "}" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		return lineIndent(fileLines, line)
	}
	return headerIndent + "  "
}

func determineActualBaseIndent(fileLines []string, startLine, blockStartLine int) string {
	if startLine == 0 {
		return ""
	}
	for i := startLine - 1; i >= blockStartLine-1; i-- {
		line := strings.TrimSpace(fileLines[i])
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		return fileLines[i][:len(fileLines[i])-len(strings.TrimLeft(fileLines[i], " \t"))]
	}
	return ""
}

func normalizeIndentation(input string, spacesPerTab int) string {
	lines := strings.Split(input, "\n")
	tabSpaces := strings.Repeat(" ", spacesPerTab)

	for i, line := range lines {
		line = strings.ReplaceAll(line, "\t", tabSpaces)
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `“`, `"`)
	s = strings.ReplaceAll(s, `”`, `"`)
	s = strings.Join(strings.Fields(s), " ")
	s = strings.Trim(s, `"`)
	return s
}

func isInsertingInsideNestedBlock(fileLines []string, startLocation model.SarifResourceLocation, blockStartLine, blockEndLine int) bool {
	if startLocation.Line <= blockStartLine || startLocation.Line >= blockEndLine {
		return false
	}

	if startLocation.Line-1 < 0 || startLocation.Line-1 >= len(fileLines) {
		return false
	}

	lineContent := strings.TrimSpace(fileLines[startLocation.Line-1])
	if lineContent == "" || lineContent == "}" {
		return false
	}

	for i := startLocation.Line - 2; i >= blockStartLine-1; i-- {
		if strings.Contains(fileLines[i], "{") {
			return true
		}
		trimmed := strings.TrimSpace(fileLines[i])
		if trimmed == "" {
			continue
		}
		if trimmed != "}" {
			break
		}
	}
	return false
}

// isUnparseableValue checks if a value is incomplete or cannot be meaningfully parsed
func isUnparseableValue(value string) bool {
	trimmed := strings.TrimSpace(value)

	// Case 1: Just an opening bracket (multiline array/object)
	if trimmed == "[" || trimmed == "{" {
		return true
	}

	// Case 2: Unclosed string (starts with quote but doesn't end with one)
	if (strings.HasPrefix(trimmed, `"`) && !strings.HasSuffix(trimmed, `"`)) ||
		(strings.HasSuffix(trimmed, `"`) && !strings.HasPrefix(trimmed, `"`)) {
		return true
	}

	// Case 3: Resource reference (contains terraform resource pattern like "aws_type.name" or "var.name")
	// Common patterns: aws_*, azurerm_*, google_*, var.*, data.*, module.*
	// Not tackled yet

	// Case 4: Empty or whitespace-only value
	if trimmed == "" {
		return true
	}

	return false
}
