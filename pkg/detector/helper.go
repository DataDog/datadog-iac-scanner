/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/agnivade/levenshtein"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

var (
	nameRegex          = regexp.MustCompile(`^([A-Za-z\d-_]+)\[([A-Za-z\d-_{}]+)]$`)
	nameRegexDocker    = regexp.MustCompile(`{{(.*?)}}`)
	indentRegex        = regexp.MustCompile(`^\s+`)
	whitespacesRegex   = regexp.MustCompile(`\s+`)
	yamlMultilineRegex = regexp.MustCompile(
		`(?m)^[ \t]*-?[ \t]*[^:\n#][^:\n]*:\s*(?:[|>](?:[+-]?\d+|\d+[+-]?|[+-])?|\\)\s*(?:#.*)?$`,
	)
)

const (
	namePartsLength  = 3
	valuePartsLength = 2
)

// DefaultDetectLineResponse is the default response for struct DetectLine
type DefaultDetectLineResponse struct {
	CurrentLine     int
	IsBreak         bool
	FoundAtLeastOne bool
	ResolvedFile    string
	ResolvedFiles   map[string]model.ResolvedFileSplit
}

// GetBracketValues gets values inside "{{ }}" ignoring any "{{" or "}}" inside
func GetBracketValues(expr string, list [][]string, restOfString string) [][]string {
	s := expr + restOfString

	depth := 0
	simpleDepth := 0
	open := -1  // index of the first '{' in the outermost `{{`
	start := -1 // inner start = open + 2

	for i := 0; i < len(s)-1; i++ {
		switch s[i] {
		case '{':
			if s[i+1] == '{' {
				if depth == 0 && simpleDepth == 0 {
					open = i
					start = i + 2
				}
				depth++
				i++ // skip the second '{'
			} else {
				simpleDepth++
			}

		case '}':
			if s[i+1] == '}' {
				if depth > 0 && simpleDepth == 0 {
					depth--
					if depth == 0 && open >= 0 && start >= 0 {
						full := s[open : i+2]
						inner := s[start:i]
						list = append(list, []string{full, inner})
						open, start = -1, -1
					}
					i++ // skip the second '}'
				} else if simpleDepth > 0 {
					simpleDepth--
				}
			} else {
				simpleDepth--
			}
		}
	}

	if len(list) == 0 {
		list = append(list, []string{fmt.Sprintf("{{%s}}", s), s})
	}

	return list
}

// GenerateSubstrings returns the substrings used for line searching depending on search key
// '.' is new line
// '=' is value in the same line
// '[]' is in the same line
// nolint:gocritic
func GenerateSubstrings(ctx context.Context, key string, extracted [][]string, lines []string, currentLine int) (string, string) {
	var substr1, substr2 string
	if parts := nameRegex.FindStringSubmatch(key); len(parts) == namePartsLength {
		substr1, substr2 = getKeyWithCurlyBrackets(ctx, key, extracted, parts)
	} else if parts := strings.Split(key, "="); len(parts) == valuePartsLength {
		substr1, substr2 = getKeyWithCurlyBrackets(ctx, key, extracted, parts)
	} else {
		parts := []string{key, ""}
		substr1, substr2 = getKeyWithCurlyBrackets(ctx, key, extracted, parts)
	}

	return substr1, substr2
}

func getKeyWithCurlyBrackets(ctx context.Context, key string, extractedString [][]string, parts []string) (substr1Res, substr2Res string) {
	contextLogger := logger.FromContext(ctx)
	var substr1, substr2 string
	extractedPart := nameRegexDocker.FindStringSubmatch(key)
	if len(extractedPart) == valuePartsLength {
		for idx, key := range parts {
			if extractedPart[0] == key {
				switch idx {
				case len(parts) - 2:
					i, err := strconv.Atoi(extractedPart[1])
					if err != nil {
						contextLogger.Error().Msgf("failed to extract curly brackets substring")
					}
					if len(extractedString) > i {
						if extractedString[i][1] != "" {
							substr1 = extractedString[i][1]
						}
					}
				case len(parts) - 1:
					i, err := strconv.Atoi(extractedPart[1])
					if err != nil {
						contextLogger.Error().Msgf("failed to extract curly brackets substring")
					}
					if len(extractedString) > i {
						if extractedString[i][1] != "" {
							substr2 = extractedString[i][1]
						}
					}
				}
			} else {
				substr1 = generateSubstr(substr1, parts, valuePartsLength)
				substr2 = generateSubstr(substr2, parts, 1)
			}
		}
	} else if len(parts) >= 2 {
		substr1 = parts[len(parts)-2]
		substr2 = parts[len(parts)-1]
	}

	return substr1, substr2
}

func generateSubstr(substr string, parts []string, length int) string {
	if substr == "" {
		substr = parts[len(parts)-length]
	}
	return substr
}

// GetAdjacentVulnLines is used to get the lines adjacent to the line that contains the vulnerability
// adj is the amount of lines wanted
func GetAdjacentVulnLines(idx, adj int, lines []string) *[]model.CodeLine {
	var endPos int
	var startPos int
	if adj <= len(lines) {
		endPos = idx + adj/2 + 1 // if adj lines passes the number of lines in file
		if len(lines) < endPos {
			endPos = len(lines)
		}
		startAdj := adj
		if adj%2 == 0 {
			startAdj--
		}

		startPos = idx - startAdj/2 // if adj lines passes the first line in the file
		if startPos < 0 {
			startPos = 0
		}
	} else { // in case adj is bigger than number of lines in file
		adj = len(lines)
		endPos = len(lines)
		startPos = 0
	}

	switch idx {
	case 0:
		// case vulnerability is the first line of the file
		return createVulnLines(1, lines[:adj])
	case len(lines) - 1:
		// case vulnerability is the last line of the file
		return createVulnLines(len(lines)-adj+1, lines[len(lines)-adj:])
	default:
		// case vulnerability is in the middle of the file
		return createVulnLines(startPos+1, lines[startPos:endPos])
	}
}

// createVulnLines is the function that will  generate the array that contains the lines numbers
// used to alter the color of the line that contains the vulnerability
func createVulnLines(startPos int, lines []string) *[]model.CodeLine {
	vulns := make([]model.CodeLine, len(lines))
	for idx, line := range lines {
		vulns[idx] = model.CodeLine{
			Line:     line,
			Position: startPos,
		}
		startPos++
	}
	return &vulns
}

// SelectLineWithMinimumDistance will search a map of levenshtein distances to find the minimum distance
func SelectLineWithMinimumDistance(distances map[int]int, startingFrom int) int {
	minDistance, lineOfMinDistance := constants.MaxInteger, startingFrom
	for line, distance := range distances {
		if distance < minDistance || distance == minDistance && line < lineOfMinDistance {
			minDistance = distance
			lineOfMinDistance = line
		}
	}

	return lineOfMinDistance
}

// ExtractLineFragment will prepare substr for line detection
func ExtractLineFragment(line, substr string, key bool) string {
	// If detecting line by keys only
	idx := strings.Index(line, ":")
	if key && idx >= 0 {
		return line[:idx]
	}
	start := strings.Index(line, substr)
	end := start + len(substr)

	for start >= 0 {
		if line[start] == ' ' {
			break
		}

		start--
	}

	for end < len(line) {
		if line[end] == ' ' {
			break
		}

		end++
	}

	return removeExtras(line, start, end)
}

func removeExtras(result string, start, end int) string {
	// workaround for selecting yaml keys
	if result[end-1] == ':' {
		end--
	}

	if result[end-1] == '"' {
		end--
	}

	if result[start+1] == '"' {
		start++
	}

	return result[start+1 : end]
}

// DetectCurrentLine uses levenshtein distance to find the most accurate line for the vulnerability
// nolint:gocritic
func (d *DefaultDetectLineResponse) DetectCurrentLine(str1, str2 string, recurseCount int,
	lines []string, kind model.FileKind) (*DefaultDetectLineResponse, model.ResourceLine, model.ResourceLine, []string) {
	distances := make(map[int]int)
	starts, ends := make(map[int]model.ResourceLine), make(map[int]model.ResourceLine)

	for i := d.CurrentLine; i < len(lines); i++ {
		distances, starts, ends = checkLine(str1, str2, distances, starts, ends, lines, i, kind)
	}

	if len(distances) == 0 {
		d.IsBreak = true
		return d, model.ResourceLine{Line: d.CurrentLine + 1, Col: 0},
			model.ResourceLine{Line: d.CurrentLine + 1, Col: len(lines[d.CurrentLine])},
			lines
	}

	d.CurrentLine = SelectLineWithMinimumDistance(distances, d.CurrentLine)
	d.IsBreak = false
	d.FoundAtLeastOne = true

	return d, starts[d.CurrentLine], ends[d.CurrentLine], lines
}

//nolint:gocyclo,gocritic
func checkLine(str1, str2 string, distances map[int]int, starts map[int]model.ResourceLine, ends map[int]model.ResourceLine,
	lines []string, startLine int, kind model.FileKind) (map[int]int, map[int]model.ResourceLine, map[int]model.ResourceLine) {
	line := strings.TrimSpace(lines[startLine])
	endLine := startLine + 1
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return distances, starts, ends
	}

	line = indentRegex.ReplaceAllString(line, "")
	currentIndent := strings.Index(lines[startLine], line)
	if str1 != "" && str2 != "" && strings.Contains(line, str1) {
		restLine := line[strings.Index(line, str1)+len(str1):]
		if strings.Contains(restLine, str2) {
			distances[startLine] = levenshtein.ComputeDistance(ExtractLineFragment(line, str1, false), str1)
			distances[startLine] += levenshtein.ComputeDistance(ExtractLineFragment(restLine, str2, false), str2)
			starts[startLine] = model.ResourceLine{Line: startLine + 1, Col: currentIndent}
			ends[startLine] = model.ResourceLine{Line: startLine + 1, Col: len(lines[startLine])}
		} else if kind == model.KindYAML && yamlMultilineRegex.MatchString(line) {
			s, nextLine := "", ""
			for endLine < len(lines) {
				nextLine = indentRegex.ReplaceAllString(lines[endLine], "")
				nextIndent := strings.Index(lines[endLine], nextLine)
				if currentIndent == nextIndent || strings.Contains(nextLine, str2) {
					break
				}
				s += nextLine
				endLine++
			}

			if strings.Contains(
				whitespacesRegex.ReplaceAllString(str2, ""),
				whitespacesRegex.ReplaceAllString(s, ""),
			) || strings.Contains(nextLine, str2) {
				distances[startLine] = levenshtein.ComputeDistance(ExtractLineFragment(line, str1, false), str1)
				distances[startLine] += levenshtein.ComputeDistance(ExtractLineFragment(str2, s, false), s)
				starts[startLine] = model.ResourceLine{Line: startLine + 1, Col: currentIndent}
				ends[startLine] = model.ResourceLine{Line: endLine, Col: len(lines[startLine])}
			}
		}
	} else if str1 != "" && strings.Contains(line, str1) {
		distances[startLine] = levenshtein.ComputeDistance(ExtractLineFragment(line, str1, false), str1)
		starts[startLine] = model.ResourceLine{Line: startLine + 1, Col: currentIndent}
		ends[startLine] = model.ResourceLine{Line: startLine + 1, Col: len(lines[startLine])}
	}

	return distances, starts, ends
}
