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
	"sort"
	"strconv"
	"strings"

	"github.com/agnivade/levenshtein"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

var (
	nameRegex          = regexp.MustCompile(`^([A-Za-z\d-_]+)\[([A-Za-z\d-_{}]+)]$`)
	nameRegexDocker    = regexp.MustCompile(`{{(\d+)}}`)
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
	// File, when set, is the file whose Lines() are passed to DetectCurrentLine,
	// letting it visit only the lines that contain the searched text.
	File *model.FileMetadata
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
	if line == "" {
		return ""
	}
	start := strings.Index(line, substr)
	if start < 0 {
		return line
	}
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
	if result == "" || end <= 0 || start+1 >= len(result) {
		return result
	}

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
	best, bestDistance := -1, 0
	var bestStart, bestEnd model.ResourceLine

	// visit reports whether the scan can stop: lines are visited in ascending
	// order, so the first exact match (distance 0) is the best and earliest one.
	visit := func(i int) bool {
		distance, start, end, ok := checkLine(str1, str2, lines, i, kind)
		if ok && (best < 0 || distance < bestDistance) {
			best, bestDistance, bestStart, bestEnd = i, distance, start, end
		}
		return ok && distance == 0
	}
	if first, second, ok := d.candidateLines(str1, str2, kind); ok {
		walkAscending(first, second, d.CurrentLine, func(i int) bool { return visit(i) })
	} else {
		for i := d.CurrentLine; i < len(lines); i++ {
			if visit(i) {
				break
			}
		}
	}

	if best < 0 {
		d.IsBreak = true
		return d, model.ResourceLine{Line: d.CurrentLine + 1, Col: 0},
			model.ResourceLine{Line: d.CurrentLine + 1, Col: len(lines[d.CurrentLine])},
			lines
	}

	d.CurrentLine = best
	d.IsBreak = false
	d.FoundAtLeastOne = true

	return d, bestStart, bestEnd, lines
}

// candidateLines returns sorted line indexes, as one or two lists whose union
// holds every line of d.File that checkLine can accept for str1 and str2; ok is
// false when the file cannot cache them. Lines without str1 never match. With
// str2, a line also needs str2 after str1, except a YAML line that starts a
// block scalar, which matches on the lines that follow it. The shorter of the
// str1 list and the str2 (plus block scalar) lists is used.
func (d *DefaultDetectLineResponse) candidateLines(str1, str2 string, kind model.FileKind) (first, second []int, ok bool) {
	if d.File == nil || str1 == "" {
		return nil, nil, false
	}
	byStr1, ok := d.File.LinesContaining(str1)
	if !ok || str2 == "" {
		return byStr1, nil, ok
	}
	byStr2, ok := d.File.LinesContaining(str2)
	if !ok {
		return byStr1, nil, true
	}
	var blocks []int
	if kind == model.KindYAML {
		blocks, _ = d.File.LinesMatching("yamlBlockScalar", startsYAMLBlockScalar)
	}
	if len(byStr2)+len(blocks) < len(byStr1) {
		return byStr2, blocks, true
	}
	return byStr1, nil, true
}

// walkAscending calls visit on the indexes of a and b that are >= from, in
// ascending order and without repeats, until visit returns true.
func walkAscending(a, b []int, from int, visit func(int) bool) {
	a, b = a[sort.SearchInts(a, from):], b[sort.SearchInts(b, from):]
	for len(a) > 0 || len(b) > 0 {
		var i int
		switch {
		case len(b) == 0 || (len(a) > 0 && a[0] < b[0]):
			i, a = a[0], a[1:]
		case len(a) == 0 || b[0] < a[0]:
			i, b = b[0], b[1:]
		default:
			i, a, b = a[0], a[1:], b[1:]
		}
		if visit(i) {
			return
		}
	}
}

// startsYAMLBlockScalar reports whether checkLine would treat the line as the
// start of a YAML block scalar.
func startsYAMLBlockScalar(raw string) bool {
	line := strings.TrimSpace(raw)
	return mayStartYAMLBlockScalar(line) && yamlMultilineRegex.MatchString(line)
}

func mayStartYAMLBlockScalar(line string) bool {
	return strings.IndexByte(line, ':') >= 0 && strings.ContainsAny(line, "|>\\")
}

// checkLine scores lines[startLine] against str1 and str2; ok is false when the line does not match.
//
//nolint:gocyclo,gocritic
func checkLine(str1, str2 string, lines []string, startLine int, kind model.FileKind) (
	distance int, start, end model.ResourceLine, ok bool) {
	if str1 == "" || !strings.Contains(lines[startLine], str1) {
		return distance, start, end, ok
	}
	line := strings.TrimSpace(lines[startLine])
	endLine := startLine + 1
	if !strings.Contains(line, str1) || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return distance, start, end, ok
	}

	currentIndent := strings.Index(lines[startLine], line)
	if str1 != "" && str2 != "" && strings.Contains(line, str1) {
		restLine := line[strings.Index(line, str1)+len(str1):]
		if strings.Contains(restLine, str2) {
			distance = levenshtein.ComputeDistance(ExtractLineFragment(line, str1, false), str1)
			distance += levenshtein.ComputeDistance(ExtractLineFragment(restLine, str2, false), str2)
			start = model.ResourceLine{Line: startLine + 1, Col: currentIndent}
			ok = true
			end = model.ResourceLine{Line: startLine + 1, Col: len(lines[startLine])}
		} else if kind == model.KindYAML && mayStartYAMLBlockScalar(line) && yamlMultilineRegex.MatchString(line) {
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
				distance = levenshtein.ComputeDistance(ExtractLineFragment(line, str1, false), str1)
				distance += levenshtein.ComputeDistance(ExtractLineFragment(str2, s, false), s)
				start = model.ResourceLine{Line: startLine + 1, Col: currentIndent}
				ok = true
				end = model.ResourceLine{Line: endLine, Col: len(lines[startLine])}
			}
		}
	} else if str1 != "" && strings.Contains(line, str1) {
		distance = levenshtein.ComputeDistance(ExtractLineFragment(line, str1, false), str1)
		start = model.ResourceLine{Line: startLine + 1, Col: currentIndent}
		ok = true
		end = model.ResourceLine{Line: startLine + 1, Col: len(lines[startLine])}
	}

	return distance, start, end, ok
}
