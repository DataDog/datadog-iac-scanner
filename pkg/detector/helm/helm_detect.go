/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"
	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/agnivade/levenshtein"
)

// DetectKindLine defines a kindDetectLine type
type DetectKindLine struct {
}

type detectCurlLine struct {
	foundRes   bool
	lineRes    int
	breakRes   bool
	lastUnique dupHistory
}

// dupHistory keeps the history of uniques
type dupHistory struct {
	unique         bool
	lastUniqueLine int
}

const (
	undetectedVulnerabilityLine = -1
)

// DetectLine is used to detect line on the helm template,
// it looks only at the keys of the template and will make use of the auxiliary added
// lines (ex: "# KICS_HELM_ID_")
func (d DetectKindLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)
	stamp, stamped := helmmarker.ParseIDLine(file.HelmID)
	if stamped {
		searchKey = fmt.Sprintf("%s.%s", stamp.SearchKey(), searchKey)
	}

	lines := make([]string, len(file.Lines()))
	copy(lines, file.Lines())

	curLineRes := detectCurlLine{
		foundRes: false,
		lineRes:  0,
		breakRes: false,
	}
	var extractedString [][]string
	extractedString = detector.GetBracketValues(searchKey, extractedString, "")
	sanitizedSubstring := searchKey
	for idx, str := range extractedString {
		sanitizedSubstring = strings.ReplaceAll(sanitizedSubstring, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}

	// Only the line is kept: idInfo is the line-range map of this file, and the
	// walk below finds the stamp by its full text first, so a stamp of another
	// template never reaches idInfo.
	helmID := -1
	if stamped {
		helmID = stamp.Line
	}

	curLineRes, start, end := curLineRes.walkSearchKey(ctx, lines, sanitizedSubstring, extractedString, file.IDInfo, helmID, nil)

	if curLineRes.foundRes {
		return foundLines(file, lines, curLineRes.lineRes, start, end, outputLines)
	}

	// The keys are not all in this template: an include emitted some, as Helm
	// attributes named-template output to the file invoking it.
	if found, ok := renderedLines(ctx, file, lines, sanitizedSubstring, extractedString, helmID, outputLines); ok {
		return found
	}

	var filePathSplit = strings.Split(file.FilePath, "/")
	contextLogger.Warn().Msgf("Failed to detect line associated with identified result in file %s", filePathSplit[len(filePathSplit)-1])

	return model.VulnerabilityLines{
		Line:         undetectedVulnerabilityLine,
		VulnLines:    &[]model.CodeLine{},
		ResolvedFile: file.FilePath,
	}
}

// foundLines locates a finding at line, an index of lines.
func foundLines(
	file *model.FileMetadata, lines []string, line int, start, end model.ResourceLine, outputLines int,
) model.VulnerabilityLines {
	unstamped, index := unstampedLines(lines)
	at := index(line)
	adjustedLine := at + 1
	return model.VulnerabilityLines{
		Line:                  adjustedLine,
		VulnLines:             detector.GetAdjacentVulnLines(at, outputLines, unstamped),
		LineWithVulnerability: strings.Split(unstamped[at], ": ")[0],
		ResolvedFile:          file.FilePath,
		VulnerablilityLocation: model.ResourceLocation{
			Start: model.ResourceLine{Line: adjustedLine, Col: start.Col},
			End:   model.ResourceLine{Line: adjustedLine, Col: end.Col},
		},
	}
}

// renderedLines locates a finding at the include whose output holds its
// rendered line. A finding whose keys are not all rendered, or that no include
// is known to have emitted, is not located.
func renderedLines(ctx context.Context, file *model.FileMetadata, lines []string, sanitizedSubstring string,
	extractedString [][]string, helmID, outputLines int,
) (model.VulnerabilityLines, bool) {
	attribution := file.HelmAttribution
	if attribution == nil || attribution.RenderedContent == "" {
		return model.VulnerabilityLines{}, false
	}
	rendered := strings.Split(attribution.RenderedContent, "\n")
	var path []keyMatch
	found, _, _ := detectCurlLine{}.walkSearchKey(ctx, rendered, sanitizedSubstring, extractedString, nil, helmID, &path)
	if !found.foundRes || found.breakRes || !keyPathHolds(rendered, path) {
		return model.VulnerabilityLines{}, false
	}
	if !attribution.Invocations.KnownBefore(found.lineRes + 1) {
		// In a template of actions alone, the first include stands for the
		// document, as no text of the template is in it.
		if actionsOnly(lines) {
			return invocationLines(file, attribution.Invocations.First(), lines, outputLines)
		}
		return model.VulnerabilityLines{}, false
	}
	if invocation, ok := attribution.Invocations.Containing(found.lineRes + 1); ok {
		return invocationLines(file, invocation.Position, lines, outputLines)
	}
	return model.VulnerabilityLines{}, false
}

// actionsOnly reports whether the template holds actions and nothing else
// outside its ID stamps and document separators.
func actionsOnly(lines []string) bool {
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !isIDLine(line) {
			kept = append(kept, line)
		}
	}
	for _, line := range strings.Split(helmaction.Remove(strings.Join(kept, "\n")), "\n") {
		if line = strings.TrimSpace(line); line != "" && !isDocumentSeparator(line) {
			return false
		}
	}
	return true
}

func isDocumentSeparator(line string) bool {
	line = strings.TrimRight(line, " \t\r")
	return line == "---" || strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "---\t")
}

// invocationLines locates a finding at the include-like action whose output
// produced it. The invocation is a position in the template as written, so it
// indexes the lines without their ID stamps, which are not reported either.
func invocationLines(
	file *model.FileMetadata, invocation model.ResourceLine, lines []string, outputLines int,
) (model.VulnerabilityLines, bool) {
	unstamped, _ := unstampedLines(lines)
	if invocation.Line < 1 || invocation.Line > len(unstamped) {
		return model.VulnerabilityLines{}, false
	}
	at := invocation.Line - 1
	return model.VulnerabilityLines{
		Line:                  invocation.Line,
		VulnLines:             detector.GetAdjacentVulnLines(at, outputLines, unstamped),
		LineWithVulnerability: unstamped[at],
		ResolvedFile:          file.FilePath,
		VulnerablilityLocation: model.ResourceLocation{
			Start: invocation,
			End:   model.ResourceLine{Line: invocation.Line, Col: len(unstamped[at])},
		},
	}, true
}

// walkSearchKey matches the keys of the sanitized search key one after the
// other in lines, each below the previous one. In a template, values passed
// through '=' and '[]' are often actions, so only keys are matched there;
// rendered lines hold the values, which then select among equal keys.
func (d detectCurlLine) walkSearchKey(ctx context.Context, lines []string, sanitizedSubstring string,
	extractedString [][]string, idInfo map[int]interface{}, helmID int, path *[]keyMatch,
) (walked detectCurlLine, start, end model.ResourceLine) {
	for _, key := range strings.Split(sanitizedSubstring, ".") {
		substr1, substr2 := detector.GenerateSubstrings(ctx, key, extractedString, lines, d.lineRes)
		if path == nil {
			substr2 = ""
		}
		var iterStart, iterEnd model.ResourceLine
		d, iterStart, iterEnd = d.detectCurrentLine(lines, fmt.Sprintf("%s:", substr1), substr2, true, idInfo, helmID)

		if d.breakRes {
			break
		}
		if path != nil {
			*path = append(*path, keyMatch{key: substr1, selector: substr2 != "", line: d.lineRes})
		}
		start = iterStart
		end = iterEnd
	}

	// Look at dupHistory to see if the last element was duplicate, if so
	// change the line to the last unique key
	if !d.lastUnique.unique {
		d.lineRes = d.lastUnique.lastUniqueLine
	}
	return d, start, end
}

// keyMatch is the line a key of a search key matched; a selector key matched
// its value too, and so picks an item of a list.
type keyMatch struct {
	key      string
	selector bool
	line     int
}

// keyPathHolds reports whether the keys of path matched YAML keys, each one
// under the one before: a key matched in a comment, in a block scalar or under
// another parent does not locate the finding. A search key may skip levels,
// and a selector that picks no list item starts over.
func keyPathHolds(lines []string, path []keyMatch) bool {
	holder := -1
	for _, match := range path {
		if isIDLine(lines[match.line]) {
			continue
		}
		indent, item, ok := keyLine(lines[match.line], match.key)
		if !ok {
			return false
		}
		if holder >= 0 && holder != match.line &&
			(!holds(lines, holder, match.line, indent) || !match.selector && closerKey(lines, holder, match.line, match.key)) {
			return false
		}
		holder = match.line
		if match.selector && !item {
			holder = yamlParent(lines, match.line, indent)
			if holder < 0 || !isItem(lines[holder], indent) {
				holder = -1
			}
		}
	}
	return true
}

// holds reports whether the node at indent written at line sits under the
// node of line holder.
func holds(lines []string, holder, line, indent int) bool {
	for line > holder {
		line = yamlParent(lines, line, indent)
		if line < 0 {
			return false
		}
		if blockScalar.MatchString(lines[line]) {
			return false
		}
		indent = itemIndent(lines[line])
		if content := strings.TrimLeft(lines[line], " "); line != holder && strings.HasPrefix(content, "- ") {
			indent++
		}
	}
	return line == holder
}

// blockScalar matches a line whose value opens a block scalar, which holds
// text, not keys.
var blockScalar = regexp.MustCompile(`:\s+[|>][-+0-9]*\s*(#.*)?\r?$`)

// closerKey reports whether key is written right under holder, other than at
// line: a search key skipping levels then matched a deeper key first.
func closerKey(lines []string, holder, line int, key string) bool {
	if yamlParent(lines, line, keyIndent(lines[line])) == holder {
		return false
	}
	for i := holder + 1; i < len(lines); i++ {
		parent := yamlParent(lines, i, keyIndent(lines[i]))
		if parent < holder || isDocumentSeparator(lines[i]) {
			return false
		}
		if _, _, ok := keyLine(lines[i], key); ok && parent == holder {
			return true
		}
	}
	return false
}

func keyIndent(line string) int {
	indent, _, _ := keyLine(line, "")
	return indent
}

// keyLine reports whether line holds key as a key, and the indentation of the
// key and whether it opens a list item.
func keyLine(line, key string) (indent int, item, ok bool) {
	content := strings.TrimLeft(line, " ")
	indent = len(line) - len(content)
	if rest, isItem := strings.CutPrefix(content, "- "); isItem {
		item, content = true, strings.TrimLeft(rest, " ")
		indent = len(line) - len(content)
	}
	for _, written := range []string{key, `"` + key + `"`, `'` + key + `'`} {
		if strings.HasPrefix(content, written+":") {
			return indent, item, true
		}
	}
	return indent, item, false
}

func itemIndent(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// isItem reports whether line opens a list item whose keys are at indent.
func isItem(line string, indent int) bool {
	content := strings.TrimLeft(line, " ")
	rest, ok := strings.CutPrefix(content, "- ")
	return ok && len(line)-len(strings.TrimLeft(rest, " ")) == indent
}

// yamlParent returns the line that holds the node at indent written at line
// from: the nearest line above it of a smaller indentation, or of an item
// holding it, or -1 at the top of the document.
func yamlParent(lines []string, from, indent int) int {
	for i := from - 1; i >= 0; i-- {
		line := strings.TrimRight(lines[i], " \t\r")
		content := strings.TrimLeft(line, " ")
		if content == "" || strings.HasPrefix(content, "#") {
			continue
		}
		if isDocumentSeparator(line) {
			return -1
		}
		if itemIndent(line) < indent {
			return i
		}
	}
	return -1
}

// unstampedLines drops the ID stamp lines the resolver stamped into
// the rendered output. index maps a position in lines to its position in kept;
// a stamp line maps to the line that follows it.
func unstampedLines(lines []string) (kept []string, index func(int) int) {
	kept = make([]string, 0, len(lines))
	keptBefore := make([]int, len(lines))
	for i, line := range lines {
		keptBefore[i] = len(kept)
		if !isIDLine(line) {
			kept = append(kept, line)
		}
	}
	return kept, func(i int) int { return keptBefore[i] }
}

func isIDLine(line string) bool {
	_, ok := helmmarker.ParseIDLine(line)
	return ok
}

func containsHelmKey(line, key string) bool {
	lineID, isStamp := helmmarker.ParseIDLine(line)
	if keyID, isStampKey := helmmarker.ParseSearchKey(key); isStampKey {
		// A stamp key matches its own stamp line, never text that mentions it.
		return isStamp && lineID == keyID
	}
	if isStamp {
		return false
	}
	if strings.Contains(line, key) {
		return true
	}
	key = strings.TrimSuffix(key, ":")
	return strings.Contains(line, `"`+key+`":`) || strings.Contains(line, `'`+key+`':`)
}

// nolint:gocritic
func (d detectCurlLine) detectCurrentLine(lines []string, str1,
	str2 string, byKey bool, idInfo map[int]interface{}, id int) (detectCurlLine, model.ResourceLine, model.ResourceLine) {
	distances := make(map[int]int)
	starts, ends := make(map[int]model.ResourceLine), make(map[int]model.ResourceLine)
	for i := d.lineRes; i < len(lines); i++ {
		if str1 != "" && str2 != "" {
			if strings.Contains(lines[i], str1) && strings.Contains(lines[i], str2) {
				distances[i] = levenshtein.ComputeDistance(detector.ExtractLineFragment(lines[i], str2, byKey), str2)
				starts[i] = model.ResourceLine{Line: i + 1, Col: 0}
				ends[i] = model.ResourceLine{Line: i + 1, Col: len(lines[i])}
			}
		} else if str1 != "" {
			if containsHelmKey(lines[i], str1) {
				distances[i] = levenshtein.ComputeDistance(
					detector.ExtractLineFragment(strings.TrimSpace(lines[i]), str1, byKey), str1)
				starts[i] = model.ResourceLine{Line: i + 1, Col: 0}
				ends[i] = model.ResourceLine{Line: i + 1, Col: len(lines[i])}
			}
		}
	}

	lastSingle := d.lastUnique.lastUniqueLine

	if len(distances) == 0 {
		return detectCurlLine{
			foundRes: d.foundRes,
			lineRes:  d.lineRes,
			breakRes: true,
			lastUnique: dupHistory{
				lastUniqueLine: lastSingle,
				unique:         d.lastUnique.unique,
			},
		}, model.ResourceLine{}, model.ResourceLine{}
	}

	lineResponse := detector.SelectLineWithMinimumDistance(distances, d.lineRes)
	// if lineResponse is unique
	unique := detectLastSingle(lineResponse, distances, idInfo, id)
	if unique {
		lastSingle = lineResponse
	}

	return detectCurlLine{
			foundRes: true,
			lineRes:  lineResponse,
			breakRes: false,
			lastUnique: dupHistory{
				unique:         unique,
				lastUniqueLine: lastSingle,
			},
		},
		starts[lineResponse],
		ends[lineResponse]
}

// detectLastSingle checks if the line is unique or a duplicate
func detectLastSingle(line int, dis map[int]int, idInfo map[int]interface{}, id int) bool {
	if idInfo == nil {
		return true
	}
	var containsLine func(int) bool
	switch originalLines := idInfo[id].(type) {
	case model.HelmIDLineRange:
		containsLine = func(line int) bool {
			return line >= originalLines.Start && line <= originalLines.End
		}
	case map[int]int:
		containsLine = func(line int) bool {
			_, ok := originalLines[line]
			return ok
		}
	default:
		return true
	}
	for key, value := range dis {
		if value == dis[line] && key != line {
			// check if we are only looking at original data equivalent to the vulnerability
			if containsLine(key) {
				return false
			}
		}
	}
	return true
}
