/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"
	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/agnivade/levenshtein"
	"gopkg.in/yaml.v3"
)

// DetectKindLine defines a kindDetectLine type
type DetectKindLine struct {
}

type detectCurlLine struct {
	foundRes   bool
	lineRes    int
	breakRes   bool
	lastUnique dupHistory
	// tiedInBranch is set when the key's line is not unique and a line it ties
	// with sits in a template block or holds an action: the copies may be branches.
	tiedInBranch bool
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

	// A stamp line is never the finding's line: a stamp at the end of the file
	// has no line of its own once the stamps are dropped.
	// A key whose candidate lines are alternative branches is first looked up in
	// the rendered document, which says which one was written.
	whole := curLineRes.foundRes && !curLineRes.breakRes && !curLineRes.tiedInBranch && curLineRes.lastUnique.unique
	if whole && !isIDLine(lines[curLineRes.lineRes]) {
		return foundLines(file, lines, curLineRes.lineRes, start, end, outputLines)
	}

	// The keys are not all in this template: an include emitted some, as Helm
	// attributes named-template output to the file invoking it.
	if found, ok := renderedLines(ctx, file, lines, sanitizedSubstring, extractedString, helmID, outputLines); ok {
		return found
	}

	// Otherwise the last key that is in this template, and unique, locates the
	// finding: the node owning the offending key.
	if curLineRes.foundRes && !isIDLine(lines[curLineRes.lineRes]) {
		return foundLines(file, lines, curLineRes.lineRes, start, end, outputLines)
	}

	if found, ok := ownerLines(ctx, file, lines, sanitizedSubstring, extractedString, helmID, outputLines); ok {
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

// renderedLines locates a finding by the rendered line that holds it: at the
// include that emitted that line, or at the template line that wrote it when
// the document aligns line for line with the template. A finding whose keys are
// not all rendered, or whose line cannot be told, is left to ownerLines.
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
	if !found.foundRes || found.breakRes {
		return model.VulnerabilityLines{}, false
	}
	if !keyPathHolds(rendered, path) {
		// A nested key of the same name matched first: the direct one is the key.
		line, ok := directKeyLine(rendered, pathKeys(rendered, path))
		if !ok {
			return model.VulnerabilityLines{}, false
		}
		found.lineRes = line
	}
	return writerLines(file, lines, rendered, found.lineRes, outputLines)
}

// ownerLines locates a finding whose key is not located, as it is absent from
// the rendered document or its writer cannot be told, at the deepest key
// before it that holds in the document and is located: the node owning it.
func ownerLines(ctx context.Context, file *model.FileMetadata, lines []string, sanitizedSubstring string,
	extractedString [][]string, helmID, outputLines int,
) (model.VulnerabilityLines, bool) {
	attribution := file.HelmAttribution
	if attribution == nil || attribution.RenderedContent == "" {
		return model.VulnerabilityLines{}, false
	}
	rendered := strings.Split(attribution.RenderedContent, "\n")
	var path []keyMatch
	found, _, _ := detectCurlLine{}.walkSearchKey(ctx, rendered, sanitizedSubstring, extractedString, nil, helmID, &path)
	if found.foundRes && !found.breakRes && len(path) > 0 {
		path = path[:len(path)-1]
	}
	for i := len(path); i > 0; i-- {
		if !keyPathHolds(rendered, path[:i]) {
			continue
		}
		if located, ok := writerLines(file, lines, rendered, path[i-1].line, outputLines); ok {
			return located, true
		}
	}
	return model.VulnerabilityLines{}, false
}

// writerLines locates rendered line target at the include that emitted it, or
// at the template line that wrote it.
func writerLines(file *model.FileMetadata, lines, rendered []string, target, outputLines int,
) (model.VulnerabilityLines, bool) {
	invocations := file.HelmAttribution.Invocations
	if !invocations.KnownBefore(target + 1) {
		// In a template of actions alone, the first include stands for the
		// document, as no text of the template is in it.
		if actionsOnly(lines) {
			return invocationLines(file, invocations.First(), lines, outputLines)
		}
		return model.VulnerabilityLines{}, false
	}
	if invocation, ok := invocations.Containing(target + 1); ok {
		return invocationLines(file, invocation.Position, lines, outputLines)
	}
	start := documentStart(lines, file.HelmID, invocations)
	if line, ok := alignedLine(lines, rendered, invocations, target, start); ok {
		return foundLines(file, lines, line, model.ResourceLine{}, model.ResourceLine{Col: len(lines[line])}, outputLines), true
	}
	if line, ok := uniqueLine(lines, rendered, invocations, target, start); ok {
		return foundLines(file, lines, line, model.ResourceLine{}, model.ResourceLine{Col: len(lines[line])}, outputLines), true
	}
	return model.VulnerabilityLines{}, false
}

// alignedLine returns the index of the template line that wrote rendered line
// target, which no include emitted. From the start of the document, a line of
// plain text prints once, as written, and in order, so
// the rendered lines outside the includes' output match those lines one for
// one. The first line with an action of its own ends that: an action may print
// nothing, several lines, or join lines. Only that line's first rendered line
// is known still, when the line starts with text: it is the next one.
func alignedLine(lines, rendered []string, invocations model.HelmInvocations, target, start int) (int, bool) {
	written, next := plainLines(lines, invocations, start)
	kept := 0
	for r := renderedStart(rendered, invocations); r < len(rendered); r++ {
		line := strings.TrimRight(rendered[r], " \t\r")
		if _, emitted := invocations.Containing(r + 1); emitted || strings.TrimSpace(line) == "" || isIDLine(line) {
			continue
		}
		switch {
		case kept < len(written) && line == strings.TrimRight(lines[written[kept]], " \t\r"):
			if r == target {
				return written[kept], true
			}
			kept++
		case kept == len(written) && next >= 0 && r == target && strings.HasPrefix(line, valueLinePrefix(lines[next])):
			return next, true
		default:
			return 0, false
		}
	}
	return 0, false
}

// keywordEnd closes a control block.
const keywordEnd = "end"

// blockOpeners are the actions that open a control block or a definition.
var blockOpeners = map[string]bool{"if": true, "with": true, "range": true, "define": true, "block": true}

// nonValueActions are the control actions that print no value of their own.
var nonValueActions = map[string]bool{
	"else": true, "end": true, "break": true, "continue": true,
}

// uniqueLine returns the index of the template line that wrote rendered line
// target when alignment no longer holds. A line of plain text prints once, as
// written. Outside every control block it always prints, so when the rendered
// text occurs once and that line holds it, the line wrote it. Inside a block
// that may be dead, the text may come from another line: the line is then the
// writer only when it is the one plain line with that text and no other action
// could print it. The rendered line must also be the only one with its text
// that no marked include emitted. start is the source line the document starts
// at (see documentStart).
func uniqueLine(lines, rendered []string, invocations model.HelmInvocations, target, start int) (int, bool) {
	text := strings.TrimRight(rendered[target], " \t\r")
	if strings.TrimSpace(text) == "" || isIDLine(text) {
		return 0, false
	}
	if !renderedOnce(rendered, invocations, target, text) {
		return 0, false
	}
	from, to := documentLines(lines, start)
	if from < 0 {
		return 0, false
	}
	inInclude, inAction, spanned := actionLines(lines, invocations)
	depths := lineDepths(lines)
	writers := scanWriters(lines, from, to, text, inInclude, inAction, spanned, depths)
	if writers.literal0 >= 0 && writers.literals0 == 1 {
		return writers.literal0, true
	}
	// A single candidate outside every block always prints, but several candidates
	// with a value cannot be told apart by their text.
	if writers.count == 1 && depths[writers.found] == 0 {
		return writers.found, true
	}
	return soleWriter(writers.found, writers.count, writers.printers)
}

// writers are the template lines of a document that may have written a text.
type writers struct {
	found, count int   // the last candidate, and how many there are
	printers     []int // lines with an action that may print the text
	literal0     int   // the last plain-text line outside every block that writes the text
	literals0    int   // how many plain-text lines outside every block write it
}

// scanWriters classifies the lines from..to-1 by how they may have written text.
func scanWriters(lines []string, from, to int, text string, inInclude, inAction, spanned []bool,
	depths []int,
) writers {
	w := writers{found: -1, literal0: -1}
	for i := from; i < to; i++ {
		if inInclude[i] || isIDLine(lines[i]) || commentOnly(lines[i]) {
			continue
		}
		candidate, printer := lineWrites(lines[i], text, inAction[i] || spanned[i])
		if candidate {
			w.count, w.found = w.count+1, i
			if depths[i] == 0 && len(helmaction.Scan(lines[i])) == 0 {
				// A line of plain text outside every block always prints it, and
				// the text is printed once, so this line printed it.
				w.literal0, w.literals0 = i, w.literals0+1
			}
		}
		if printer {
			w.printers = append(w.printers, i)
		}
	}
	return w
}

// soleWriter returns the template line that wrote the text: the one candidate
// when no action could print it, or else the one action that could, as a block.
func soleWriter(found, count int, printers []int) (int, bool) {
	switch {
	case count == 1 && len(printers) == 0:
		return found, true
	case count == 0 && len(printers) == 1:
		return printers[0], true
	}
	return 0, false
}

// renderedOnce reports whether target is the only rendered line with text that
// no marked include emitted.
func renderedOnce(rendered []string, invocations model.HelmInvocations, target int, text string) bool {
	for r, line := range rendered {
		if _, emitted := invocations.Containing(r + 1); !emitted && r != target &&
			strings.TrimRight(line, " \t\r") == text {
			return false
		}
	}
	return true
}

// lineWrites reports whether the template line can write text: candidate when
// it writes text as written, or starts with the text before its value, and
// printer when one of its actions may print text. A line of text inside a
// multi-line action (spanned) prints nothing.
func lineWrites(line, text string, spanned bool) (candidate, printer bool) {
	actions := helmaction.Scan(line)
	if len(actions) == 0 {
		return strings.TrimRight(line, " \t\r") == text && !spanned, false
	}
	prefix := strings.TrimRight(line[:actions[0].Start], " \t\r")
	if onlyControl(actions, line) {
		return prefix == text, false
	}
	if strings.Contains(prefix, ":") && strings.HasPrefix(strings.TrimSpace(text), strings.TrimSpace(prefix)) {
		return true, false
	}
	return false, true
}

// actionWord is the first word of an action, the keyword or function it starts
// with, however it is separated from its arguments.
func actionWord(action string) string {
	inner := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(action, "{{"), "}}"), "- \t\r\n")
	if fields := strings.Fields(inner); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// lineDepths returns, for each of lines, how many control blocks are open where
// the line starts, counting the blocks opened on the lines before it.
func lineDepths(lines []string) []int {
	depths, depth := make([]int, len(lines)), 0
	for i, line := range lines {
		depths[i] = depth
		for _, action := range helmaction.Scan(line) {
			if action.Comment {
				continue
			}
			word := actionWord(line[action.Start:action.End])
			switch {
			case blockOpeners[word]:
				depth++
			case word == keywordEnd && depth > 0:
				depth--
			}
		}
	}
	return depths
}

// onlyControl reports whether every action of line is a control action or a
// comment, which prints no value of its own.
func onlyControl(actions []helmaction.Action, line string) bool {
	for _, action := range actions {
		if action.Comment {
			continue
		}
		word := actionWord(line[action.Start:action.End])
		if !blockOpeners[word] && !nonValueActions[word] {
			return false
		}
	}
	return true
}

// documentStart is the source line the document starts at: the line after its
// ID stamp when the template holds it, else the first include's line, as the
// stamp is in that include's output.
func documentStart(lines []string, stamp string, invocations model.HelmInvocations) int {
	source := 0
	for _, line := range lines {
		if !isIDLine(line) {
			source++
		} else if stamp != "" && strings.TrimSpace(line) == strings.TrimSpace(stamp) {
			return source + 1
		}
	}
	if len(invocations) == 0 {
		return 1
	}
	return invocations.First().Line
}

// renderedStart is the index of the rendered line the document starts at: the
// first include's, or the line after the document's stamp when no include
// emitted any of it.
func renderedStart(rendered []string, invocations model.HelmInvocations) int {
	if len(invocations) > 0 {
		return invocations[0].RenderedLine - 1
	}
	for i, line := range rendered {
		if isIDLine(line) {
			return i + 1
		}
	}
	return 0
}

// plainLines returns the indexes of the lines of plain text of the document,
// from its start up to the first line with an action of its own, and
// the index of that line when it is a value line (see valueLinePrefix), or -1.
// Actions are found in the document as a whole, as one may span lines; a line
// inside a marked include prints nothing of its own.
func plainLines(lines []string, invocations model.HelmInvocations, start int) (written []int, next int) {
	from, to := documentLines(lines, start)
	if from < 0 {
		return nil, -1
	}
	inInclude, inAction, spanned := actionLines(lines[:to], invocations)
	if inAction[from] {
		return nil, -1
	}
	for i := from; i < to; i++ {
		switch {
		case isIDLine(lines[i]):
		case inAction[i]:
			if !inInclude[i] && !spanned[i] && valueLinePrefix(lines[i]) != "" {
				return written, i
			}
			return written, -1
		case inInclude[i] || strings.TrimSpace(lines[i]) == "" || commentOnly(lines[i]):
		case helmaction.Remove(lines[i]) != lines[i]:
			return written, -1
		default:
			written = append(written, i)
		}
	}
	return written, -1
}

// actionLines reports, for each of lines, whether a marked include touches
// it, whether another action does, and whether that action spans lines. A
// single-line template comment counts as no action.
func actionLines(lines []string, invocations model.HelmInvocations) (inInclude, inAction, spanned []bool) {
	marked := make(map[model.ResourceLine]bool, len(invocations))
	for _, invocation := range invocations {
		marked[invocation.Position] = true
	}
	sourceLines, starts := make([]int, len(lines)), make([]int, len(lines)+1)
	sourceLine, offset := 0, 0
	for i, line := range lines {
		if !isIDLine(line) {
			sourceLine++
		}
		sourceLines[i], starts[i] = sourceLine, offset
		offset += len(line) + 1
	}
	starts[len(lines)] = offset
	lineAt := func(offset int) int { return min(sort.SearchInts(starts, offset+1)-1, len(lines)-1) }
	inInclude, inAction, spanned = make([]bool, len(lines)), make([]bool, len(lines)), make([]bool, len(lines))
	for _, action := range helmaction.Scan(strings.Join(lines, "\n")) {
		first, last := lineAt(action.Start), lineAt(max(action.End-1, action.Start))
		include := marked[model.ResourceLine{Line: sourceLines[first], Col: action.Start - starts[first]}]
		for i := first; i <= last; i++ {
			switch {
			case include:
				inInclude[i] = true
			case first != last:
				inAction[i], spanned[i] = true, true
			case !action.Comment:
				inAction[i] = true
			}
		}
	}
	return inInclude, inAction, spanned
}

// commentOnly reports whether line holds template comments and nothing else.
// They print nothing; trims joining the lines around them leave text that no
// longer matches its line.
func commentOnly(line string) bool {
	actions := helmaction.Scan(line)
	for _, action := range actions {
		if !action.Comment || action.Unterminated {
			return false
		}
	}
	return len(actions) > 0 && strings.TrimSpace(helmaction.Remove(line)) == ""
}

// valueLinePrefix returns the text a value line starts with: a line holding a
// key, written as text, whose value has actions that are not control
// structures or includes, so it prints at least that text first. It is empty
// for any other line.
func valueLinePrefix(line string) string {
	actions := helmaction.Scan(line)
	if len(actions) == 0 {
		return ""
	}
	prefix := strings.TrimRight(line[:actions[0].Start], " \t")
	if !strings.Contains(prefix, ":") || strings.TrimSpace(prefix) == "" {
		return ""
	}
	for _, action := range actions {
		text := line[action.Start:action.End]
		switch actionWord(text) {
		case "if", "else", "end", "with", "range", "define", "block", "template", "include", "tpl", "break", "continue":
			return ""
		}
		if action.Unterminated || strings.HasPrefix(text, "{{-") || strings.HasSuffix(text, "-}}") {
			return ""
		}
	}
	return prefix
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

// documentLines returns the range of lines, as indexes, from the source line
// sourceLine (1-based, without stamps) up to the next document separator.
func documentLines(lines []string, sourceLine int) (from, to int) {
	from, source := -1, 0
	for i, line := range lines {
		if isIDLine(line) {
			continue
		}
		source++
		if source == sourceLine {
			from = i
		} else if from >= 0 && isDocumentSeparator(line) {
			return from, i
		}
	}
	return from, len(lines)
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
		selector := substr2
		if path == nil {
			substr2 = ""
		}
		var iterStart, iterEnd model.ResourceLine
		before := d
		d, iterStart, iterEnd = d.detectCurrentLine(lines, fmt.Sprintf("%s:", substr1), substr2, true, idInfo, helmID)
		if path == nil && selector != "" && !d.breakRes && contradictsSelector(lines[d.lineRes], substr1, selector) {
			// The line holds another value than the item the key picks.
			d, iterStart, iterEnd = before, model.ResourceLine{}, model.ResourceLine{}
			d.breakRes = true
		}

		if d.breakRes {
			break
		}
		if path != nil {
			*path = append(*path, keyMatch{key: substr1, selector: substr2 != "", value: substr2, line: d.lineRes})
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

// contradictsSelector reports whether line writes key with a literal value other
// than value. A value with an action in it may print any value.
func contradictsSelector(line, key, value string) bool {
	written, ok := writtenScalar(line, key+":")
	return ok && written != "" && written != value
}

// writtenScalar returns the literal scalar written after marker on line, as
// YAML reads it: without its quotes or a trailing comment. It is false when
// there is no marker, the value has an action in it or is not a scalar.
func writtenScalar(line, marker string) (string, bool) {
	_, written, ok := strings.Cut(line, marker)
	if !ok || strings.Contains(written, "{{") {
		return "", false
	}
	var node yaml.Node
	if yaml.Unmarshal([]byte(written), &node) != nil || len(node.Content) != 1 || node.Content[0].Kind != yaml.ScalarNode {
		return "", false
	}
	return node.Content[0].Value, true
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

	exactSelectors(lines, distances, str1, str2)
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
			tiedInBranch: !unique && tiedInBranch(lines, distances, lineResponse),
		},
		starts[lineResponse],
		ends[lineResponse]
}

// exactSelectors keeps, among the lines that hold both str1 and the selector
// value str2, the ones whose value is exactly str2 when there are any: a
// selector value that only starts a longer one does not pick that item.
func exactSelectors(lines []string, distances map[int]int, str1, str2 string) {
	if str1 == "" || str2 == "" {
		return
	}
	exact := map[int]bool{}
	for i := range distances {
		if value, ok := writtenScalar(lines[i], str1); ok && value == str2 {
			exact[i] = true
		}
	}
	if len(exact) == 0 {
		return
	}
	for i := range distances {
		if !exact[i] {
			delete(distances, i)
		}
	}
}

// tiedInBranch reports whether a line other than line, at the same distance, is
// inside a template block or holds an action: such lines may be alternative
// branches of the template, not copies of one another.
func tiedInBranch(lines []string, distances map[int]int, line int) bool {
	depths := lineDepths(lines)
	for key, value := range distances {
		if key != line && value == distances[line] && (depths[key] > 0 || len(helmaction.Scan(lines[key])) > 0) {
			return true
		}
	}
	return false
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
