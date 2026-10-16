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
	walk := walkRendered(ctx, file, sanitizedSubstring, extractedString, helmID)
	if found, ok := renderedLines(file, lines, walk, outputLines); ok {
		return found
	}

	// Otherwise the node owning the offending key: the deepest key before it that
	// the rendered document holds and whose line is told, or the last key that is
	// in this template, and unique. A key nested in another is written after it,
	// so the later line is the deeper one.
	owner, ownerFound := ownerLines(file, lines, walk, outputLines)
	if curLineRes.foundRes && !isIDLine(lines[curLineRes.lineRes]) {
		last := foundLines(file, lines, curLineRes.lineRes, start, end, outputLines)
		if !ownerFound || last.Line > owner.Line {
			return last
		}
	}
	if ownerFound {
		return owner
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

// renderedWalk is the search key of a finding walked in the rendered document.
type renderedWalk struct {
	rendered []string
	found    detectCurlLine
	path     []keyMatch
	resolver *resolver // shared by the lookups of the finding
}

// walkRendered walks the search key in the rendered document of the file, or
// returns nil when the file has none.
func walkRendered(ctx context.Context, file *model.FileMetadata, sanitizedSubstring string,
	extractedString [][]string, helmID int,
) *renderedWalk {
	attribution := file.HelmAttribution
	if attribution == nil || attribution.RenderedContent == "" {
		return nil
	}
	walk := &renderedWalk{rendered: cachedDocumentOf(attribution).lines}
	walk.found, _, _ = detectCurlLine{}.walkSearchKey(ctx, walk.rendered, sanitizedSubstring, extractedString, nil, helmID, &walk.path)
	return walk
}

// renderedLines locates a finding by the rendered line that holds it: at the
// include that emitted that line, or at the template line that wrote it when
// the document aligns line for line with the template. A finding whose keys are
// not all rendered, or whose line cannot be told, is left to ownerLines.
func renderedLines(file *model.FileMetadata, lines []string, walk *renderedWalk, outputLines int,
) (model.VulnerabilityLines, bool) {
	if walk == nil || !walk.found.foundRes || walk.found.breakRes {
		return model.VulnerabilityLines{}, false
	}
	rendered, path, line := walk.rendered, walk.path, walk.found.lineRes
	if !keyPathHolds(rendered, path) {
		// A nested key of the same name matched first: the direct one is the key.
		direct, ok := directKeyLine(rendered, pathKeys(rendered, path))
		if !ok {
			return model.VulnerabilityLines{}, false
		}
		line = direct
	}
	return writerLines(file, lines, walk, pathOrNil(path, line), line, outputLines)
}

// ownerLines locates a finding whose key is not located, as it is absent from
// the rendered document or its writer cannot be told, at the deepest key
// before it that holds in the document and is located: the node owning it.
func ownerLines(file *model.FileMetadata, lines []string, walk *renderedWalk, outputLines int,
) (model.VulnerabilityLines, bool) {
	if walk == nil {
		return model.VulnerabilityLines{}, false
	}
	path := walk.path
	if walk.found.foundRes && !walk.found.breakRes && len(path) > 0 {
		path = path[:len(path)-1]
	}
	for i := len(path); i > 0; i-- {
		if !keyPathHolds(walk.rendered, path[:i]) {
			continue
		}
		if located, ok := writerLines(file, lines, walk, path[:i], path[i-1].line, outputLines); ok {
			return located, true
		}
	}
	return model.VulnerabilityLines{}, false
}

// writerLines locates rendered line target at the include that emitted it, or
// at the template line that wrote it.
func writerLines(file *model.FileMetadata, lines []string, walk *renderedWalk, path []keyMatch, target, outputLines int,
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
	if walk.resolver == nil {
		start := documentStart(lines, file.HelmID, invocations)
		walk.resolver = newResolver(lines, walk.rendered, invocations, start, nil, nil, file.HelmID)
		walk.resolver.tree, _ = cachedKeyTree(walk.rendered)
	}
	r := walk.resolver
	r.path, r.memo = path, map[int]resolved{}
	if line, ok := r.locate(target); ok {
		return foundLines(file, lines, line, model.ResourceLine{}, model.ResourceLine{Col: len(lines[line])}, outputLines), true
	}
	return model.VulnerabilityLines{}, false
}

// alignment maps the rendered lines that align with the template to the
// template lines that wrote them. From the start of the document, a line of
// plain text prints once, as written, and in order, so the rendered lines
// outside the includes match those lines one for one. The first line with an
// action of its own ends that: an action may print nothing, several lines, or
// join lines. Only that line's first rendered line is known still, when the
// line starts with text: it is the next one.
func alignment(lines, rendered []string, invocations model.HelmInvocations, start int) map[int]int {
	written, next := plainLines(lines, invocations, start)
	aligned := map[int]int{}
	kept := 0
	for r := renderedStart(rendered, invocations); r < len(rendered); r++ {
		line := strings.TrimRight(rendered[r], " \t\r")
		if _, emitted := invocations.Containing(r + 1); emitted || strings.TrimSpace(line) == "" || isIDLine(line) {
			continue
		}
		switch {
		case kept < len(written) && line == strings.TrimRight(lines[written[kept]], " \t\r"):
			aligned[r] = written[kept]
			kept++
		case kept == len(written) && next >= 0 && strings.HasPrefix(line, valueLinePrefix(lines[next])):
			aligned[r] = next
			return aligned
		default:
			return aligned
		}
	}
	return aligned
}

// keywordEnd closes a control block.
const keywordEnd = "end"

// keywordElse starts the other branch of a control block.
const keywordElse = "else"

// blockOpeners are the actions that open a control block or a definition.
var blockOpeners = map[string]bool{"if": true, "with": true, "range": true, "define": true, "block": true}

// nonValueActions are the control actions that print no value of their own.
var nonValueActions = map[string]bool{
	keywordElse: true, "end": true, "break": true, "continue": true,
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

// renderedOnce reports whether target is the only line of rendered[from:to]
// with text that no marked include emitted.
func renderedOnce(rendered []string, invocations model.HelmInvocations, target, from, to int, text string) bool {
	for r := from; r < to && r < len(rendered); r++ {
		if _, emitted := invocations.Containing(r + 1); !emitted && r != target &&
			strings.TrimRight(rendered[r], " \t\r") == text {
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
	return false, !cannotPrint(actions, line, text)
}

// singleLineFunctions end a pipeline with the text of one line: their output
// has no line break.
var singleLineFunctions = map[string]bool{
	"quote": true, "int": true, "int64": true, "float64": true, "b64enc": true, "sha256sum": true,
	"toJson": true, "toRawJson": true,
}

// indentCannotPrint reports whether an indent of width, the action at start of
// line, cannot have printed text. Its padding is printed after the text before
// the action; a "{{-" trims the line break before it, so the output may
// continue the text of the line above and the text may start anywhere.
func indentCannotPrint(line string, start int, width, text string) bool {
	if strings.HasPrefix(line[start:], "{{-") {
		return false
	}
	n, err := strconv.Atoi(width)
	prefix := strings.TrimRight(line[:start], " \t\r")
	if err != nil || !strings.HasPrefix(text, prefix) || strings.TrimSpace(text[len(prefix):]) == "" {
		return false
	}
	rest := text[len(prefix):]
	return n > len(rest)-len(strings.TrimLeft(rest, " "))
}

// cannotPrint reports whether the one action of line cannot print text, as
// the last function of its pipeline bounds its output: indent and nindent
// indent every line of it by their width, and a single-line function leaves
// one line after the key that precedes the action.
func cannotPrint(actions []helmaction.Action, line, text string) bool {
	if len(actions) != 1 || actions[0].Comment || actions[0].Unterminated {
		return false
	}
	body := strings.Trim(line[actions[0].Start+2:actions[0].End-2], "- \t")
	fields := strings.Fields(lastStage(body))
	switch {
	case len(fields) == 2 && fields[0] == "nindent":
		width, err := strconv.Atoi(fields[1])
		return err == nil && width > len(text)-len(strings.TrimLeft(text, " "))
	case len(fields) == 2 && fields[0] == "indent":
		return indentCannotPrint(line, actions[0].Start, fields[1], text)
	case len(fields) == 1 && singleLineFunctions[fields[0]]:
		prefix := strings.TrimRight(line[:actions[0].Start], " \t")
		return strings.Contains(prefix, ":") && !strings.HasPrefix(text, prefix)
	}
	return false
}

// lastStage returns the last stage of the pipeline body, split at the last |
// outside parentheses and quotes.
func lastStage(body string) string {
	depth, quote, at := 0, rune(0), -1
	for i, r := range body {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '`' || r == '\'':
			quote = r
		case r == '(':
			depth++
		case r == ')':
			depth--
		case r == '|' && depth == 0:
			at = i
		}
	}
	return body[at+1:]
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
		if path != nil && isListIndex(key) && indexesList(lines, *path) {
			// A position in a list is no text to look for: the item is read in the
			// parsed document. After a mapping a number is a key, looked for as text.
			line, ok := itemLine(lines, *path, key)
			if !ok {
				d.breakRes = true
				break
			}
			d = detectCurlLine{foundRes: true, lineRes: line, lastUnique: dupHistory{unique: true, lastUniqueLine: line}}
			*path = append(*path, keyMatch{key: key, index: true, line: line})
			continue
		}
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

// isListIndex reports whether key is the position of a list item.
func isListIndex(key string) bool {
	_, err := strconv.Atoi(key)
	return err == nil && key != ""
}

// contradictsSelector reports whether line writes key with a literal value other
// than value. A value with an action in it may print any value.
func contradictsSelector(line, key, value string) bool {
	written, ok := writtenScalar(line, key+":")
	return ok && written != "" && written != value
}

// cutKey returns what follows marker, a key and its colon, at the start of
// text, the key being quoted or not.
func cutKey(text, marker string) (string, bool) {
	key := strings.TrimSuffix(marker, ":")
	for _, prefix := range []string{marker, `"` + key + `":`, `'` + key + `':`} {
		if rest, ok := strings.CutPrefix(text, prefix); ok {
			return rest, true
		}
	}
	return "", false
}

// writtenScalar returns the literal scalar of the key written at the start of
// line, after its indentation and any list dashes, as YAML reads it: without
// its quotes or a trailing comment. marker is the key and its colon, which the
// line may quote. It is
// false when the line does not start with marker, so that "hostname:" is not
// "name:", the value has an action in it or is not a scalar.
func writtenScalar(line, marker string) (string, bool) {
	rest := strings.TrimLeft(line, " \t")
	for strings.HasPrefix(rest, "- ") {
		rest = strings.TrimLeft(rest[len("- "):], " \t")
	}
	written, ok := cutKey(rest, marker)
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
	return quotedKeyStarts(line, key)
}

// quotedKeyStarts reports whether line holds the key quoted as a YAML key, not
// as text: outside any quoted scalar and any comment on the line. It covers a
// key at the start of a line after its indentation and list dashes, and one of
// an inline mapping, as in - {"name": web}, but not data: '{"name": web}'.
func quotedKeyStarts(line, key string) bool {
	key = strings.TrimSuffix(key, ":")
	for _, quoted := range []string{`"` + key + `":`, `'` + key + `':`} {
		for at := 0; ; {
			j := strings.Index(line[at:], quoted)
			if j < 0 {
				break
			}
			if outsideScalarsAndComments(line[:at+j]) {
				return true
			}
			at += j + len(quoted)
		}
	}
	return false
}

// outsideScalarsAndComments reports whether text ends outside any quoted scalar
// and before any comment. A quote opens a scalar only where a token starts, so
// the apostrophe of it's is text; a '#' starts a comment after a blank or at the
// start of the line.
func outsideScalarsAndComments(text string) bool {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			i, quote = consumeQuoted(text, i, quote)
			continue
		}
		if c == '#' && (i == 0 || text[i-1] == ' ' || text[i-1] == '\t') {
			return false
		}
		if (c == '"' || c == '\'') && tokenStarts(text[:i]) {
			quote = c
		}
	}
	return quote == 0
}

// consumeQuoted returns the index of the last character of text the scalar
// quoted with quote takes at i, and the quote still open after it (0 once the
// scalar closes).
func consumeQuoted(text string, i int, quote byte) (next int, open byte) {
	switch c := text[i]; {
	case quote == '"' && c == '\\':
		return i + 1, quote
	case c != quote:
		return i, quote
	case quote == '\'' && i+1 < len(text) && text[i+1] == '\'':
		return i + 1, quote
	}
	return i, 0
}

// tokenStarts reports whether a token starts after before: at the start of the
// line, or after an indicator that opens a node.
func tokenStarts(before string) bool {
	before = strings.TrimRight(before, " \t")
	return before == "" || strings.IndexByte(":-{[,?", before[len(before)-1]) >= 0
}

// nolint:gocritic
func (d detectCurlLine) detectCurrentLine(lines []string, str1,
	str2 string, byKey bool, idInfo map[int]interface{}, id int) (detectCurlLine, model.ResourceLine, model.ResourceLine) {
	distances := make(map[int]int)
	starts, ends := make(map[int]model.ResourceLine), make(map[int]model.ResourceLine)
	for i := d.lineRes; i < len(lines); i++ {
		if str1 != "" && str2 != "" {
			if containsHelmKey(lines[i], str1) && strings.Contains(lines[i], str2) {
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
