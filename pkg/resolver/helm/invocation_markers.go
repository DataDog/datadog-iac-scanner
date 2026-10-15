package helm

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"
	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"helm.sh/helm/v3/pkg/chart"
)

// invocationPrefix starts every invocation marker line.
const invocationPrefix = "# KICS_HELM_INVOCATION_"

// invocationEnd is the line printed after the output of a marked include, so
// the rendered lines it emitted are known exactly.
const invocationEnd = invocationPrefix + "END:"

// invocationMarker is printed ahead of the output of an include and records
// where the action is in the template as written, without ID stamps: its
// 1-based line and 0-based byte column. "# KICS_HELM_INVOCATION_<line>_<col>:".
type invocationMarker struct {
	Line, Col int
}

// String is the marker line, with its line break.
func (m invocationMarker) String() string {
	return invocationPrefix + strconv.Itoa(m.Line) + "_" + strconv.Itoa(m.Col) + ":\n"
}

// parseInvocationMarker reads a marker line, as String writes it.
func parseInvocationMarker(line string) (invocationMarker, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), invocationPrefix)
	if !ok {
		return invocationMarker{}, false
	}
	rest, ok = strings.CutSuffix(rest, ":")
	if !ok {
		return invocationMarker{}, false
	}
	lineText, colText, ok := strings.Cut(rest, "_")
	if !ok {
		return invocationMarker{}, false
	}
	l, lErr := strconv.ParseUint(lineText, 10, 31)
	c, cErr := strconv.ParseUint(colText, 10, 31)
	return invocationMarker{Line: int(l), Col: int(c)}, lErr == nil && cErr == nil
}

// hasInvocationMarker reports whether content may hold a marker.
func hasInvocationMarker(content string) bool {
	return strings.Contains(content, invocationPrefix)
}

// indentedInvocationEnd matches an end, indented when an include's output
// holding it went through "indent", and the line break before it.
var indentedInvocationEnd = regexp.MustCompile(`(^|\n)[ \t]*` + regexp.QuoteMeta(invocationEnd))

// removeInvocationEnds drops every end and the line break before it.
func removeInvocationEnds(content string) string {
	return indentedInvocationEnd.ReplaceAllString(content, "")
}

// removeInvocationMarkers drops every marker line and end from content.
func removeInvocationMarkers(content string) string {
	if !hasInvocationMarker(content) {
		return content
	}
	content = removeInvocationEnds(content)
	var kept strings.Builder
	kept.Grow(len(content))
	for content != "" {
		line := content
		if i := strings.IndexByte(content, '\n'); i >= 0 {
			line = content[:i+1]
		}
		content = content[len(line):]
		if _, ok := parseInvocationMarker(line); !ok {
			kept.WriteString(line)
		}
	}
	return kept.String()
}

// addHelmInvocationMarkers instruments manifest templates so the rendered
// output retains the source position of the invocation that actually ran, which
// is what lets a finding in output produced by a named template point back to
// the file that invoked it. The marker is printed just ahead of the output of
// include/template/tpl, which keeps it under the same Helm control flow as the
// invocation.
//
// Two kinds of invocation are instrumented, and nothing else:
//   - any top-level invocation of an action-only wrapper template, whose whole
//     output is the output of its invocations;
//   - in other manifest templates, an invocation that stands alone on its line
//     and is not left-trimmed, which can only emit a block of YAML. Inline
//     uses (`name: {{ include ... }}`) and trimmed ones (`{{- include ... }}`)
//     produce values glued to the surrounding text and are left alone.
//
// The body of a define or block is never instrumented: it is a named partial
// whose result is used by its callers, often as a scalar (a label value, a
// name), so anything added there would corrupt every value the partial returns.
// Files that only hold partials (a leading underscore) are skipped for the same
// reason.
func addHelmInvocationMarkers(file *chart.File) *chart.File {
	source := string(file.Data)
	if hasInvocationMarker(source) {
		return file
	}
	wrapper := isHelmInvocationWrapper(source)
	if !wrapper && strings.HasPrefix(filepath.Base(file.Name), "_") {
		return file
	}
	var markers []replacement
	var blocks helmBlockStack
	lines := sourceLines{source: source, line: 1}
	// commentsOnly holds while every action before the current one is a comment.
	commentsOnly := true
	for _, action := range helmaction.Terminated(source) {
		first := commentsOnly
		commentsOnly = commentsOnly && action.Comment
		span := [2]int{action.Start, action.End}
		actionText := strings.Trim(source[span[0]+len("{{"):span[1]-len("}}")], "- \t\r\n")
		fields := strings.Fields(actionText)
		if len(fields) == 0 {
			continue
		}
		if blocks.track(fields[0]) || blocks.inPartial() || !isHelmOutputInvocation(fields[0]) {
			continue
		}

		lineStart, _ := lineBounds(source, span[0])
		marker := invocationMarker{Line: lines.lineOf(span[0]), Col: span[0] - lineStart}.String()
		opensTemplate := first && startsTemplate(source, span, actionText)
		if r, ok := invocationReplacement(source, span, actionText, marker, wrapper, opensTemplate); ok {
			markers = append(markers, r)
		}
	}

	sort.Slice(markers, func(i, j int) bool {
		return markers[i].start > markers[j].start
	})
	for _, marker := range markers {
		source = source[:marker.start] + marker.text + source[marker.end:]
	}
	file.Data = []byte(source)
	return file
}

// sourceLines numbers the lines of a stamped template as the template is
// written, leaving its ID stamps out. Positions are asked in increasing order.
type sourceLines struct {
	source string
	// at is the start of the line numbered line.
	at, line int
}

// lineOf returns the 1-based line of the template as written that pos is on.
func (s *sourceLines) lineOf(pos int) int {
	for {
		end := strings.IndexByte(s.source[s.at:pos], '\n')
		if end < 0 {
			return s.line
		}
		if _, stamp := helmmarker.ParseIDLine(s.source[s.at : s.at+end]); !stamp {
			s.line++
		}
		s.at += end + 1
	}
}

// invocationReplacement builds the marker edit for one include-like action.
//
// The marker is printed ahead of the action's output. In a wrapper template it
// starts with a newline of its own: the output before it may not end with one,
// as when a "-}}" trimmed it, and a blank line there is harmless. In a mixed
// manifest the marker precedes the indentation of the action's line instead.
//
// An include is rewritten to print the marker itself and repeat it in every
// document its output holds; in a mixed manifest only an include starting its
// line is, since the marker could not precede the indentation otherwise.
// template is an action and tpl rarely emits documents, so neither is rewritten.
//
// The output is closed by an end line (see invocationEndText), and so is every
// document it holds, which bounds the rendered lines the action emitted.
func invocationReplacement(source string, span [2]int, actionText, marker string,
	wrapper, opensTemplate bool,
) (replacement, bool) {
	lineStart, _ := lineBounds(source, span[0])
	action := source[span[0]:span[1]]
	lead := marker
	if wrapper {
		lead = "\n" + marker
	}
	end := invocationEndText(source, span)
	switch {
	case wrapper || standaloneUntrimmedAction(source, span):
	case trimmedStandaloneNindent(source, span, actionText):
		// The "-" removed the line break before the action and nindent prints
		// one first: the marker takes that line break, and indent keeps the
		// output as Helm prints it.
		action = trailingNindent.ReplaceAllString(action, "| indent ${1} ${2}")
		lead = "\n" + marker
	case opensTemplate:
		// The marker starts a line of its own after "---" or the start of the
		// template, so the marker's leading line break is not needed.
	default:
		return replacement{}, false
	}
	startsLine := wrapper || span[0] == lineStart || lead != marker || opensTemplate
	if strings.HasPrefix(actionText, helmInclude) && startsLine {
		return replacement{start: span[0], end: span[1], text: markEveryDocument(action, lead, marker, end)}, true
	}
	prefix := fmt.Sprintf("{{ print %q }}", lead)
	suffix := ""
	if end != "" {
		suffix = fmt.Sprintf("{{ print %q }}", end)
	}
	if wrapper {
		return replacement{start: span[0], end: span[1], text: prefix + action + suffix}, true
	}
	// Emitted before the line's indentation so the include output keeps it.
	return replacement{start: lineStart, end: span[1], text: prefix + source[lineStart:span[0]] + action + suffix}, true
}

// trailingNindent matches a final "| nindent N" stage of an action.
var trailingNindent = regexp.MustCompile(`\|\s*nindent\s+(\d+)\s*(-?\}\})$`)

// trimmedStandaloneNindent reports whether the action at span is a left-trimmed
// include alone on its line whose output goes through "nindent", outside any
// block scalar.
func trimmedStandaloneNindent(source string, span [2]int, actionText string) bool {
	if !strings.HasPrefix(source[span[0]:], "{{-") || !strings.HasPrefix(actionText, helmInclude) ||
		!trailingNindent.MatchString(source[span[0]:span[1]]) {
		return false
	}
	lineStart, _ := lineBounds(source, span[0])
	_, lineEnd := lineBounds(source, span[1])
	return strings.TrimSpace(source[lineStart:span[0]]) == "" && strings.TrimSpace(source[span[1]:lineEnd]) == "" &&
		!insideBlockScalar(source[:lineStart])
}

// startsTemplate reports whether the action at span is a left-trimmed include
// that starts its template, or a document, which the "-" then trims nothing
// but the line break before. The marker, which starts with a line break, then
// keeps the output on a line of its own: a document starts after "---" or the
// start of the template, with only blanks, comments and ID stamps before it.
// Every action before span must be a comment, which the caller checks.
func startsTemplate(source string, span [2]int, actionText string) bool {
	if !strings.HasPrefix(source[span[0]:], "{{-") || !strings.HasPrefix(actionText, helmInclude) {
		return false
	}
	content := ""
	for _, line := range strings.Split(helmaction.Remove(source[:span[0]]), "\n") {
		if _, stamp := helmmarker.ParseIDLine(line); !stamp && strings.TrimSpace(line) != "" {
			content = line
		}
	}
	return content == "" || isYAMLDocumentBoundary(content)
}

// startsWithNindent reports whether text starts with an action ending with a
// "| nindent N" stage, whose output starts with a line break: nothing printed
// before it is glued to what precedes it.
func startsWithNindent(text string) bool {
	if !strings.HasPrefix(text, "{{") {
		return false
	}
	end := strings.Index(text, "}}")
	return end >= 0 && trailingNindent.MatchString(text[:end+2])
}

// silentTrimmedAction matches a "{{-" action that prints nothing and keeps the
// line break after it, so it glues nothing to the output before it.
var silentTrimmedAction = regexp.MustCompile(`^\{\{-\s+(?:(?:end|else)\b[^}]*[^-]|/\*(?:[^*]|\*[^/])*\*/\s*)\}\}`)

// invocationEndText is printed after the output of the action at span to put
// the end line after it. The line break before the end is its own, so removing
// both restores the output as Helm prints it, along with any text that follows
// the action on its line. When a "-}}" ends the action, or a "{{-" starts the
// text after it that prints, that text is glued to the output on purpose, and an end in
// between would split what Helm parses: it is left out, and the extent of the
// action stays unknown unless its output ends a line (see markEveryDocument).
func invocationEndText(source string, span [2]int) string {
	after := strings.TrimLeft(source[span[1]:], " \t\r\n")
	if after != "" && strings.HasSuffix(source[span[0]:span[1]], "-}}") && !startsWithNindent(after) ||
		strings.HasPrefix(after, "{{-") && !silentTrimmedAction.MatchString(after) && !startsWithNindent(after) {
		return ""
	}
	return "\n" + invocationEnd
}

// standaloneUntrimmedAction reports whether the action at span is alone on its
// line and no whitespace before it is trimmed, by the action itself or by a
// right-trimming action ("-}}") ending the text before its line. Either would
// remove the newline before a marker inserted at the start of the line and
// glue it to the previous output.
func standaloneUntrimmedAction(source string, span [2]int) bool {
	if strings.HasPrefix(source[span[0]:], "{{-") {
		return false
	}
	lineStart, _ := lineBounds(source, span[0])
	if strings.HasSuffix(strings.TrimRight(source[:lineStart], " \t\r\n"), "-}}") {
		return false
	}
	_, lineEnd := lineBounds(source, span[1])
	// An unindented action at column 0 ends a block scalar, as its output does,
	// unless the output is indented by "indent" or "nindent".
	endsScalar := span[0] == lineStart && !strings.Contains(source[span[0]:span[1]], "indent")
	// A comment after the action prints nothing, so it is not text of the line.
	rest := strings.TrimSpace(source[span[1]:lineEnd])
	return strings.TrimSpace(source[lineStart:span[0]]) == "" &&
		(rest == "" || strings.HasPrefix(rest, "{{/*")) &&
		(endsScalar || !insideBlockScalar(source[:lineStart]))
}

var blockScalarHeader = regexp.MustCompile(`[|>][+-]?\d?[+-]?(?:\s+#.*)?\s*$`)

// lineBounds returns the start of the line holding pos and the line break that
// ends it, or the end of the template.
func lineBounds(source string, pos int) (start, end int) {
	start = strings.LastIndexByte(source[:pos], '\n') + 1
	end = len(source)
	if i := strings.IndexByte(source[pos:], '\n'); i >= 0 {
		end = pos + i
	}
	return start, end
}

// insideBlockScalar reports whether the text before an action may belong to a
// YAML block scalar: walking back over indented lines reaches a "|" or ">"
// header whose content they all are, being indented more than it. A column-0
// marker line would terminate such a scalar, so these actions are left
// uninstrumented.
func insideBlockScalar(before string) bool {
	walked := -1 // the least indentation of the lines walked over, -1 for none
	for end := len(before); end > 0; {
		start := strings.LastIndexByte(before[:end-1], '\n') + 1
		line := strings.TrimRight(helmaction.Remove(before[start:end]), " \t\r\n")
		end = start
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if blockScalarHeader.MatchString(line) && (walked < 0 || walked > indent) {
			return true
		}
		if indent == 0 {
			return false
		}
		if walked < 0 || indent < walked {
			walked = indent
		}
	}
	return false
}

// helmBlockStack follows the control-flow blocks opened by template actions so
// an action can be told apart as top-level output or part of a define body.
type helmBlockStack []bool

// track updates the stack for an action starting with keyword and reports
// whether the action only opens or closes a block.
func (b *helmBlockStack) track(keyword string) bool {
	switch keyword {
	case "define", "block":
		*b = append(*b, true)
	case "if", "range", "with":
		*b = append(*b, false)
	case "end":
		if len(*b) > 0 {
			*b = (*b)[:len(*b)-1]
		}
	default:
		return false
	}
	return true
}

// inPartial reports whether the current action sits inside a define or block.
func (b helmBlockStack) inPartial() bool {
	for _, partial := range b {
		if partial {
			return true
		}
	}
	return false
}

// helmDocumentSeparator matches a document separator in an include's output that
// has a document after it, keeping the separator line and what follows. A
// trailing separator is left alone: the document after it is not the include's.
const helmDocumentSeparator = `\n((?:---(?:[ \t][^\n]*|\r)?\n)+)(\s*\S)`

// markEveryDocument makes an include print lead ahead of its output, end after
// it, and marker after each document separator in it, preceded by an end line.
// Helm splits and sorts every template's documents before the resolver sees
// them, so a marker printed only ahead of the include never reaches documents
// after the first separator. lead ends with a newline, so a separator opening
// the output is matched too, and the end line follows the output, so a
// separator closing it is matched as well.
func markEveryDocument(templateAction, lead, marker, end string) string {
	inner := templateAction[len("{{") : len(templateAction)-len("}}")]
	left, right := "", ""
	if strings.HasPrefix(inner, "-") {
		left, inner = "-", inner[1:]
	}
	if strings.HasSuffix(inner, "-") {
		right, inner = "-", inner[:len(inner)-1]
	}
	output := fmt.Sprintf(`(print %q (%s) %q)`, lead, inner, end)
	if end == "" {
		// Text glued to the output is not split from it when the output ends a
		// line: the end then fits on a line of its own.
		output = fmt.Sprintf(`(regexReplaceAll %q (print %q (%s)) %q)`,
			`\n\z`, lead, inner, "\n"+invocationEnd+"\n")
	}
	return fmt.Sprintf(`{{%s regexReplaceAll %q %s %q %s}}`,
		left, helmDocumentSeparator, output, "\n"+invocationEnd+"\n${1}"+marker+"${2}", right)
}

func isHelmInvocationWrapper(source string) bool {
	// A quoted "}}" must not end an action early and leave residue that
	// disqualifies a wrapper template which is in fact action-only.
	withoutActions := helmaction.Remove(source)
	for _, line := range strings.Split(withoutActions, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !isYAMLDocumentBoundary(trimmed) {
			return false
		}
	}
	return true
}

const helmInclude = "include"

func isHelmOutputInvocation(name string) bool {
	return name == helmInclude || name == "template" || name == "tpl"
}
