package helm

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"
	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"helm.sh/helm/v3/pkg/chart"
)

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
	for _, action := range helmaction.Terminated(source) {
		span := [2]int{action.Start, action.End}
		actionText := strings.Trim(source[span[0]+len("{{"):span[1]-len("}}")], "- \t\r\n")
		fields := strings.Fields(actionText)
		if len(fields) == 0 {
			continue
		}
		if blocks.track(fields[0]) || blocks.inPartial() || !isHelmOutputInvocation(fields[0]) {
			continue
		}

		lineStart := strings.LastIndexByte(source[:span[0]], '\n') + 1
		marker := invocationMarker{Line: lines.lineOf(span[0]), Col: span[0] - lineStart}.String()
		if r, ok := invocationReplacement(source, span, actionText, marker, wrapper); ok {
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
func invocationReplacement(source string, span [2]int, actionText, marker string, wrapper bool) (replacement, bool) {
	if !wrapper && !standaloneUntrimmedAction(source, span) {
		return replacement{}, false
	}
	lineStart := strings.LastIndexByte(source[:span[0]], '\n') + 1
	action := source[span[0]:span[1]]
	lead := marker
	if wrapper {
		lead = "\n" + marker
	}
	if strings.HasPrefix(actionText, helmInclude) && (wrapper || span[0] == lineStart) {
		return replacement{start: span[0], end: span[1], text: markEveryDocument(action, lead, marker)}, true
	}
	prefix := fmt.Sprintf("{{ print %q }}", lead)
	if wrapper {
		return replacement{start: span[0], end: span[1], text: prefix + action}, true
	}
	// Emitted before the line's indentation so the include output keeps it.
	return replacement{start: lineStart, end: span[1], text: prefix + source[lineStart:span[0]] + action}, true
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
	lineStart := strings.LastIndexByte(source[:span[0]], '\n') + 1
	if strings.HasSuffix(strings.TrimRight(source[:lineStart], " \t\r\n"), "-}}") {
		return false
	}
	lineEnd := len(source)
	if i := strings.IndexByte(source[span[1]:], '\n'); i >= 0 {
		lineEnd = span[1] + i
	}
	return strings.TrimSpace(source[lineStart:span[0]]) == "" &&
		strings.TrimSpace(source[span[1]:lineEnd]) == "" &&
		!insideBlockScalar(source[:lineStart])
}

var blockScalarHeader = regexp.MustCompile(`[|>][+-]?\d?[+-]?(?:\s+#.*)?\s*$`)

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
const helmDocumentSeparator = `\n(---(?:[ \t][^\n]*|\r)?\n)(\s*\S)`

// markEveryDocument makes an include print lead ahead of its output and marker
// after each document separator in it. Helm splits and sorts every template's
// documents before the resolver sees them, so a marker printed only ahead of
// the include never reaches documents after the first separator. lead ends
// with a newline, so a separator opening the output is matched too.
func markEveryDocument(templateAction, lead, marker string) string {
	inner := templateAction[len("{{") : len(templateAction)-len("}}")]
	left, right := "", ""
	if strings.HasPrefix(inner, "-") {
		left, inner = "-", inner[1:]
	}
	if strings.HasSuffix(inner, "-") {
		right, inner = "-", inner[:len(inner)-1]
	}
	return fmt.Sprintf(`{{%s regexReplaceAll %q (print %q (%s)) %q %s}}`,
		left, helmDocumentSeparator, lead, inner, "\n${1}"+marker+"${2}", right)
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
