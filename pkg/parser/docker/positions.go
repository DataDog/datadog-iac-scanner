package docker

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type position struct{ line, column int }

// source maps an instruction and the scripts it runs back to the file. It
// rebuilds the logical line the way BuildKit joins continuation lines,
// remembering where each byte came from.
type source struct {
	lines        []string
	continuation *regexp.Regexp
}

func newSource(content []byte, escape rune) *source {
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	token := regexp.QuoteMeta(string(escape))
	return &source{
		lines:        strings.Split(text, "\n"),
		continuation: regexp.MustCompile(fmt.Sprintf(`([^%s])%s[ \t]*$`, token, token)),
	}
}

func (s *source) instruction(node *parser.Node) model.Source {
	if s == nil || node.EndLine > len(s.lines) || node.StartLine < 1 {
		return model.Source{Line: node.StartLine, EndLine: node.EndLine}
	}
	first := s.lines[node.StartLine-1]
	return model.Source{
		Line: node.StartLine, Column: len(first) - len(strings.TrimLeft(first, " \t")),
		EndLine: node.EndLine, EndColumn: len(s.lines[node.EndLine-1]),
	}
}

// script returns the file position of every byte of script, or nil when the
// script is not a verbatim part of the instruction's lines.
func (s *source) script(node *parser.Node, script string, heredoc bool) []position {
	if s == nil || node.EndLine > len(s.lines) || node.StartLine < 1 {
		return nil
	}
	text, positions, last := s.logical(node)
	if heredoc {
		return s.heredoc(script, last+1, node.EndLine-1)
	}
	at := strings.LastIndex(text, script)
	if at < 0 {
		return nil
	}
	return positions[at : at+len(script)]
}

func (s *source) logical(node *parser.Node) (text string, positions []position, last int) {
	var joinedText strings.Builder
	appendLine := func(line, column int, raw string) bool {
		joined := raw
		continues := s.continuation.MatchString(raw)
		if continues {
			joined = s.continuation.ReplaceAllString(raw, "$1")
		}
		for i := range len(joined) {
			positions = append(positions, position{line: line, column: column + i})
		}
		joinedText.WriteString(joined)
		return continues
	}
	first := s.lines[node.StartLine-1]
	trimmed := strings.TrimLeft(first, " \t")
	line := node.StartLine
	continues := appendLine(line, len(first)-len(trimmed), trimmed)
	for continues && line < node.EndLine {
		line++
		raw := s.lines[line-1]
		blank := strings.TrimLeft(raw, " \t")
		if blank == "" || strings.HasPrefix(blank, "#") {
			continue
		}
		continues = appendLine(line, 0, raw)
	}
	return joinedText.String(), positions, line
}

// heredoc maps a heredoc body, one script line per file line. A removed tab
// prefix (<<-) shifts columns by the width the file line has in excess.
func (s *source) heredoc(script string, first, last int) []position {
	scriptLines := strings.SplitAfter(script, "\n")
	positions := make([]position, 0, len(script))
	for i, scriptLine := range scriptLines {
		if scriptLine == "" {
			continue
		}
		line := first + i
		content := strings.TrimSuffix(scriptLine, "\n")
		if line > last || !strings.HasSuffix(s.lines[line-1], content) {
			return nil
		}
		shift := len(s.lines[line-1]) - len(content)
		for j := range len(scriptLine) {
			positions = append(positions, position{line: line, column: shift + j})
		}
	}
	return positions
}

func locate(positions []position, span shell.Span) *model.Source {
	if span.End <= span.Start || span.End > len(positions) {
		return nil
	}
	start, end := positions[span.Start], positions[span.End-1]
	return &model.Source{Line: start.line, Column: start.column, EndLine: end.line, EndColumn: end.column + 1}
}

// locateFacts sets the file range of the calls, pipelines and packages of
// facts analyzed from a script whose bytes sit at positions.
func locateFacts(facts *shell.Facts, positions []position) {
	if positions == nil {
		return
	}
	for i := range facts.Calls {
		facts.Calls[i].Source = locate(positions, facts.Calls[i].Span)
	}
	for i := range facts.Pipelines {
		facts.Pipelines[i].Source = locate(positions, facts.Pipelines[i].Span)
	}
	for i := range facts.PackageCommands {
		command := &facts.PackageCommands[i]
		call := &facts.Calls[command.Call]
		command.Source = call.Source
		for j := range command.Packages {
			pkg := &command.Packages[j]
			if pkg.Argument < len(call.ArgumentSpans) {
				pkg.Source = locate(positions, call.ArgumentSpans[pkg.Argument])
			}
		}
	}
}
