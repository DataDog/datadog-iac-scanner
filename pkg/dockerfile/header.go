package dockerfile

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// HasFrom rejects obvious non-Dockerfile headers before parsing the body. A
// qualifying header still requires one full BuildKit parse: the first non-ARG
// instruction must be FROM, and malformed bodies must be excluded as well.
func HasFrom(reader io.Reader) bool {
	var prefix bytes.Buffer
	scanner := bufio.NewScanner(io.TeeReader(reader, &prefix))
	if rejectsHeader(scanner, &prefix) || scanner.Err() != nil {
		return false
	}
	// Replay every byte read ahead by Scanner, including directives and BOM.
	// No growing prefix is parsed repeatedly; BuildKit owns continuation,
	// directive and heredoc semantics.
	parsed, err := parser.Parse(io.MultiReader(&prefix, reader))
	if err != nil {
		return false
	}
	for _, node := range parsed.AST.Children {
		if strings.EqualFold(node.Value, command.Arg) {
			continue
		}
		return strings.EqualFold(node.Value, command.From) && node.Next != nil
	}
	return false
}

// rejectsHeader is deliberately conservative: escape-bearing instructions are
// left to BuildKit. Buffering is bounded even for a large leading ARG section.
func rejectsHeader(scanner *bufio.Scanner, prefix *bytes.Buffer) bool {
	first := true
	for scanner.Scan() {
		if prefix.Len() >= bufio.MaxScanTokenSize {
			break
		}
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		word, _, _ := strings.Cut(line, " ")
		if end := strings.IndexAny(word, "\t\r\v\f"); end >= 0 {
			word = word[:end]
		}
		// A keyword or ARG can be continued. Defer ambiguous headers to
		// BuildKit rather than duplicating its escape/directive grammar. Simple
		// leading ARGs can be skipped without parsing their declaration values.
		if strings.ContainsAny(word, "\\`") {
			break
		}
		if !strings.EqualFold(word, command.Arg) && !strings.EqualFold(word, command.From) {
			return true
		}
		if strings.ContainsAny(line, "\\`") {
			break
		}
		if strings.EqualFold(word, command.Arg) {
			continue
		}
		break
	}
	return false
}
