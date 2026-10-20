// Package dockerfile shares BuildKit source parsing between classification,
// document parsing and finding locations.
package dockerfile

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// SourceViewKey identifies the shared logical source view in file metadata.
const SourceViewKey = "docker.source"

type sourceLinesKey struct{}
type sourceLinesRecorder struct {
	original []string
	record   func([]string)
}

// WithSourceLines records logical instruction lines while parsing line info.
// The detector then reuses these lines without decoding the document's schema
// or parsing again. The callback receives an immutable, physically indexed view.
func WithSourceLines(ctx context.Context, original []string, record func([]string)) context.Context {
	return context.WithValue(ctx, sourceLinesKey{}, sourceLinesRecorder{original: original, record: record})
}

// Parse builds the source AST and optionally records its instruction view.
func Parse(ctx context.Context, content []byte) (*parser.Result, error) {
	parsed, err := parser.Parse(bytes.NewReader(content))
	if err == nil {
		if recorder, ok := ctx.Value(sourceLinesKey{}).(sourceLinesRecorder); ok {
			recorder.record(instructionLines(parsed, recorder.original))
		}
	}
	return parsed, err
}

// InstructionLines builds the same view for callers without a line-info loader.
// BuildKit joins continuations and excludes heredoc payloads from node.Original.
func InstructionLines(original []string) []string {
	parsed, err := parser.Parse(strings.NewReader(strings.Join(original, "\n")))
	if err != nil {
		return original
	}
	return instructionLines(parsed, original)
}

// instructionLines reuses physical source strings wherever BuildKit's logical
// text is identical. Files without continuations, comments or heredocs can reuse
// the entire source slice and its existing substring index.
func instructionLines(parsed *parser.Result, original []string) []string {
	var lines []string
	child := 0
	for i, physical := range original {
		text := ""
		if child < len(parsed.AST.Children) && parsed.AST.Children[child].StartLine == i+1 {
			text = parsed.AST.Children[child].Original
			child++
		}
		if text == physical {
			text = physical
		} else if lines == nil {
			lines = slices.Clone(original)
		}
		if lines != nil {
			lines[i] = text
		}
	}
	if lines == nil {
		return original
	}
	return lines
}

// FromArguments returns the raw arguments of a FROM instruction, including
// flags and an optional alias. Non-instructions and keyword prefixes return "".
func FromArguments(original string) string {
	original = strings.TrimSpace(original)
	end := strings.IndexAny(original, " \t\r\n\f")
	if end < 0 || !strings.EqualFold(original[:end], "FROM") {
		return ""
	}
	return strings.TrimSpace(original[end:])
}
