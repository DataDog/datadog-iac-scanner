// Package dockerfile shares BuildKit source parsing between classification,
// document parsing and finding locations.
package dockerfile

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"

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

type preparedSourceKey struct{}
type sourceSnapshot struct {
	once      sync.Once
	candidate bool
	content   []byte
	parsed    *parser.Result
	err       error
}

func preparedSource(ctx context.Context, content []byte) *sourceSnapshot {
	prepared, _ := ctx.Value(preparedSourceKey{}).(*sourceSnapshot)
	if prepared != nil && bytes.Equal(prepared.content, content) {
		return prepared
	}
	return nil
}

// PrepareSource computes an immutable, content-bound source snapshot for one
// dispatch. Candidate headers are screened before parsing; classification and
// document parsing share the result, including parse errors. No global cache is
// retained. Callers must treat the returned AST as read-only.
func PrepareSource(ctx context.Context, content []byte, candidate bool) context.Context {
	if preparedSource(ctx, content) != nil {
		return ctx
	}
	prepared := &sourceSnapshot{content: bytes.Clone(content), candidate: candidate}
	return context.WithValue(ctx, preparedSourceKey{}, prepared)
}

func (s *sourceSnapshot) parse() (*parser.Result, error) {
	s.once.Do(func() {
		if s.candidate {
			s.parsed, s.err = parseCandidate(bytes.NewReader(s.content))
		} else {
			s.parsed, s.err = parser.Parse(bytes.NewReader(s.content))
		}
	})
	return s.parsed, s.err
}

// SourceContext transfers only the immutable snapshot, without retaining an
// analysis context's cancellation or other request state. The recipient can
// reuse it for document parsing and lazy line-info generation.
func SourceContext(ctx context.Context) func(context.Context) context.Context {
	prepared, _ := ctx.Value(preparedSourceKey{}).(*sourceSnapshot)
	if prepared == nil {
		return nil
	}
	return func(next context.Context) context.Context {
		return context.WithValue(next, preparedSourceKey{}, prepared)
	}
}

// Parse builds the source AST and optionally records its instruction view.
func Parse(ctx context.Context, content []byte) (*parser.Result, error) {
	var parsed *parser.Result
	var err error
	if prepared := preparedSource(ctx, content); prepared != nil {
		parsed, err = prepared.parse()
	} else {
		parsed, err = parser.Parse(bytes.NewReader(content))
	}
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
	end := strings.IndexAny(original, " \t\r\n\v\f")
	if end < 0 || !strings.EqualFold(original[:end], "FROM") {
		return ""
	}
	return strings.TrimSpace(original[end:])
}
