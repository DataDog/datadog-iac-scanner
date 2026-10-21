// Package dockerfile shares BuildKit source parsing between classification,
// document parsing and finding locations.
package dockerfile

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
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
	mu         sync.Mutex
	parsedOnce bool
	candidate  bool
	content    []byte
	parsed     *parser.Result
	err        error
	data       any
}

func preparedSource(ctx context.Context, content []byte) *sourceSnapshot {
	prepared, _ := ctx.Value(preparedSourceKey{}).(*sourceSnapshot)
	if prepared != nil {
		prepared.mu.Lock()
		matches := bytes.Equal(prepared.content, content)
		prepared.mu.Unlock()
		if matches {
			return prepared
		}
	}
	return nil
}

// PrepareSource computes an immutable, content-bound source snapshot for one
// dispatch. content must remain immutable until dispatch completes. Candidate
// headers are screened before parsing; classification and
// document parsing share the result, including parse errors. No global cache is
// retained. Callers must treat the returned AST as read-only.
func PrepareSource(ctx context.Context, content []byte, candidate bool) context.Context {
	if preparedSource(ctx, content) != nil {
		return ctx
	}
	prepared := &sourceSnapshot{content: content, candidate: candidate}
	return context.WithValue(ctx, preparedSourceKey{}, prepared)
}

func (s *sourceSnapshot) parse() (*parser.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.parsedOnce {
		s.parsedOnce = true
		if s.candidate {
			s.parsed, s.err = parseCandidate(bytes.NewReader(s.content))
		} else {
			s.parsed, s.err = parser.Parse(bytes.NewReader(s.content))
		}
	}
	return s.parsed, s.err
}

// SourceContext transfers only the immutable snapshot, without retaining an
// analysis context's cancellation or other request state. The recipient can
// reuse it for document parsing during dispatch.
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

type instructionRun struct{ first, last int }

// SourceLines records runs of adjacent instruction starts and only strings that
// differ from physical source. It retains neither the AST nor the input buffer.
// BuildKit owns continuation, escape, whitespace and heredoc interpretation.
type SourceLines struct {
	runs      []instructionRun
	overrides map[int]string
}

// CaptureSourceLines makes compact location metadata in O(bytes + instructions).
func CaptureSourceLines(parsed *parser.Result, content []byte) SourceLines {
	layout := SourceLines{}
	position, line := 0, 1
	for _, node := range parsed.AST.Children {
		for line < node.StartLine && position < len(content) {
			end := bytes.IndexByte(content[position:], '\n')
			if end < 0 {
				position = len(content)
				break
			}
			position += end + 1
			line++
		}
		if line != node.StartLine || node.StartLine < 1 {
			continue
		}
		end := bytes.IndexByte(content[position:], '\n')
		if end < 0 {
			end = len(content) - position
		}
		layout.record(node.StartLine, node.Original, string(content[position:position+end]))
	}
	return layout
}

func (layout *SourceLines) record(line int, logical, physical string) {
	// Adjacent instruction starts need only one range. Plain Dockerfiles
	// retain O(1) location metadata rather than an index per command.
	if n := len(layout.runs); n > 0 && layout.runs[n-1].last+1 == line {
		layout.runs[n-1].last = line
	} else {
		layout.runs = append(layout.runs, instructionRun{first: line, last: line})
	}
	logical = utils.StripCarriageReturns(logical)
	physical = utils.StripCarriageReturns(physical)
	// If BuildKit's complete instruction already occurs verbatim on its first
	// source line, retain that line's indentation, trailing whitespace and EOF
	// escape. Joined instructions still use BuildKit's logical text. A BOM is
	// parser metadata and remains stripped as in the fresh parse path.
	if strings.Contains(physical, logical) && !strings.HasPrefix(physical, "\ufeff") {
		return
	}
	if logical != physical {
		if layout.overrides == nil {
			layout.overrides = make(map[int]string)
		}
		layout.overrides[line] = logical
	}
}

// Apply reuses the physical slice unless masking or a logical instruction
// changes a line. Out-of-range instruction markers are ignored. Cost is O(lines).
func (layout SourceLines) Apply(original []string) []string {
	var lines []string
	child := 0
	for i, physical := range original {
		text := ""
		for child < len(layout.runs) && layout.runs[child].last < i+1 {
			child++
		}
		if child < len(layout.runs) && layout.runs[child].first <= i+1 {
			text = physical
			if override, ok := layout.overrides[i+1]; ok {
				text = override
			}
		}
		if text != physical && lines == nil {
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

func instructionLines(parsed *parser.Result, original []string) []string {
	// Fresh location requests use exactly the same compact representation.
	layout := SourceLines{}
	for _, node := range parsed.AST.Children {
		if node.StartLine > 0 && node.StartLine <= len(original) {
			layout.record(node.StartLine, node.Original, original[node.StartLine-1])
		}
	}
	return layout.Apply(original)
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

// RememberSource stores compact parser-owned location data for transfer to lazy
// location requests. It must not retain the BuildKit tree or source byte slice.
func RememberSource(ctx context.Context, data any) {
	if source, _ := ctx.Value(preparedSourceKey{}).(*sourceSnapshot); source != nil {
		source.mu.Lock()
		defer source.mu.Unlock()
		source.data = data
	}
}

// SavedSource returns immutable parser-owned metadata without changing ownership.
func SavedSource(ctx context.Context) any {
	source, _ := ctx.Value(preparedSourceKey{}).(*sourceSnapshot)
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.data
}

// DetachSource drops dispatch-only state after all consumers have finished.
func DetachSource(ctx context.Context) any {
	source, _ := ctx.Value(preparedSourceKey{}).(*sourceSnapshot)
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.content, source.parsed = nil, nil
	return source.data
}
