package docker

import "unicode/utf8"

type shellContext uint8

const (
	contextWord shellContext = iota
	contextDoubleQuote
	contextSingleQuote
	contextParameter
)

type shellReference struct {
	start, end, nameEnd int
}

func (r shellReference) braced(value string) bool {
	return r.start+1 < len(value) && value[r.start+1] == '{'
}

func (r shellReference) name(value string) string {
	start := r.start + 1
	if r.braced(value) {
		start++
	}
	return value[start:r.nameEnd]
}

type shellSyntax struct {
	references []shellReference // Opening order, including nested references.
	quotes     map[int]int
}

// A cursor consumes ordered references once, including those skipped by a
// complete quote or parameter span. Recovery needs no second reference map.
type shellReferences struct {
	items []shellReference
	next  int
}

func (c *shellReferences) end(pos int) int {
	for c.next < len(c.items) && c.items[c.next].start < pos {
		c.next++
	}
	if c.next < len(c.items) && c.items[c.next].start == pos {
		return c.items[c.next].end
	}
	return pos + 1
}

type shellFrame struct {
	kind      shellContext
	start     int
	reference int
	stop      byte // Replacement patterns stop on / before the final } operand.
}

type shellContextScanner struct {
	value   string
	escape  byte
	stack   []shellFrame
	syntax  shellSyntax
	ignored map[int]bool
	orphans []int
	plain   bool
	escaped bool // Word-boundary bookkeeping for malformed-input recovery only.
}

// scanShell uses the same context stack for protection and recovery. Parameters
// push an operand context even inside double quotes; a double-quoted operand
// pushes another context in which apostrophes are literal. Evaluation stays in
// BuildKit. Each pass is O(n); unclosed quotes need at most two repair passes.
func (e *wordExpander) scanShell(value string, quoted bool) shellSyntax {
	root := contextWord
	if quoted {
		root = contextDoubleQuote
	}
	var frames [8]shellFrame
	s := shellContextScanner{value: value, escape: e.escape, stack: frames[:0]}
	s.scan(root)
	var ignored map[int]bool
	for _, frame := range s.stack[1:] {
		if frame.kind == contextSingleQuote || frame.kind == contextDoubleQuote {
			if ignored == nil {
				ignored = make(map[int]bool)
			}
			ignored[frame.start] = true
		}
	}
	if len(ignored) == 0 {
		return s.syntax
	}
	for _, start := range s.orphans {
		ignored[start] = true
	}
	s.ignored = ignored
	s.scan(root)
	// Ignoring an unmatched double quote can expose a final single quote.
	// A single-quote frame consumes every byte up to the next apostrophe, so
	// an unclosed one starts at the last apostrophe in the input. Ignoring it
	// cannot expose another single-quote frame: one final pass is sufficient.
	last := s.stack[len(s.stack)-1]
	if last.kind == contextSingleQuote && last.start >= 0 {
		s.ignored[last.start] = true
		s.scan(root)
	}
	return s.syntax
}

func (s *shellContextScanner) scan(root shellContext) {
	s.stack = append(s.stack[:0], shellFrame{kind: root, start: -1})
	s.syntax = shellSyntax{}
	s.orphans = s.orphans[:0]
	s.plain, s.escaped = true, false
	for pos := 0; pos < len(s.value); {
		next := s.step(pos)
		// Keep the old recovery convention for contractions local to malformed
		// input. This bookkeeping does not decide shell quote nesting.
		for i := pos; i < next; i++ {
			s.wordBoundary(s.value[i])
		}
		pos = next
	}
}

func (s *shellContextScanner) step(pos int) int {
	frame := s.stack[len(s.stack)-1]
	ch := s.value[pos]
	if frame.kind == contextSingleQuote {
		if ch == '\'' {
			s.closeQuote(pos)
		}
		return pos + 1
	}
	if ch == s.escape {
		return s.escapeEnd(pos, frame.kind)
	}
	if ch == '$' {
		return s.reference(pos)
	}
	if frame.kind == contextDoubleQuote {
		if ch == '"' && len(s.stack) > 1 && !s.ignored[pos] {
			s.closeQuote(pos)
		}
		return pos + 1 // Apostrophes and braces are literal in this context.
	}
	if frame.kind == contextParameter && ch == frame.stop {
		if ch == '/' {
			s.stack[len(s.stack)-1].stop = '}'
		} else {
			s.syntax.references[frame.reference].end = pos + 1
			s.stack = s.stack[:len(s.stack)-1]
		}
		return pos + 1
	}
	return s.openQuote(pos)
}

func (s *shellContextScanner) openQuote(pos int) int {
	ch := s.value[pos]
	if (ch == '\'' || ch == '"') && !s.ignored[pos] {
		kind := contextSingleQuote
		if ch == '"' {
			kind = contextDoubleQuote
		}
		s.stack = append(s.stack, shellFrame{kind: kind, start: pos})
	}
	return pos + 1
}

func (s *shellContextScanner) escapeEnd(pos int, kind shellContext) int {
	if pos+1 == len(s.value) {
		return pos + 1
	}
	next := s.value[pos+1]
	if kind == contextDoubleQuote && next != '"' && next != '$' && next != s.escape {
		return pos + 1
	}
	_, size := utf8.DecodeRuneInString(s.value[pos+1:])
	return pos + 1 + size
}

func (s *shellContextScanner) reference(pos int) int {
	_, end, braced := referenceHead(s.value, pos)
	ref := len(s.syntax.references)
	s.syntax.references = append(s.syntax.references, shellReference{start: pos, nameEnd: end})
	if !braced {
		s.syntax.references[ref].end = end
		return end // Consume $$ and positional names atomically.
	}
	stop := byte('}')
	if end < len(s.value) && s.value[end] != '}' {
		operator := s.value[end]
		end++
		if operator == ':' && end < len(s.value) {
			operator = s.value[end]
			end++
		}
		if operator == '/' {
			stop = '/'
			if end < len(s.value) && s.value[end] == '/' {
				end++
			}
		}
	}
	s.stack = append(s.stack, shellFrame{kind: contextParameter, start: pos, reference: ref, stop: stop})
	return end
}

func (s *shellContextScanner) closeQuote(pos int) {
	frame := s.stack[len(s.stack)-1]
	if s.syntax.quotes == nil {
		s.syntax.quotes = make(map[int]int)
	}
	s.syntax.quotes[frame.start] = pos + 1
	if frame.kind == contextSingleQuote && s.plain && embeddedApostrophe(s.value, frame.start) &&
		pos+1 < len(s.value) && (variableNameByte(s.value[pos+1]) || s.value[pos+1] == '$') {
		s.orphans = append(s.orphans, frame.start)
	}
	s.stack = s.stack[:len(s.stack)-1]
}

func (s *shellContextScanner) wordBoundary(ch byte) {
	if s.escaped {
		s.escaped = false
		return
	}
	switch ch {
	case s.escape:
		s.escaped, s.plain = true, false
	case ' ', '\t', '\n':
		s.plain = true
	default:
		s.plain = s.plain && variableNameByte(ch)
	}
}

func embeddedApostrophe(value string, pos int) bool {
	return pos > 0 && pos+1 < len(value) && variableNameByte(value[pos-1]) && variableNameByte(value[pos+1])
}

func variableNameByte(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_'
}
