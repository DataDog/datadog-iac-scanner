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
}

type shellFrame struct {
	kind      shellContext
	reference int
	stop      byte // Replacement patterns stop on / before the final } operand.
}

type shellContextScanner struct {
	value  string
	escape byte
	stack  []shellFrame
	syntax shellSyntax
}

// scanShell identifies references in one O(n) context-stack walk. It never
// repairs quotes or evaluates expressions; BuildKit owns complete-word parsing.
// The same immutable spans drive unknown-name protection and plain recovery.
func (e *wordExpander) scanShell(value string, quoted bool) shellSyntax {
	root := contextWord
	if quoted {
		root = contextDoubleQuote
	}
	var frames [8]shellFrame
	s := shellContextScanner{value: value, escape: e.escape, stack: frames[:0]}
	s.stack = append(s.stack, shellFrame{kind: root})
	for pos := 0; pos < len(value); {
		pos = s.step(pos)
	}
	return s.syntax
}

func (s *shellContextScanner) step(pos int) int {
	frame := s.stack[len(s.stack)-1]
	ch := s.value[pos]
	if frame.kind == contextSingleQuote {
		if ch == '\'' {
			s.closeQuote()
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
		if ch == '"' && len(s.stack) > 1 {
			s.closeQuote()
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
	if ch == '\'' || ch == '"' {
		kind := contextSingleQuote
		if ch == '"' {
			kind = contextDoubleQuote
		}
		s.stack = append(s.stack, shellFrame{kind: kind})
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
			// A colon modifier such as :/ uses a }-terminated operand,
			// rather than the direct / modifier's pattern delimiter.
			// BuildKit decides whether the modifier itself is supported.
			end++
		}
		if operator == '/' {
			stop = '/'
			if end < len(s.value) && s.value[end] == '/' {
				end++
			}
		}
	}
	s.stack = append(s.stack, shellFrame{kind: contextParameter, reference: ref, stop: stop})
	return end
}

func (s *shellContextScanner) closeQuote() {
	s.stack = s.stack[:len(s.stack)-1]
}
