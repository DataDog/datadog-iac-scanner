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
	anchors map[int]int // Balanced quote openers from the original shell contexts.
	orphans []int
	plain   bool
	escaped bool // Word-boundary bookkeeping for malformed-input recovery only.
	repair  bool
}

// scanShell uses the same context stack for protection and recovery. Parameters
// push an operand context even inside double quotes; a double-quoted operand
// pushes another context in which apostrophes are literal. Evaluation stays in
// BuildKit. Each pass is O(n). Repair repeats only when a previously active
// quote is ignored, so it terminates in at most q+1 passes for q quote positions;
// the worst-case bound is O(n*q), not a fixed number of linear passes.
func (e *wordExpander) scanShell(value string, quoted bool) shellSyntax {
	root := contextWord
	if quoted {
		root = contextDoubleQuote
	}
	var frames [8]shellFrame
	s := shellContextScanner{value: value, escape: e.escape, stack: frames[:0]}
	s.scan(root, false)
	if !s.ignoreBrokenQuotes() {
		return s.syntax
	}
	// A contraction exposed by repair must yield to a quote opener already
	// identified in the original parameter context (for example :-'word').
	s.anchors, s.syntax.quotes = s.syntax.quotes, nil
	for {
		s.scan(root, true)
		if !s.ignoreBrokenQuotes() {
			return s.syntax
		}
	}
}

func (s *shellContextScanner) ignoreBrokenQuotes() bool {
	changed := false
	ignore := func(pos int) {
		if s.ignored == nil {
			s.ignored = make(map[int]bool)
		}
		if !s.ignored[pos] {
			s.ignored[pos] = true
			changed = true
		}
	}
	// Fix misplaced contraction openers before ignoring unmatched quotes:
	// those apparent unmatched quotes may close correctly on the next pass.
	if len(s.orphans) > 0 {
		for _, start := range s.orphans {
			ignore(start)
		}
		return changed
	}
	for _, frame := range s.stack[1:] {
		if frame.kind == contextSingleQuote || frame.kind == contextDoubleQuote {
			ignore(frame.start)
		}
	}
	return changed
}

func (s *shellContextScanner) scan(root shellContext, repair bool) {
	s.stack = append(s.stack[:0], shellFrame{kind: root, start: -1})
	s.syntax.references = s.syntax.references[:0]
	clear(s.syntax.quotes)
	s.orphans = s.orphans[:0]
	s.plain, s.escaped, s.repair = true, false, repair
	for pos := 0; pos < len(s.value); {
		next := s.step(pos)
		// Only malformed-input repair needs contraction bookkeeping.
		if repair {
			for i := pos; i < next; i++ {
				s.wordBoundary(s.value[i])
			}
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
	s.stack = append(s.stack, shellFrame{kind: contextParameter, start: pos, reference: ref, stop: stop})
	return end
}

func (s *shellContextScanner) closeQuote(pos int) {
	frame := s.stack[len(s.stack)-1]
	if s.syntax.quotes == nil {
		s.syntax.quotes = make(map[int]int)
	}
	s.syntax.quotes[frame.start] = pos + 1
	if s.repair && frame.kind == contextSingleQuote && (s.plain || s.anchors[pos] > pos) && embeddedApostrophe(s.value, frame.start) &&
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
