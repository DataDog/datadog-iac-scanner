package helm

import (
	"regexp"
	"strings"
)

// templateActionRE matches Helm/Go template action delimiters including trim markers.
var templateActionRE = regexp.MustCompile(`(?s)\{\{-?.*?-?\}\}`)

// templateCommentRE matches Helm template comment blocks: {{/* ... */}} (with optional trim markers).
var templateCommentRE = regexp.MustCompile(`(?s)\{\{-?\s*/\*.*?\*/\s*-?\}\}`)

// isTemplateSpace reports whether c is whitespace allowed between template
// markers, delimiters and comment text.
func isTemplateSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// templateCommentStart returns the index of the "/*" opening a comment
// action's text, or -1 when the action whose "{{" starts at start is not a
// comment.
func templateCommentStart(s string, start int) int {
	c := start + 2
	if c < len(s) && s[c] == '-' {
		c++
	}
	for c < len(s) && isTemplateSpace(s[c]) {
		c++
	}
	if c+1 < len(s) && s[c] == '/' && s[c+1] == '*' {
		return c
	}
	return -1
}

// templateCommentActionEnd returns the index just past the "}}" closing the
// comment action whose "/*" is at start: the first "*/" ends the comment
// text, followed by optional whitespace, a trim marker and the "}}".
// Quoted-string tracking must not apply to comment text — an apostrophe in a
// contraction (e.g. "don't") would open a string and make the comment appear
// unbalanced.
func templateCommentActionEnd(s string, start int) (end int, ok bool) {
	closeIdx := strings.Index(s[start+2:], "*/")
	if closeIdx < 0 {
		return 0, false
	}
	c := start + 2 + closeIdx + 2
	for c < len(s) && isTemplateSpace(s[c]) {
		c++
	}
	if c < len(s) && s[c] == '-' {
		c++
	}
	if c+1 < len(s) && s[c] == '}' && s[c+1] == '}' {
		return c + 2, true
	}
	return 0, false
}

// templateActionEnd returns the index just past the closing "}}" of the action
// whose "{{" starts at start, treating quoted strings (", ' and `) inside the
// action as opaque so a "}}" within a quoted template argument does not end
// the action. Comment actions are terminated by "*/" plus the closing "}}"
// instead, as their text may hold quotes that would defeat that tracking.
// ok is false when the action has no terminator outside quotes
// (e.g. an unterminated string).
func templateActionEnd(s string, start int) (end int, ok bool) {
	if c := templateCommentStart(s, start); c >= 0 {
		return templateCommentActionEnd(s, c)
	}
	var quote byte
	for i := start + 2; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '`':
			if c == '`' {
				quote = 0
			}
		case quote != 0:
			switch c {
			case '\\':
				i++ // skip the escaped character
			case quote:
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '}' && i+1 < len(s) && s[i+1] == '}':
			return i + 2, true
		}
	}
	return 0, false
}

// balancedTemplateActionSpans returns the [start, end) byte ranges of all {{ ... }}
// actions in s whose delimiters are balanced with respect to quoted strings,
// unlike templateActionRE, which stops at the first "}}" even inside a quoted
// template argument. Comment actions are skipped by the marker loop itself (the
// action text starts with "/*"), so they are not filtered here. Unbalanced
// actions (unterminated quotes, no terminator) are omitted so they are never
// rewritten.
func balancedTemplateActionSpans(s string) [][2]int {
	var spans [][2]int
	for i := 0; i+1 < len(s); {
		start := strings.Index(s[i:], "{{")
		if start < 0 {
			break
		}
		start += i
		end, ok := templateActionEnd(s, start)
		if !ok {
			i = start + 2
			continue
		}
		spans = append(spans, [2]int{start, end})
		i = end
	}
	return spans
}

// removeBalancedActions removes every balanced {{ ... }} action, leaving quoted
// "}}" residue intact as it is still part of an action.
func removeBalancedActions(s string) string {
	var b strings.Builder
	last := 0
	for _, span := range balancedTemplateActionSpans(s) {
		b.WriteString(s[last:span[0]])
		last = span[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// templateActionSpans returns the [start, end) byte ranges of all {{ ... }} blocks in s,
// excluding comment blocks ({{/* ... */}}).
// The returned slice is sorted by start (FindAllStringIndex guarantees this).
func templateActionSpans(s string) [][2]int {
	allMatches := templateActionRE.FindAllStringIndex(s, -1)
	commentMatches := templateCommentRE.FindAllStringIndex(s, -1)
	commentSet := make(map[[2]int]bool, len(commentMatches))
	for _, m := range commentMatches {
		commentSet[[2]int{m[0], m[1]}] = true
	}
	spans := make([][2]int, 0, len(allMatches))
	for _, m := range allMatches {
		if !commentSet[[2]int{m[0], m[1]}] {
			spans = append(spans, [2]int{m[0], m[1]})
		}
	}
	return spans
}

// inAnySpan reports whether pos falls within any of the sorted, non-overlapping spans.
func inAnySpan(pos int, spans [][2]int) bool {
	// Binary search for the last span with start <= pos.
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := (lo + hi) / 2
		if spans[mid][0] <= pos {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return false
	}
	span := spans[lo-1]
	return pos < span[1]
}

// insideQuotedStringInSpan reports whether pos is inside a Go template string literal
// within the action span that contains it. It counts unescaped double-quotes from the
// span's opening {{ to pos; an odd count means we are inside a string.
func insideQuotedStringInSpan(s string, pos int, spans [][2]int) bool {
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := (lo + hi) / 2
		if spans[mid][0] <= pos {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return false
	}
	span := spans[lo-1]
	if pos >= span[1] {
		return false
	}
	text := s[span[0]:pos]
	quoteCount := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '"' && (i == 0 || text[i-1] != '\\') {
			quoteCount++
		}
	}
	return quoteCount%2 == 1
}

// replacement is a single pending substitution collected before applying back-to-front.
type replacement struct {
	start int
	end   int
	text  string
}
