/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// exceedsNestingLimit performs a linear, shell-aware pre-scan to reject
// pathologically deep delimiter nesting (such as thousands of nested
// `((((...))))`) before invoking mvdan.cc/sh's recursive parser, preventing an
// unrecoverable stack overflow.
//
// Opening delimiters `(`, `{`, `[` are always counted — even inside quotes or
// comments — so a quote/heredoc desync can never hide deep nesting. Closing
// delimiters inside quotes or comments cannot pop below the nesting depth at
// which that quote or comment began, so `$(echo ')' $(echo ')' ...` cannot
// mask outer nesting either.
func exceedsNestingLimit(input string, limit int) bool {
	s := nestingScanner{limit: limit, atWordStart: true}
	return s.scan(input)
}

type nestingScanner struct {
	limit       int
	depth       int
	quoteBases  []int
	inDouble    bool
	atWordStart bool
}

func (s *nestingScanner) push() bool {
	s.depth++
	return s.depth > s.limit
}

func (s *nestingScanner) pop(floor int) {
	if s.depth > floor {
		s.depth--
	}
}

func (s *nestingScanner) scan(input string) bool {
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == '\\' {
			i++
			s.atWordStart = false
			continue
		}
		if s.inDouble {
			next, exceeded := s.scanDoubleQuoteByte(input, i)
			if exceeded {
				return true
			}
			i = next
			continue
		}
		if c == '\'' {
			next, exceeded := s.scanSingleQuote(input, i)
			if exceeded {
				return true
			}
			i = next
			s.atWordStart = false
			continue
		}
		if c == '#' && s.atWordStart {
			next, exceeded := s.scanComment(input, i)
			if exceeded {
				return true
			}
			i = next
			s.atWordStart = true
			continue
		}
		if s.scanNormalByte(c) {
			return true
		}
	}
	return false
}

func (s *nestingScanner) scanDoubleQuoteByte(input string, i int) (next int, exceeded bool) {
	c := input[i]
	floor := s.quoteBases[len(s.quoteBases)-1]
	switch c {
	case '"':
		s.quoteBases = s.quoteBases[:len(s.quoteBases)-1]
		s.inDouble = len(s.quoteBases) > 0
		s.atWordStart = false
	case '$':
		if i+1 < len(input) && (input[i+1] == '(' || input[i+1] == '{') {
			i++
			if s.push() {
				return i, true
			}
		}
	case '(', '{', '[':
		if s.push() {
			return i, true
		}
	case ')', '}', ']':
		s.pop(floor)
	}
	return i, false
}

func (s *nestingScanner) scanSingleQuote(input string, start int) (next int, exceeded bool) {
	ansiC := start > 0 && input[start-1] == '$'
	floor := s.depth
	for i := start + 1; i < len(input); i++ {
		c := input[i]
		if ansiC && c == '\\' {
			i++
			continue
		}
		switch c {
		case '\'':
			return i, false
		case '(', '{', '[':
			if s.push() {
				return i, true
			}
		case ')', '}', ']':
			s.pop(floor)
		}
	}
	return len(input) - 1, false
}

func (s *nestingScanner) scanComment(input string, start int) (next int, exceeded bool) {
	floor := s.depth
	for i := start + 1; i < len(input); i++ {
		switch input[i] {
		case '\n':
			return i, false
		case '(', '{', '[':
			if s.push() {
				return i, true
			}
		case ')', '}', ']':
			s.pop(floor)
		}
	}
	return len(input) - 1, false
}

func (s *nestingScanner) scanNormalByte(c byte) bool {
	switch c {
	case '"':
		s.quoteBases = append(s.quoteBases, s.depth)
		s.inDouble = true
		s.atWordStart = false
	case '(', '{', '[':
		s.atWordStart = true
		return s.push()
	case ')', '}', ']':
		s.pop(0)
		s.atWordStart = true
	case ' ', '\t', '\n', '\r', ';', '&', '|':
		s.atWordStart = true
	default:
		s.atWordStart = false
	}
	return false
}

// Literal performs only quote removal for a single grammar-delimited word.
// Expansion, globbing, ANSI-C quoting and command substitution remain unknown.
func Literal(raw string) Value {
	if len(raw) > maxScriptBytes || exceedsNestingLimit(raw, maxSyntaxNesting) {
		return Value{Raw: raw}
	}
	var parsed *syntax.Word
	count := 0
	err := syntax.NewParser().Words(strings.NewReader(raw), func(w *syntax.Word) bool {
		count++
		if count == 1 {
			parsed = w
		}
		return count == 1
	})
	if err != nil || count != 1 || parsed == nil {
		return Value{Raw: raw}
	}
	if int(parsed.Pos().Offset()) != 0 || int(parsed.End().Offset()) != len(raw) {
		return Value{Raw: raw}
	}
	return wordValue(parsed, raw)
}

func wordValue(word *syntax.Word, raw string) Value {
	result := Value{Raw: raw}
	var text strings.Builder
	pattern := false
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if p.Dollar {
				return result
			}
			text.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar || !appendDoubleQuoted(&text, p.Parts) {
				return result
			}
		case *syntax.Lit:
			if !appendUnquotedLit(&text, p.Value, &pattern) {
				return result
			}
		default:
			return result
		}
	}
	if pattern {
		result.Pattern = text.String()
		return result
	}
	result.Text = text.String()
	if result.Raw == result.Text {
		result.Raw = ""
	}
	result.Known = true
	return result
}

func appendDoubleQuoted(text *strings.Builder, parts []syntax.WordPart) bool {
	for _, part := range parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return false
		}
		escaped := false
		for _, r := range lit.Value {
			if escaped {
				if !strings.ContainsRune("$`\"\\\n", r) {
					text.WriteByte('\\')
				}
				if r != '\n' {
					text.WriteRune(r)
				}
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			text.WriteRune(r)
		}
		if escaped {
			return false
		}
	}
	return true
}

func appendUnquotedLit(text *strings.Builder, value string, pattern *bool) bool {
	escaped := false
	var previous rune
	for _, r := range value {
		if escaped {
			if r != '\n' {
				text.WriteRune(r)
				previous = r
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '~' && (text.Len() == 0 || previous == '=' || previous == ':') {
			return false
		}
		if r == '(' || r == ')' {
			return false
		}
		if strings.ContainsRune("*?[]{}", r) {
			*pattern = true
		}
		text.WriteRune(r)
		previous = r
	}
	return !escaped
}
