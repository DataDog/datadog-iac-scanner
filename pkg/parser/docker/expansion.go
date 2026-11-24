package docker

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

// wordExpander expands the variables of one Dockerfile word.
//
// Valid words go through BuildKit's lexer, so quoting, escapes (including the
// file's escape directive) and parameter operators on known variables behave as
// they do in a build. Variables that are not known are left as written, since a
// shell or the build command line may still provide them. Any word the lexer
// would reject or rewrite is expanded by expandPlainRefs instead, which only
// replaces known $NAME and ${NAME} references and keeps every other byte.
//
// Reading a variable can expand another declaration, so expansions nest. A
// shell.Lex keeps its scanner state, so every expansion uses its own.
type wordExpander struct {
	escape byte
	raw    bool
}

// newWordExpander builds an expander for words whose quotes and escapes are
// kept (raw, for commands that a shell reads later) or removed (declarations).
func newWordExpander(escape rune, raw bool) *wordExpander {
	return &wordExpander{escape: byte(escape), raw: raw}
}

func (e *wordExpander) newLex() *shell.Lex {
	lex := shell.NewLex(rune(e.escape))
	lex.RawQuotes = e.raw
	lex.RawEscapes = e.raw
	lex.SkipUnsetEnv = true
	return lex
}

// expandValues expands each value in place against scope and returns values.
func expandValues(e *wordExpander, values []string, scope environment) []string {
	if e.raw && scope.empty() {
		return values
	}
	for i, value := range values {
		if e.mayReference(value) {
			values[i] = e.expand(value, scope)
		}
	}
	return values
}

func (e *wordExpander) mayReference(value string) bool {
	if e.raw {
		return strings.Contains(value, "$")
	}
	// Declarations also lose their quotes and escapes.
	return strings.ContainsAny(value, "$\\\"'`")
}

func (e *wordExpander) expand(value string, scope environment) string {
	if e.lexerHandles(value, scope) {
		if expanded, _, err := e.newLex().ProcessWord(value, scope); err == nil {
			return expanded
		}
	}
	return e.expandPlainRefs(value, scope)
}

// lexerHandles reports whether BuildKit's lexer can expand value faithfully.
// One pass over ${...} references decides:
//   - bytes that make text/scanner write diagnostics to stderr, or a leading
//     byte order mark it would drop, are not given to it;
//   - an unset variable with an operator, such as ${NAME//a/b} or ${NAME:-x}, is
//     not given to it. With SkipUnsetEnv it rebuilds that reference from its
//     parsed parts, which changes it (// becomes /, escapes and quotes in the
//     operand are processed) and drops explicit defaults. A plain ${NAME} is
//     rebuilt exactly and stays on this path.
//
// The scan ignores quoting, so it can only err towards the byte-preserving path.
func (e *wordExpander) lexerHandles(value string, scope environment) bool {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || strings.HasPrefix(value, "\ufeff") {
		return false
	}
	for pos := 0; pos+1 < len(value); pos++ {
		if value[pos] != '$' || value[pos+1] != '{' {
			continue
		}
		nameStart := pos + 2
		nameEnd := parameterNameEnd(value, nameStart)
		plain := nameEnd < len(value) && value[nameEnd] == '}'
		if _, known := scope.Get(value[nameStart:nameEnd]); !plain && !known {
			return false
		}
		pos++
	}
	return true
}

// parameterNameEnd returns the end of the variable name starting at start,
// using BuildKit's rules: digits only, one special parameter, or letters,
// digits and underscores.
func parameterNameEnd(value string, start int) int {
	if start >= len(value) {
		return start
	}
	first, size := utf8.DecodeRuneInString(value[start:])
	if !unicode.IsDigit(first) && strings.ContainsRune("@*#?-$!", first) {
		return start + size
	}
	numeric := unicode.IsDigit(first)
	pos := start
	for pos < len(value) {
		ch, size := utf8.DecodeRuneInString(value[pos:])
		if numeric && !unicode.IsDigit(ch) {
			break
		}
		if !numeric && !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && ch != '_' {
			break
		}
		pos += size
	}
	return pos
}

// expandPlainRefs replaces known $NAME and ${NAME} references that are outside
// single quotes in one linear pass. Every other byte stays as written: quotes,
// escapes, operators, unknown names and invalid bytes. Substituted values are
// never scanned again.
func (e *wordExpander) expandPlainRefs(value string, scope environment) string {
	var out strings.Builder
	copied := 0
	inSingle, inDouble := false, false

	for pos := 0; pos < len(value); {
		ch := value[pos]
		switch {
		case inSingle:
			inSingle = ch != '\''
			pos++
		case ch == e.escape:
			pos = e.skipEscape(value, pos, inDouble)
		case ch == '"':
			inDouble = !inDouble
			pos++
		case ch == '\'' && !inDouble:
			inSingle = true
			pos++
		case ch != '$':
			pos++
		case pos+1 < len(value) && value[pos+1] == '$':
			// Consume $$ together so $$NAME is not read as $ and $NAME.
			pos += 2
		default:
			name, end, ok := plainReferenceAt(value, pos)
			if !ok {
				pos++
				continue
			}
			if replacement, known := scope.Get(name); known {
				out.WriteString(value[copied:pos])
				out.WriteString(replacement)
				copied = end
			}
			pos = end
		}
	}

	if copied == 0 {
		return value
	}
	out.WriteString(value[copied:])
	return out.String()
}

// skipEscape returns the position after an escape sequence. Inside double
// quotes only a quote, a dollar or the escape itself can be escaped.
func (e *wordExpander) skipEscape(value string, pos int, inDouble bool) int {
	if pos+1 == len(value) {
		return pos + 1
	}
	next := value[pos+1]
	if inDouble && next != '"' && next != '$' && next != e.escape {
		return pos + 1
	}
	_, size := utf8.DecodeRuneInString(value[pos+1:])
	return pos + 1 + size
}

// plainReferenceAt parses a plain $NAME or ${NAME} at pos, where NAME starts
// with a letter or underscore.
func plainReferenceAt(value string, pos int) (name string, end int, ok bool) {
	start := pos + 1
	braced := start < len(value) && value[start] == '{'
	if braced {
		start++
	}
	if start >= len(value) {
		return "", start, false
	}
	first, _ := utf8.DecodeRuneInString(value[start:])
	if first != '_' && !unicode.IsLetter(first) {
		return "", start, false
	}
	end = parameterNameEnd(value, start)
	name = value[start:end]
	if braced {
		if end >= len(value) || value[end] != '}' {
			return "", end, false
		}
		end++
	}
	return name, end, true
}
