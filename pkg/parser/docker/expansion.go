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
// would reject or rewrite goes to expandPlainRefsFromScan instead, which only
// replaces known plain $NAME and ${NAME} references outside single quotes and
// keeps every other byte verbatim.
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

// expandValues expands each value in place against env and returns values.
// Any lazy declarations referenced by a word are resolved iteratively before
// BuildKit's lexer runs, so the lexer only ever sees finalized values.
func expandValues(e *wordExpander, values []string, env *envNode) []string {
	if e.raw && env == nil {
		return values
	}
	for i, value := range values {
		if !e.mayReference(value) {
			continue
		}
		scan := scanWord(value, e.escape)
		plainOnly := !canUseLexer(value, scan, env)
		if deps := unresolvedDeps(scan.refs, env, plainOnly); len(deps) > 0 {
			resolveBindings(deps)
		}
		values[i] = e.expandResolved(value, scan, env)
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

// expandResolved expands value after its referenced bindings in env have been
// resolved. It uses BuildKit's lexer when the lexer can process value without
// diagnostics or lossy unset-operator reconstruction, and otherwise falls back
// to plain-reference replacement using the same scan.
func (e *wordExpander) expandResolved(value string, scan wordScan, env *envNode) string {
	if canUseLexer(value, scan, env) {
		if expanded, _, err := e.newLex().ProcessWord(value, resolvedEnv{env}); err == nil {
			return expanded
		}
	}
	return expandPlainRefsFromScan(value, scan.refs, env)
}

// maxLexerDepth guards BuildKit's recursive shell.Lex (one Go stack frame per
// nested ${...} or quote level), which otherwise fatally overflows the goroutine
// stack on continuation-joined lines with hundreds of thousands of levels.
const maxLexerDepth = 1000

// canUseLexer reports whether BuildKit's shell.Lex can expand value faithfully:
//   - invalid UTF-8 or NUL bytes cause text/scanner to write to stderr, and a
//     leading BOM is silently dropped by text/scanner;
//   - syntax errors (unclosed quotes/braces, unsupported bash operators) would
//     fail in BuildKit anyway;
//   - nesting beyond maxLexerDepth could overflow BuildKit's recursive lexer stack;
//   - an unset variable with an operator (e.g. ${X//a/b} or ${X:-x}) is rebuilt
//     lossily under SkipUnsetEnv (// becomes /, escapes/quotes in operands are
//     processed). A plain ${NAME} is rebuilt verbatim and stays on this path.
func canUseLexer(value string, scan wordScan, env *envNode) bool {
	if scan.syntaxErr || scan.maxDepth > maxLexerDepth ||
		!utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || strings.HasPrefix(value, "\ufeff") {
		return false
	}
	for _, ref := range scan.refs {
		if !ref.plain && !env.has(ref.name) {
			return false
		}
	}
	return true
}

// resolvedEnv adapts an immutable *envNode to BuildKit's shell.EnvGetter.
// Referenced bindings are already resolved before ProcessWord runs; if an
// unexpected binding is still lazy, it is resolved iteratively as a safeguard.
type resolvedEnv struct {
	env *envNode
}

func (r resolvedEnv) Get(name string) (string, bool) {
	b, ok := r.env.get(name)
	if !ok {
		return "", false
	}
	if !b.done {
		resolveBindings([]*binding{b})
	}
	return b.value, true
}

func (r resolvedEnv) Keys() []string {
	return r.env.keys(nil)
}

// expandPlainRefsFromScan replaces only known plain identifier $NAME and
// ${NAME} references recorded by scanWord, keeping every other byte verbatim.
// Plain references are disjoint and ordered by start offset, and inserted
// values are never scanned again.
func expandPlainRefsFromScan(value string, refs []wordRef, env *envNode) string {
	if env == nil || len(refs) == 0 {
		return value
	}
	var out strings.Builder
	copied := 0
	for _, ref := range refs {
		if !ref.plain || !isIdentifierName(ref.name) {
			continue
		}
		b, ok := env.get(ref.name)
		if !ok {
			continue
		}
		if !b.done {
			resolveBindings([]*binding{b})
		}
		out.WriteString(value[copied:ref.start])
		out.WriteString(b.value)
		copied = ref.end
	}
	if copied == 0 {
		return value
	}
	out.WriteString(value[copied:])
	return out.String()
}

func isIdentifierName(name string) bool {
	if name == "" {
		return false
	}
	first, _ := utf8.DecodeRuneInString(name)
	return first == '_' || unicode.IsLetter(first)
}

type scanCtx uint8

const (
	ctxWord scanCtx = iota
	ctxDouble
	ctxSingle
	ctxParam
)

type scanFrame struct {
	kind scanCtx
	stop byte // '}' or '/' for ctxParam
}

type wordRef struct {
	start int
	end   int // valid when plain is true
	name  string
	plain bool
}

type wordScan struct {
	refs      []wordRef
	maxDepth  int
	syntaxErr bool
}

// scanWord performs one O(len(value)) context-stack walk matching BuildKit's
// shell.Lex quoting, escape, and parameter boundaries. It serves three roles
// from one consistent view of the word:
//   - static dependency discovery for lazy bindings (no speculative lexing),
//   - quote-aware detection of unset parameter operators and syntax errors,
//   - plain $NAME/${NAME} span collection for byte-preserving fallback.
func scanWord(value string, escape byte) wordScan {
	var inline [8]scanFrame
	s := wordScanner{
		value:  value,
		escape: escape,
		stack:  append(inline[:0], scanFrame{kind: ctxWord}),
	}
	for pos := 0; pos < len(value); {
		pos = s.step(pos)
		if depth := len(s.stack) - 1; depth > s.result.maxDepth {
			s.result.maxDepth = depth
		}
	}
	if len(s.stack) > 1 {
		s.result.syntaxErr = true
	}
	return s.result
}

type wordScanner struct {
	value  string
	escape byte
	stack  []scanFrame
	result wordScan
}

func (s *wordScanner) step(pos int) int {
	top := s.stack[len(s.stack)-1]
	ch := s.value[pos]

	if top.kind == ctxSingle {
		if ch == '\'' {
			s.stack = s.stack[:len(s.stack)-1]
		}
		return pos + 1
	}
	if top.kind == ctxParam && ch == top.stop {
		if ch == '/' {
			s.stack[len(s.stack)-1].stop = '}'
		} else {
			s.stack = s.stack[:len(s.stack)-1]
		}
		return pos + 1
	}
	if ch == s.escape {
		return s.skipEscape(pos, top.kind == ctxDouble)
	}
	if ch == '$' {
		return s.scanDollar(pos)
	}
	if top.kind == ctxDouble {
		if ch == '"' {
			s.stack = s.stack[:len(s.stack)-1]
		}
		return pos + 1
	}
	switch ch {
	case '\'':
		s.stack = append(s.stack, scanFrame{kind: ctxSingle})
	case '"':
		s.stack = append(s.stack, scanFrame{kind: ctxDouble})
	}
	return pos + 1
}

func (s *wordScanner) skipEscape(pos int, inDouble bool) int {
	if pos+1 >= len(s.value) {
		return pos + 1
	}
	next := s.value[pos+1]
	if inDouble && next != '"' && next != '$' && next != s.escape {
		return pos + 1
	}
	_, size := utf8.DecodeRuneInString(s.value[pos+1:])
	return pos + 1 + size
}

func (s *wordScanner) scanDollar(pos int) int {
	if pos+1 >= len(s.value) {
		return pos + 1
	}
	if s.value[pos+1] != '{' {
		nameEnd := parameterNameEnd(s.value, pos+1)
		if nameEnd == pos+1 {
			return pos + 1
		}
		s.result.refs = append(s.result.refs, wordRef{
			start: pos,
			end:   nameEnd,
			name:  s.value[pos+1 : nameEnd],
			plain: true,
		})
		return nameEnd
	}
	return s.scanBraced(pos)
}

func (s *wordScanner) scanBraced(pos int) int {
	nameStart := pos + 2
	if nameStart >= len(s.value) {
		s.result.syntaxErr = true
		return len(s.value)
	}
	switch s.value[nameStart] {
	case '}':
		s.result.syntaxErr = true
		return nameStart + 1
	case '{', ':':
		s.result.syntaxErr = true
		s.stack = append(s.stack, scanFrame{kind: ctxParam, stop: '}'})
		return nameStart
	}

	nameEnd := parameterNameEnd(s.value, nameStart)
	if nameEnd >= len(s.value) {
		s.result.syntaxErr = true
		return len(s.value)
	}

	name := s.value[nameStart:nameEnd]
	op := s.value[nameEnd]
	if op == '}' {
		s.result.refs = append(s.result.refs, wordRef{
			start: pos,
			end:   nameEnd + 1,
			name:  name,
			plain: true,
		})
		return nameEnd + 1
	}
	return s.scanOperator(pos, name, nameEnd, op)
}

func (s *wordScanner) scanOperator(pos int, name string, nameEnd int, op byte) int {
	next := nameEnd + 1
	switch op {
	case '/':
		s.result.refs = append(s.result.refs, wordRef{start: pos, name: name})
		if next < len(s.value) && s.value[next] == '/' {
			next++
		}
		s.stack = append(s.stack, scanFrame{kind: ctxParam, stop: '/'})
		return next
	case ':':
		if next >= len(s.value) {
			s.result.syntaxErr = true
			return len(s.value)
		}
		op2 := s.value[next]
		if op2 == '+' || op2 == '-' || op2 == '?' {
			s.result.refs = append(s.result.refs, wordRef{start: pos, name: name})
			s.stack = append(s.stack, scanFrame{kind: ctxParam, stop: '}'})
			return next + 1
		}
		s.result.syntaxErr = true
		if op2 == '}' {
			return next + 1
		}
		// Keep the first operand byte (e.g. $, ", ', \) so fallback scanning
		// preserves references and quote boundaries in unsupported : forms.
		s.stack = append(s.stack, scanFrame{kind: ctxParam, stop: '}'})
		return next
	case '+', '-', '?', '#', '%':
		s.result.refs = append(s.result.refs, wordRef{start: pos, name: name})
		s.stack = append(s.stack, scanFrame{kind: ctxParam, stop: '}'})
		return next
	default:
		// Reprocess the byte at nameEnd inside ctxParam so opening quotes,
		// escapes, or $ references in unsupported forms stay balanced.
		s.result.syntaxErr = true
		s.stack = append(s.stack, scanFrame{kind: ctxParam, stop: '}'})
		return nameEnd
	}
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
