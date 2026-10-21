package docker

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/pkg/errors"
)

type wordExpander struct {
	lex          *shell.Lex
	parameterLex *shell.Lex
	escape       byte
}

func newWordExpander(escape rune, raw bool) *wordExpander {
	lex := shell.NewLex(escape)
	lex.RawQuotes, lex.RawEscapes, lex.SkipUnsetEnv = raw, raw, true
	parameters := shell.NewLex(escape)
	parameters.RawQuotes, parameters.RawEscapes = raw, raw
	return &wordExpander{lex: lex, parameterLex: parameters, escape: byte(escape)}
}

// expandValues uses BuildKit for shell expansion. Unknown references stay
// visible to rules; explicit defaults still apply to unset variables. Unsupported
// syntax is preserved locally, without preventing independent references from
// expanding. Inserted values are never scanned again.
func expandValues(expander *wordExpander, values []string, scopes ...map[string]string) []string {
	for i, value := range values {
		if !strings.ContainsAny(value, "$\\\"'`") {
			continue
		}
		env := variableEnvironment(scopes)
		word, restore := protectBadBytes(value, env)
		expanded, err := expander.expandWord(word, env)
		if err != nil {
			expanded = expander.recoverWord(word, env)
		}
		if restore != nil {
			expanded = restore.Replace(expanded)
		}
		values[i] = expanded
	}
	return values
}

// recoverWord masks unsupported parameter expressions before asking BuildKit to
// process the complete value again. This preserves BuildKit's nested quote and
// default semantics even when unrelated syntax is unsupported. Only malformed
// quoting needs fragment recovery; inserted values are restored without expansion.
func (e *wordExpander) recoverWord(value string, env variableEnvironment) string {
	ends := e.referenceEndIndex(value)
	const privateMarker = "\ue002"
	marker := privateMarker
	for containsMarker(value, env, marker) {
		marker += privateMarker
	}
	var out strings.Builder
	var replacements []string
	copied := 0
	quotes := e.recoveryQuotes(value)
	for pos := 0; pos < len(value); pos++ {
		if value[pos] == e.escape {
			pos++
			continue
		}
		if end := quotes.literalEnd(value, pos); end > pos {
			pos = end // Literal text must not be masked as unsupported syntax.
			continue
		}
		if value[pos] != '$' || pos+1 == len(value) {
			continue
		}
		if value[pos+1] != '{' {
			pos = max(pos, referenceNameEnd(value, pos+1)-1)
			continue
		}
		end, found := ends[pos]
		if !found {
			continue
		}
		if _, err := e.expandWord(value[pos:end], env); err != nil && unsupportedModifier(err) {
			token := marker + strconv.Itoa(len(replacements)/2) + marker
			out.WriteString(value[copied:pos])
			out.WriteString(token)
			replacements = append(replacements, token, value[pos:end])
			copied = end
		}
		pos = end - 1
	}
	if len(replacements) == 0 {
		return e.expandParts(value, env, false)
	}
	out.WriteString(value[copied:])
	word := out.String()
	expanded, err := e.expandWord(word, env)
	if err != nil {
		expanded = e.expandParts(word, env, false)
	}
	return strings.NewReplacer(replacements...).Replace(expanded)
}

// Brace spans only identify candidates, not shell grammar. Mask a span only
// when BuildKit identifies an unsupported modifier; delimiter, quote and pattern
// errors may mean the span cuts across a valid expression. The complete-word
// parse, or fragment recovery for malformed input, handles those errors.
func unsupportedModifier(err error) bool {
	return strings.HasPrefix(errors.Cause(err).Error(), "unsupported modifier (")
}

type expansionQuotes struct {
	ends         map[int]int
	doubleQuoted bool
}

func (e *wordExpander) recoveryQuotes(value string) expansionQuotes {
	if !strings.ContainsAny(value, "'\"") {
		return expansionQuotes{}
	}
	return expansionQuotes{ends: e.recoveryQuoteEnds(value)}
}

// The quote index is shared by both masking passes. BuildKit processes the
// original quote bytes; masking must not hide quotes within a literal fragment.
func (q *expansionQuotes) literalEnd(value string, pos int) int {
	if value[pos] == '"' {
		q.doubleQuoted = !q.doubleQuoted
	}
	if value[pos] == '\'' && !q.doubleQuoted && q.ends[pos] > pos {
		return q.ends[pos]
	}
	return pos
}

// expandWord applies the same unknown-reference policy to complete values and
// isolated expressions recovered from unsupported shell syntax.
func (e *wordExpander) expandWord(value string, env variableEnvironment) (string, error) {
	word, restore := value, (*strings.Replacer)(nil)
	lex := e.lex
	if strings.Contains(value, "${") {
		// SkipUnsetEnv also skips defaults. Preserve unknown references and
		// operations needing their values before evaluating explicit defaults.
		word, restore = e.protectUnknownReferences(value, env)
		lex = e.parameterLex
	}
	expanded, _, err := lex.ProcessWord(word, env)
	if err == nil && restore != nil {
		expanded = restore.Replace(expanded)
	}
	return expanded, err
}

// expandParts isolates references before handing them to BuildKit. This is a
// recovery boundary, not an implementation of shell parameter operators. A bad
// reference or unmatched quote must not discard expansion elsewhere in a value.
func (e *wordExpander) expandParts(value string, env variableEnvironment, quoted bool) string {
	var out strings.Builder
	ends := e.recoveryQuoteEnds(value)
	references := e.referenceEndIndex(value)
	for i := 0; i < len(value); {
		ch := value[i]
		switch {
		case ch == e.escape && i+1 == len(value) && !quoted:
			part, _ := e.expandWord(value[i:], env)
			out.WriteString(part)
			return out.String()
		case ch == e.escape && i+1 < len(value):
			if escaped, end, ok := e.escapedPart(value, i, quoted); ok {
				out.WriteString(escaped)
				i = end
				continue
			}
		case !quoted && (ch == '\'' || ch == '"'):
			if part, end, ok := e.quotedPart(value, i, ends[i], env); ok {
				out.WriteString(part)
				i = end
				continue
			}
		case ch == '$':
			end := e.referenceEnd(value, i, references)
			if end > i+1 {
				reference := value[i:end]
				expanded, err := e.expandWord(reference, env)
				if err == nil {
					out.WriteString(expanded)
				} else {
					out.WriteString(reference)
				}
				i = end
				continue
			}
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

func (e *wordExpander) referenceEnd(value string, start int, ends map[int]int) int {
	pos := start + 1
	if pos < len(value) && value[pos] == '{' {
		if end, ok := ends[start]; ok {
			return end
		}
		return pos // Preserve malformed text while later references can expand.
	}
	return referenceNameEnd(value, pos)
}

// referenceEndIndex indexes balanced parameter spans in O(n), including nested
// braces. It only isolates text passed to BuildKit; all operator evaluation is
// left to shell.Lex. Unclosed prefixes don't cause repeated suffix scans.
func (e *wordExpander) referenceEndIndex(value string) map[int]int {
	ends := make(map[int]int)
	var stack []int
	quotes := parameterQuotes{}
	if strings.ContainsAny(value, "'\"") {
		quotes.ends = e.quoteEndIndexes(value)
	}
	for pos := 0; pos < len(value); pos++ {
		switch value[pos] {
		case e.escape:
			pos++
		case '\'', '"':
			pos = quotes.advance(value, pos, len(stack))
		case '{':
			if pos > 0 && value[pos-1] == '$' {
				stack = append(stack, pos)
			}
		case '}':
			if len(stack) == 0 || quotes.literal(len(stack)) {
				continue
			}
			start := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if start > 0 && value[start-1] == '$' {
				ends[start-1] = pos + 1
			}
		}
	}
	return ends
}

// Track quote depth while indexing parameter candidates, so a quoted literal
// brace does not close its containing expression but nested references inside
// double quotes still get indexed. BuildKit validates and evaluates each span.
type parameterQuotes struct {
	ends   map[int]int
	depths []int
}

func (q *parameterQuotes) literal(depth int) bool {
	return len(q.depths) > 0 && q.depths[len(q.depths)-1] == depth
}

func (q *parameterQuotes) advance(value string, pos, depth int) int {
	if value[pos] == '"' {
		if q.literal(depth) {
			q.depths = q.depths[:len(q.depths)-1]
		} else {
			q.depths = append(q.depths, depth)
		}
	} else if !q.literal(depth) && q.ends[pos] > pos {
		return q.ends[pos]
	}
	return pos
}

func variableNameByte(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_'
}

func (e *wordExpander) escapedPart(value string, pos int, quoted bool) (part string, end int, ok bool) {
	_, size := utf8.DecodeRuneInString(value[pos+1:])
	end = pos + 1 + size
	word := value[pos:end]
	if quoted {
		word = `"` + word + `"`
	}
	part, err := e.expandWord(word, nil)
	if err != nil {
		return "", pos, false
	}
	if quoted && e.lex.RawQuotes {
		part = part[1 : len(part)-1]
	}
	return part, end, true
}

// recoveryQuoteEnds indexes quote terminators in O(n) time. Ordinary balanced
// fragments follow shell quoting. Only in malformed text may an embedded orphan
// apostrophe yield to a later quote opening a new word. This recovery convention
// is intentionally local: a later orphan cannot invalidate a closed fragment.
// Differential tests compare balanced fragments with BuildKit, including when an
// unsupported reference elsewhere forces recovery.
func (e *wordExpander) recoveryQuoteEnds(value string) map[int]int {
	ends := e.quoteEndIndexes(value)
	if e.quotesBalanced(value, ends) {
		return ends
	}
	openers := e.recoveryQuoteOpeners(value)
	for start, end := range ends {
		if isOrphanApostrophe(value, start, end, openers[end]) {
			ends[start] = -1
		}
	}
	return ends
}

func isOrphanApostrophe(value string, start, end int, opener bool) bool {
	if end < 0 || value[start] != '\'' || !opener {
		return false
	}
	embedded := start > 0 && start+1 < len(value) && variableNameByte(value[start-1]) && variableNameByte(value[start+1])
	opening := end+1 < len(value) && (variableNameByte(value[end+1]) || value[end+1] == '$')
	return embedded && opening
}

// quoteEndIndexes records the next possible terminator for each quote. A single
// quote ignores escapes inside its span; double quotes don't. Both passes are O(n).
func (e *wordExpander) quoteEndIndexes(value string) map[int]int {
	ends := make(map[int]int)
	escapedQuotes := make(map[int]bool)
	for i := 0; i < len(value); i++ {
		if value[i] == e.escape {
			i++
			escapedQuotes[i] = true
		}
	}
	nextSingle, nextDouble := -1, -1
	for i := len(value) - 1; i >= 0; i-- {
		switch value[i] {
		case '\'':
			ends[i], nextSingle = nextSingle, i
		case '"':
			ends[i] = nextDouble
			if !escapedQuotes[i] {
				nextDouble = i
			}
		}
	}
	return ends
}

func (e *wordExpander) quotesBalanced(value string, ends map[int]int) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == e.escape {
			i++
			continue
		}
		if end, quote := ends[i]; quote {
			if end < 0 {
				return false
			}
			i = end
		}
	}
	return true
}

// recoveryQuoteOpeners indexes word boundaries once, rather than rescanning
// prefixes or suffixes at each apostrophe. It is used only on malformed text.
func (e *wordExpander) recoveryQuoteOpeners(value string) map[int]bool {
	openers := make(map[int]bool)
	wordStart, plainPrefix := 0, true
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\'' || ch == '"' {
			openers[i] = wordStart == i || plainPrefix
		}
		if ch == e.escape {
			i++
			plainPrefix = false
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\n' {
			wordStart, plainPrefix = i+1, true
		} else {
			plainPrefix = plainPrefix && variableNameByte(ch)
		}
	}
	return openers
}

// protectBadBytes prevents text/scanner diagnostics and preserves exact source
// bytes while independently expanding the valid shell syntax around them.
func protectBadBytes(value string, scopes variableEnvironment) (string, *strings.Replacer) {
	if utf8.ValidString(value) && strings.IndexByte(value, 0) < 0 {
		return value, nil
	}
	const privateMarker = "\ue001"
	marker := privateMarker
	for containsMarker(value, scopes, marker) {
		marker += privateMarker
	}
	var out strings.Builder
	var replacements []string
	for i := 0; i < len(value); {
		ch, size := utf8.DecodeRuneInString(value[i:])
		if ch == 0 || ch == utf8.RuneError && size == 1 {
			token := marker + strconv.Itoa(len(replacements)/2) + marker
			out.WriteString(token)
			replacements = append(replacements, token, value[i:i+size])
		} else {
			out.WriteString(value[i : i+size])
		}
		i += size
	}
	return out.String(), strings.NewReplacer(replacements...)
}

func (e *wordExpander) quotedPart(value string, pos, quoteEnd int, env variableEnvironment) (part string, end int, ok bool) {
	end = quoteEnd
	if end < 0 {
		return "", pos, false
	} // Unmatched quotes are literal during recovery.
	if expanded, err := e.expandWord(value[pos:end+1], env); err == nil {
		return expanded, end + 1, true
	}
	inner := value[pos+1 : end]
	if value[pos] == '"' {
		inner = e.expandParts(inner, env, true)
	}
	if e.lex.RawQuotes {
		inner = value[pos:pos+1] + inner + value[end:end+1]
	}
	return inner, end + 1, true
}

// protectUnknownReferences preserves the scanner's unknown-value convention
// without asking the lexer to disable unset-variable operators. Placeholders
// cannot occur in source or scope values and are restored in one pass, so inserted
// values remain literal. Quotes and escapes are still processed by BuildKit.
// Reference collection and its optional span index each take O(len(value)) time.
func (e *wordExpander) protectUnknownReferences(value string, scopes variableEnvironment) (string, *strings.Replacer) {
	type reference struct{ start, end int }
	var unknown []reference
	var ends map[int]int // Built once, only when a value-dependent operator needs it.
	quotes := e.recoveryQuotes(value)
	for pos := 0; pos < len(value); pos++ {
		if value[pos] == e.escape {
			pos++
			continue
		}
		if end := quotes.literalEnd(value, pos); end > pos {
			pos = end
			continue
		}
		if value[pos] != '$' {
			continue
		}
		begin := pos
		name, end, braced := referenceHead(value, pos)
		if name == "" {
			continue
		}
		// A dollar used as a special parameter name belongs to this reference;
		// it must never start an independent reference on the next iteration.
		pos = end - 1
		if _, found := scopes.Get(name); found {
			continue // BuildKit evaluates known values; visit any nested operands.
		}
		end, ends = e.unknownReferenceEnd(value, begin, end, braced, ends)
		if end == 0 {
			continue
		}
		unknown = append(unknown, reference{begin, end})
		pos = end - 1
	}
	if len(unknown) == 0 {
		return value, nil
	}
	const privateMarker = "\ue000"
	marker := privateMarker
	for containsMarker(value, scopes, marker) {
		marker += privateMarker
	}
	var out strings.Builder
	replacements := make([]string, 0, len(unknown)*2)
	pos := 0
	for i, ref := range unknown {
		token := marker + strconv.Itoa(i) + marker
		out.WriteString(value[pos:ref.start])
		out.WriteString(token)
		replacements = append(replacements, token, value[ref.start:ref.end])
		pos = ref.end
	}
	out.WriteString(value[pos:])
	return out.String(), strings.NewReplacer(replacements...)
}

// Preserve plain references and operators that require an unknown value.
// Defaults/alternates evaluate normally; their nested operands remain visible
// to the caller's walk. BuildKit evaluates all actual operator semantics.
func (e *wordExpander) unknownReferenceEnd(value string, begin, nameEnd int, braced bool,
	ends map[int]int) (end int, spans map[int]int) {
	if !braced {
		return nameEnd, ends
	}
	if nameEnd == len(value) {
		return 0, ends
	}
	switch value[nameEnd] {
	case '}':
		return nameEnd + 1, ends
	case '#', '%', '/':
		if ends == nil {
			ends = e.referenceEndIndex(value)
		}
		return ends[begin], ends
	default:
		return 0, ends
	}
}

func containsMarker(value string, scopes variableEnvironment, marker string) bool {
	if strings.Contains(value, marker) {
		return true
	}
	for _, scope := range scopes {
		for _, value := range scope {
			if strings.Contains(value, marker) {
				return true
			}
		}
	}
	return false
}

// referenceHead isolates BuildKit's variable name without evaluating grammar or
// operators. Its boundaries are checked by the BuildKit differential fuzz target.
func referenceHead(value string, pos int) (name string, end int, braced bool) {
	start := pos + 1
	braced = start < len(value) && value[start] == '{'
	if braced {
		start++
	}
	end = referenceNameEnd(value, start)
	name = value[start:end]
	return name, end, braced
}

// Match BuildKit's name boundaries, including positional/special parameters and
// Unicode names, without interpreting any parameter operators here.
func referenceNameEnd(value string, start int) int {
	if start == len(value) {
		return start
	}
	first, size := utf8.DecodeRuneInString(value[start:])
	if strings.ContainsRune("@*#?-$!", first) {
		return start + size
	}
	numeric := unicode.IsDigit(first)
	pos := start
	for pos < len(value) {
		ch, size := utf8.DecodeRuneInString(value[pos:])
		if numeric {
			if !unicode.IsDigit(ch) {
				break
			}
		} else if !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && ch != '_' {
			break
		}
		pos += size
	}
	return pos
}
