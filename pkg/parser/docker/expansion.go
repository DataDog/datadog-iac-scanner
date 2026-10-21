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
	syntax := e.scanShell(value, false)
	const privateMarker = "\ue002"
	marker := privateMarker
	for containsMarker(value, env, marker) {
		marker += privateMarker
	}
	var out strings.Builder
	var replacements []string
	copied := 0
	covered := 0
	for _, ref := range syntax.references {
		pos, end := ref.start, ref.end
		if pos < covered || !ref.braced(value) || end == 0 {
			continue
		}
		if _, err := e.expandWord(value[pos:end], env); err != nil && unsupportedModifier(err) {
			token := marker + strconv.Itoa(len(replacements)/2) + marker
			out.WriteString(value[copied:pos])
			out.WriteString(token)
			replacements = append(replacements, token, value[pos:end])
			copied = end
		}
		covered = end
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
	syntax := e.scanShell(value, quoted)
	references := shellReferences{items: syntax.references}
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
		case syntax.quotes[i] > i:
			part, end := e.quotedPart(value, i, syntax.quotes[i]-1, env)
			out.WriteString(part)
			i = end
			continue
		case ch == '$':
			end := references.end(i)
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

func (e *wordExpander) quotedPart(value string, pos, quoteEnd int, env variableEnvironment) (part string, end int) {
	end = quoteEnd
	if expanded, err := e.expandWord(value[pos:end+1], env); err == nil {
		return expanded, end + 1
	}
	inner := value[pos+1 : end]
	if value[pos] == '"' {
		inner = e.expandParts(inner, env, true)
	}
	if e.lex.RawQuotes {
		inner = value[pos:pos+1] + inner + value[end:end+1]
	}
	return inner, end + 1
}

// protectUnknownReferences preserves the scanner's unknown-value convention
// without asking the lexer to disable unset-variable operators. Placeholders
// cannot occur in source or scope values and are restored in one pass, so inserted
// values remain literal. Quotes and escapes are still processed by BuildKit.
// The context scan and the ordered reference walk each take O(len(value)) time.
func (e *wordExpander) protectUnknownReferences(value string, scopes variableEnvironment) (string, *strings.Replacer) {
	syntax := e.scanShell(value, false)
	// Filtering in place only overwrites already visited entries.
	unknown := syntax.references[:0]
	covered := 0
	for _, ref := range syntax.references {
		if ref.start < covered || ref.name(value) == "" || ref.end == 0 {
			continue
		}
		if _, found := scopes.Get(ref.name(value)); found {
			continue
		}
		if !preserveUnknownReference(value, ref) {
			continue
		}
		unknown = append(unknown, ref)
		covered = ref.end
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

// Unknown required/alternate/modifier operands stay visible; explicit defaults
// continue through BuildKit. This selects policy, not operator evaluation.
func preserveUnknownReference(value string, ref shellReference) bool {
	if !ref.braced(value) || value[ref.nameEnd] == '}' {
		return true
	}
	operator := value[ref.nameEnd]
	if operator == ':' && ref.nameEnd+1 < len(value) {
		operator = value[ref.nameEnd+1]
	}
	return strings.ContainsRune("#%/?+", rune(operator))
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
