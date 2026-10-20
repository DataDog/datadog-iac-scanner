package docker

import (
	"strconv"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
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

// expandValues uses BuildKit for shell expansion. Unknown plain references stay
// visible to rules; explicit operators still apply to unset variables. Unsupported
// syntax is preserved locally, without preventing independent references from
// expanding. Inserted values are never scanned again.
func expandValues(expander *wordExpander, values []string, scopes ...map[string]string) []string {
	for i, value := range values {
		if !strings.ContainsAny(value, "$\\\"'`") {
			continue
		}
		env := variableEnvironment(scopes)
		word, restore := value, (*strings.Replacer)(nil)
		lex := expander.lex
		if strings.Contains(value, "${") {
			// BuildKit's SkipUnsetEnv also skips defaults. Protect only unknown plain
			// references, then let the normal lexer evaluate all parameter operators.
			word, restore = expander.protectUnknownReferences(value, scopes)
			lex = expander.parameterLex
		}
		expanded, _, err := lex.ProcessWord(word, env)
		if err == nil {
			if restore != nil {
				expanded = restore.Replace(expanded)
			}
			values[i] = expanded
			continue
		}
		values[i] = expander.expandParts(value, env, false)
	}
	return values
}

// expandParts isolates references before handing them to BuildKit. This is a
// recovery boundary, not an implementation of shell parameter operators. A bad
// reference or unmatched quote must not discard expansion elsewhere in a value.
func (e *wordExpander) expandParts(value string, env shell.EnvGetter, quoted bool) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		ch := value[i]
		switch {
		case ch == e.escape && i+1 < len(value):
			if escaped, end, ok := e.escapedPart(value, i, quoted); ok {
				out.WriteString(escaped)
				i = end
				continue
			}
		case !quoted && (ch == '\'' || ch == '"'):
			if part, end, ok := e.quotedPart(value, i, env); ok {
				out.WriteString(part)
				i = end
				continue
			}
		case ch == '$':
			end := e.referenceEnd(value, i)
			if end > i+1 {
				reference := value[i:end]
				lex := e.lex
				if strings.HasPrefix(reference, "${") && hasParameterOperator(reference) {
					lex = e.parameterLex
				}
				expanded, _, err := lex.ProcessWord(reference, env)
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

func (e *wordExpander) quoteEnd(value string, start int) int {
	for i := start + 1; i < len(value); i++ {
		if value[start] == '"' && value[i] == e.escape {
			i++
			continue
		}
		if value[i] == value[start] {
			return i
		}
	}
	return -1
}

func (e *wordExpander) referenceEnd(value string, start int) int {
	pos := start + 1
	if pos < len(value) && value[pos] == '{' {
		depth := 1
		for pos++; pos < len(value); pos++ {
			switch value[pos] {
			case e.escape:
				pos++
			case '\'', '"':
				if end := e.quoteEnd(value, pos); end >= 0 {
					pos = end
				}
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return pos + 1
				}
			}
		}
		return start + 1 // Preserve malformed text, allowing later references to expand.
	}
	for pos < len(value) && variableNameByte(value[pos]) {
		pos++
	}
	return pos
}

func variableNameByte(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_'
}

func hasParameterOperator(reference string) bool {
	pos := 2 // skip ${
	for pos < len(reference) && variableNameByte(reference[pos]) {
		pos++
	}
	return pos > 2 && pos < len(reference)-1
}

func (e *wordExpander) escapedPart(value string, pos int, quoted bool) (part string, end int, ok bool) {
	next := value[pos+1]
	if quoted && next != '$' && next != '"' && next != e.escape {
		return "", pos, false
	}
	if e.lex.RawEscapes {
		return value[pos : pos+2], pos + 2, true
	}
	return value[pos+1 : pos+2], pos + 2, true
}

func (e *wordExpander) quotedPart(value string, pos int, env shell.EnvGetter) (part string, end int, ok bool) {
	end = e.quoteEnd(value, pos)
	if end < 0 {
		return "", pos, false
	} // Unmatched quotes are literal during recovery.
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
func (e *wordExpander) protectUnknownReferences(value string, scopes variableEnvironment) (string, *strings.Replacer) {
	type reference struct{ start, end int }
	var unknown []reference
	for pos := 0; pos < len(value); pos++ {
		if value[pos] != '$' || e.isEscaped(value, pos) {
			continue
		}
		name, end, ok := plainReference(value, pos)
		if !ok {
			continue
		}
		if _, found := scopes.Get(name); found {
			continue
		}
		unknown = append(unknown, reference{pos, end})
		pos = end - 1
	}
	if len(unknown) == 0 {
		return value, nil
	}
	marker := "\x00"
	for containsMarker(value, scopes, marker) {
		marker += "\x00"
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

func (e *wordExpander) isEscaped(value string, pos int) bool {
	count := 0
	for pos--; pos >= 0 && value[pos] == e.escape; pos-- {
		count++
	}
	return count%2 != 0
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

func plainReference(value string, pos int) (name string, end int, ok bool) {
	start := pos + 1
	braced := start < len(value) && value[start] == '{'
	if braced {
		start++
	}
	end = start
	for end < len(value) && variableNameByte(value[end]) {
		end++
	}
	if end == start || braced && (end >= len(value) || value[end] != '}') {
		return "", pos, false
	}
	name = value[start:end]
	if braced {
		end++
	}
	return name, end, true
}
