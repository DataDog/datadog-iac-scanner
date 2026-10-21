package docker

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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

// expandValues uses BuildKit for shell expansion. Unknown references stay
// visible to rules; explicit defaults still apply to unset variables in valid
// words. Rejected words only substitute known plain references outside single
// quotes, preserving every other byte. Inserted values are never scanned again.
func expandValues(expander *wordExpander, values []string, scopes ...map[string]string) []string {
	for i, value := range values {
		if !strings.ContainsAny(value, "$\\\"'`") {
			continue
		}
		env := variableEnvironment(scopes)
		word, restore := protectBadBytes(value, env)
		expanded, syntax, err := expander.expandWord(word, env)
		if err != nil {
			expanded = expander.recoverWord(word, env, syntax)
		}
		if restore != nil {
			expanded = restore.Replace(expanded)
		}
		values[i] = expanded
	}
	return values
}

// recoverWord makes a single O(n) walk over the scanner's ordered references.
// Only known plain names are replaced. All other source bytes, including quotes,
// escapes and parameter operators, stay untouched. Values are never rescanned.
func (e *wordExpander) recoverWord(value string, env variableEnvironment, syntax shellSyntax) string {
	var out strings.Builder
	copied := 0
	for _, ref := range syntax.references {
		if ref.end == 0 || ref.name(value) == "" {
			continue
		}
		if ref.braced(value) && ref.end != ref.nameEnd+1 {
			continue
		}
		name := ref.name(value)
		first, _ := utf8.DecodeRuneInString(name)
		if first != '_' && !unicode.IsLetter(first) {
			continue
		}
		replacement, known := env.Get(name)
		if !known {
			continue
		}
		out.WriteString(value[copied:ref.start])
		out.WriteString(replacement)
		copied = ref.end
	}
	if copied == 0 {
		return value
	}
	out.WriteString(value[copied:])
	return out.String()
}

// expandWord applies unknown-reference policy to complete values. Returned spans
// belong to value (not the masked word) and are reused by malformed recovery.
func (e *wordExpander) expandWord(value string, env variableEnvironment) (expanded string, syntax shellSyntax, err error) {
	word, restore := value, (*strings.Replacer)(nil)
	lex := e.lex
	parameters := strings.Contains(value, "${")
	if parameters {
		// SkipUnsetEnv also skips defaults. Preserve unknown references and
		// operations needing their values before evaluating explicit defaults.
		syntax = e.scanShell(value, false)
		word, restore = e.protectUnknownReferences(value, env, syntax)
		lex = e.parameterLex
	}
	expanded, _, err = lex.ProcessWord(word, env)
	if err != nil && !parameters {
		syntax = e.scanShell(value, false)
	}
	if err == nil && restore != nil {
		expanded = restore.Replace(expanded)
	}
	return expanded, syntax, err
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

// protectUnknownReferences preserves the scanner's unknown-value convention
// without asking the lexer to disable unset-variable operators. Placeholders
// cannot occur in source or scope values and are restored in one pass, so inserted
// values remain literal. Quotes and escapes are still processed by BuildKit.
// The ordered O(len(value)) walk reuses the caller's context scan without
// mutating its spans, so malformed recovery can use the same result.
func (e *wordExpander) protectUnknownReferences(value string, scopes variableEnvironment, syntax shellSyntax) (string, *strings.Replacer) {
	const privateMarker = "\ue000"
	var marker string
	var out strings.Builder
	var replacements []string
	pos := 0
	for _, ref := range syntax.references {
		if ref.start < pos || ref.name(value) == "" || ref.end == 0 {
			continue
		}
		if _, found := scopes.Get(ref.name(value)); found || !preserveUnknownReference(value, ref) {
			continue
		}
		if marker == "" {
			marker = privateMarker
			for containsMarker(value, scopes, marker) {
				marker += privateMarker
			}
		}
		token := marker + strconv.Itoa(len(replacements)/2) + marker
		out.WriteString(value[pos:ref.start])
		out.WriteString(token)
		replacements = append(replacements, token, value[ref.start:ref.end])
		pos = ref.end
	}
	if len(replacements) == 0 {
		return value, nil
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
