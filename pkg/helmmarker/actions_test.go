package helmmarker

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func texts(source string, actions []Action) []string {
	var out []string
	for _, a := range actions {
		out = append(out, source[a.Start:a.End])
	}
	return out
}

func TestScanEndsActionsOutsideQuotes(t *testing.T) {
	for name, tc := range map[string]struct {
		source string
		want   []string
	}{
		"plain":              {"a: {{ .x }}\n", []string{"{{ .x }}"}},
		"quoted end":         {`a: {{ printf "}}" }} b`, []string{`{{ printf "}}" }}`}},
		"single quote":       {`a: {{ printf '}' }} b`, []string{`{{ printf '}' }}`}},
		"raw string":         {"a: {{ `}}` }} b", []string{"{{ `}}` }}"}},
		"escaped quote":      {`a: {{ printf "\"}}" }} b`, []string{`{{ printf "\"}}" }}`}},
		"trim markers":       {"{{- if .x -}}\n", []string{"{{- if .x -}}"}},
		"comment with }}":    {"{{/* }} */}}\n", []string{"{{/* }} */}}"}},
		"comment apostrophe": {"{{/* don't */}}\na: 1\n", []string{"{{/* don't */}}"}},
		"two actions":        {"{{ a }}{{ b }}", []string{"{{ a }}", "{{ b }}"}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, texts(tc.source, Terminated(tc.source)))
		})
	}
}

func TestScanUnterminatedKeepsFindingLaterActions(t *testing.T) {
	s := "a: {{ include \"x\n# note\nb: {{ .v }}\n"
	actions := Scan(s)
	require.Len(t, actions, 2)
	require.True(t, actions[0].Unterminated)
	require.Equal(t, len(s)-1, actions[0].End, "ends after the next }}")
	require.False(t, actions[1].Unterminated)
	require.Equal(t, []string{"{{ .v }}"}, texts(s, Terminated(s)))
}

func TestCodeLeavesComments(t *testing.T) {
	s := "{{/* c */}}{{ a }}"
	require.Equal(t, []string{"{{ a }}"}, texts(s, Code(s)))
}

func TestRemoveKeepsOnlyText(t *testing.T) {
	require.Equal(t, "a: \nb: 1\n", Remove("a: {{ printf \"}}\" }}\nb: 1\n"))
}

func TestBlankKeepsLineCount(t *testing.T) {
	for name, tc := range map[string]struct{ source, want string }{
		"quoted action end":       {"name: {{ include \"x}}\" . }}\n# it's ignored\n# kics-scan ignore-line\nx: 1\n", "name: \n# it's ignored\n# kics-scan ignore-line\nx: 1\n"},
		"raw string":              {"a: {{ `}}` }}\nb: 1\n", "a: \nb: 1\n"},
		"comment with }}":         {"a: {{/* }} */}}\nb: 1\n", "a: \nb: 1\n"},
		"comment with apostrophe": {"{{/* don't */}}\na: 1\n", "\na: 1\n"},
		"trim markers":            {"a: 1\n{{- if .x -}}\nb: 2\n{{- end -}}\n", "a: 1\n\nb: 2\n\n"},
		"crlf":                    {"a: {{ .x\r\n | quote }}\r\nb: 1\r\n", "a: \n\r\nb: 1\r\n"},
		"multi-line quoted":       {"a: {{ \"x\ny\" }}\nb: 1\n", "a: \n\nb: 1\n"},
		"unterminated quote":      {"a: {{ include \"x\n# kics-scan ignore-line\nb: {{ .v }}\n", "a: \n\n\n"},
		"unterminated comment":    {"a: 1\n{{/* never\nb: 2\n", "a: 1\n\n\n"},
		"no actions":              {"a: 1\n", "a: 1\n"},
		"actions of a template":   {"a: {{ .Values.x }}\n{{- if .Values.y }}\nb: 1\n{{- end }}\nc: {{ include \"t\" .\n  | indent 4 }}\nd: 2\n", "a: \n\nb: 1\n\nc: \n\nd: 2\n"},
	} {
		t.Run(name, func(t *testing.T) {
			got := string(Blank([]byte(tc.source)))
			require.Equal(t, tc.want, got)
			require.Equal(t, strings.Count(tc.source, "\n"), strings.Count(got, "\n"))
			require.NotContains(t, got, "{{")
		})
	}
}

// The scanner every pass of the resolver shares: a substitution after a quoted
// "}}" is still inside its action.
func TestInAnyAndInQuote(t *testing.T) {
	s := `{{ printf "}}%s" (now) }} now`
	code := Code(s)
	require.Len(t, code, 1)
	require.True(t, InAny(strings.Index(s, "(now)"), code))
	require.False(t, InQuote(s, strings.Index(s, "(now)"), code))
	require.True(t, InQuote(s, strings.Index(s, "}}%s"), code))
	require.False(t, InAny(strings.LastIndex(s, "now"), code), "text after the action is not in it")
}
