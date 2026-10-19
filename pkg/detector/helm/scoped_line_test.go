package helm

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"
	"github.com/stretchr/testify/require"
)

func TestCannotPrint(t *testing.T) {
	tests := []struct {
		name, line, text string
		want             bool
	}{
		{"nindent wider than the text's indent", "          lifecycle: {{- include \"x\" . | nindent 12 }}", "        - name: web", true},
		{"nindent not wider than the text's indent", "          lifecycle: {{- include \"x\" . | nindent 12 }}", "            privileged: true", false},
		{"indent wider than the text's indent", "  {{ toYaml .Values.a | indent 8 }}", "    key: value", true},
		{"pipe inside parentheses is not the last stage", "  k: {{ include \"x\" (dict \"a\" (1 | quote)) . }}", "  other: x", false},
		{"width that is not a number", "  {{ include \"x\" . | nindent .Values.w }}", "a: b", false},
		{"quote after a key, text of another key", "  value: {{ .Values.a | quote }}", "  name: web", true},
		{"quote after a key, text of the same key", "  value: {{ .Values.a | quote }}", "  value: \"x\"", false},
		{"quote with no key before it", "{{ .Values.a | quote }}", "  name: web", false},
		{"no function", "  value: {{ .Values.a }}", "  name: web", false},
		{"two actions", "  value: {{ .Values.a | quote }}{{ .Values.b }}", "  name: web", false},
		{"nindent then another function", "  {{ include \"x\" . | nindent 8 | trim }}", "a: b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, cannotPrint(helmaction.Scan(tt.line), tt.line, tt.text))
		})
	}
}

func TestLastStage(t *testing.T) {
	require.Equal(t, " nindent 4 ", lastStage(` include "a|b" (dict "k" (x | y)) | nindent 4 `))
	require.Equal(t, ` include "a" `, lastStage(` include "a" `))
}

func TestLineBranches(t *testing.T) {
	lines := []string{"a: 1", "{{- if .A }}", "b: 2", "{{- else }}", "c: 3", "{{- end }}", "d: 4", "{{- range .L }}", "e: 5", "{{- end }}"}
	branches := lineBranches(lines)
	require.Equal(t, 0, branches[0])
	require.Equal(t, 0, branches[6])
	require.NotEqual(t, branches[2], branches[4], "the branches of an if differ")
	require.NotZero(t, branches[2])
	require.NotZero(t, branches[8])
}

func TestLineBranchesSeparatedByATab(t *testing.T) {
	lines := []string{"{{ if\tfalse }}", "a: 1", "{{ else }}", "a: {{ .V }}", "{{ end }}", "b: 2"}
	branches := lineBranches(lines)
	require.NotZero(t, branches[1])
	require.NotEqual(t, branches[1], branches[3])
	require.Zero(t, branches[5])
}

func TestListIndexKeys(t *testing.T) {
	rendered := []string{"rules:", "  - verbs:", "      - get", "  - verbs:", "      - list"}
	line, ok := itemLine(rendered, []keyMatch{{key: "rules", line: 0}}, "1")
	require.True(t, ok)
	require.Equal(t, 3, line)
	_, ok = itemLine(rendered, []keyMatch{{key: "rules", line: 0}}, "2")
	require.False(t, ok)
	require.True(t, keyPathHolds(rendered, []keyMatch{{key: "rules", line: 0}, {key: "1", index: true, line: 3}, {key: "verbs", line: 3}}))
	require.False(t, keyPathHolds(rendered, []keyMatch{{key: "rules", line: 0}, {key: "1", index: true, line: 1}}))
}

func TestSelectorMatchingSeveralItemsDoesNotHold(t *testing.T) {
	rendered := []string{"containers:", "  - name: a", "    image: x", "  - name: a", "    image: y", "  - name: b", "    image: z"}
	path := func(line int, name string) []keyMatch {
		return []keyMatch{{key: "containers", line: 0}, {key: "name", selector: true, line: line}, {key: "image", line: line + 1}}
	}
	require.False(t, keyPathHolds(rendered, path(1, "a")), "two items are named a")
	require.True(t, keyPathHolds(rendered, path(5, "b")))
}

// A number after a mapping is one of its keys, not a position.
func TestNumericKeyOfAMappingIsNotAListIndex(t *testing.T) {
	rendered := []string{"# KICS_HELM_ID_0_1:", "apiVersion: v1", "kind: ConfigMap", "data:", `  "0": a`, `  "1": b`}
	var extracted [][]string
	var path []keyMatch
	found, _, _ := detectCurlLine{}.walkSearchKey(context.Background(), rendered, "data.1", extracted, nil, -1, &path)
	require.False(t, found.breakRes)
	require.Equal(t, 5, found.lineRes)

	list := []string{"rules:", "  - verbs: a", "  - verbs: b"}
	path = nil
	found, _, _ = detectCurlLine{}.walkSearchKey(context.Background(), list, "rules.1.verbs", extracted, nil, -1, &path)
	require.False(t, found.breakRes)
	require.Equal(t, 2, found.lineRes, "after a list the number is still a position")
}

// A quoted key in the middle of a scalar is text: a selector whose item is
// absent must not take the scalar's line for the item.
func TestSelectorIgnoresQuotedKeyInsideAScalar(t *testing.T) {
	absent := []string{"spec:", "  containers:", "    - name: other", "      image: x", `data: '{"name": web}'`}
	got, _, _ := detectCurlLine{lineRes: 1}.detectCurrentLine(absent, "name:", "web", true, nil, -1)
	require.True(t, got.breakRes, "the item is absent, so nothing is found")

	present := []string{"spec:", "  containers:", "    - name: other", "      image: x", `data: '{"name": web}'`, "    - name: web"}
	got, _, _ = detectCurlLine{lineRes: 1}.detectCurrentLine(present, "name:", "web", true, nil, -1)
	require.Equal(t, 5, got.lineRes, "the item is the list line, not the scalar")
}

// An indent after a key or a dash prints its padding after that text, so a
// line that holds the padded value can be its printer.
func TestIndentAfterAPrefixCanPrint(t *testing.T) {
	for _, tt := range []struct {
		line, text string
		printer    bool
	}{
		{"- {{ .Values.x | indent 2 }}      # x: bar", "-   bar", true},
		{"  {{- .Values.x | indent 2 }}     # x: bar", "foo:  bar", true},
		{"key: {{ .Values.x | indent 4 }}", "key: bar", false},
	} {
		_, printer := lineWrites(tt.line, tt.text, false)
		require.Equal(t, tt.printer, printer, tt.line)
	}
}

// A quoted key of an inline mapping is a key, as in a flow sequence item.
func TestSelectorAcceptsQuotedKeyOfAnInlineMapping(t *testing.T) {
	for _, line := range []string{`  - {"name": "web", "image": "nginx"}`, `    env: {"name": web}`, `"name": web`} {
		require.True(t, quotedKeyStarts(line, "name:"), line)
	}
	require.False(t, quotedKeyStarts(`data: '{"name": web}'`, "name:"))
	require.False(t, quotedKeyStarts(`# "name": web`, "name:"))
	require.False(t, quotedKeyStarts(`hostNetwork: true # "name": web`, "name:"))
	require.False(t, quotedKeyStarts(`data: "{\"name\": web}"`, "name:"))
}

func TestSelectorFindsItemWrittenAsInlineMapping(t *testing.T) {
	lines := []string{"spec:", "  containers:", `  - {"name": "web", "image": "nginx"}`}
	got, _, _ := detectCurlLine{lineRes: 1}.detectCurrentLine(lines, "name:", "web", true, nil, -1)
	require.False(t, got.breakRes)
	require.Equal(t, 2, got.lineRes)
}

// An apostrophe inside a plain value opens no quote, so a key after it is found;
// a quoted scalar that holds the key does not expose it.
func TestQuotedKeyNextToAnApostrophe(t *testing.T) {
	require.True(t, quotedKeyStarts(`- {a: it's, "name": web}`, "name:"))
	require.True(t, quotedKeyStarts(`- {a: it's, 'name': web}`, "name:"))
	require.False(t, quotedKeyStarts(`data: 'it''s {"name": web}'`, "name:"))
	require.False(t, quotedKeyStarts(`data: "a\" "name": web"`, "name:"))
}
