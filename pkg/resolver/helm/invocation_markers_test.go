package helm

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
)

func TestAddHelmInvocationMarkersInspectsEveryAction(t *testing.T) {
	file := &chart.File{Data: []byte(`{{- if .Values.enabled }}{{ include "resource" . }}{{- end }}`)}
	addHelmInvocationMarkers(file)

	positions := map[string]bool{}
	for _, m := range regexp.MustCompile(`KICS_HELM_INVOCATION_\d+_\d+`).FindAllString(string(file.Data), -1) {
		positions[m] = true
	}
	require.Equal(t, map[string]bool{"KICS_HELM_INVOCATION_1_25": true}, positions)
}

// The source findings are located in is the template stamped with ID lines,
// never the one Helm renders with invocation markers.
func TestSetIDKeepsSourcesWithoutMarkers(t *testing.T) {
	for _, source := range []string{
		`{{ include "resource" . }}`,
		`{{- include "resource" (dict "a" .) -}}`,
		"{{ include \"a\" . }}\n---\n{{ template \"b\" . }}\n{{ include \"c\" . | nindent 0 }}",
		`{{ include "na}}me" . }}`,
		"kind: Service\n{{- if .a }}\n{{ include \"svc\" . }}\n{{- end }}\n",
	} {
		file := &chart.File{Name: "templates/t.yaml", Data: []byte(source)}
		sources := setID(&chart.Chart{Metadata: &chart.Metadata{Name: "c"}, Templates: []*chart.File{file}}, nil)
		require.Contains(t, string(file.Data), invocationPrefix)
		want := addID(&chart.File{Name: file.Name, Data: []byte(source)}, 0).Data
		require.Equal(t, string(want), string(sources.of(file)))
	}
}

// TestIsHelmInvocationWrapperCommentAction covers comment actions whose text
// holds an apostrophe (e.g. "don't"): quoted-string tracking would open a
// string at the apostrophe and never find the comment's "}}", leaving the
// action in place and disqualifying a genuine wrapper template (_helpers.tpl
// comments often contain contractions). The comment must be consumed whole.
func TestIsHelmInvocationWrapperCommentAction(t *testing.T) {
	source := "{{/* don't render when disabled */}}\n{{ include \"mychart.labels\" . }}\n"
	require.True(t, isHelmInvocationWrapper(source))

	// Trim markers and whitespace around the comment text must not change the
	// outcome.
	source = "{{- /* chart's helper, not emitted when disabled */ -}}\n{{ include \"mychart.labels\" . }}\n"
	require.True(t, isHelmInvocationWrapper(source))
	file := addHelmInvocationMarkers(&chart.File{Data: []byte(source)})
	require.Contains(t, string(file.Data), "KICS_HELM_INVOCATION_2_")
}

func TestAddHelmInvocationMarkersSkipsPartialBodies(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		wantMarked int
	}{
		{"define body", "{{- define \"p\" -}}\n{{- include \"q\" . -}}\n{{- end -}}\n", 0},
		{"conditional in define", "{{- define \"p\" -}}\n{{- if .a }}{{ include \"q\" . }}{{ end }}{{ template \"r\" . }}\n{{- end -}}\n", 0},
		{"block body", "{{- block \"p\" . -}}\n{{ include \"q\" . }}\n{{- end -}}\n", 0},
		{"top level after define", "{{- define \"p\" -}}\n{{ include \"q\" . }}\n{{- end -}}\n{{ include \"all\" . }}\n", 1},
		{"top level conditional", "{{- if .a }}\n{{ include \"all\" . }}\n{{- end }}\n", 1},
		{"if closed before define ends", "{{- define \"p\" -}}{{ if .a }}{{ end }}{{ include \"q\" . }}{{- end -}}{{ include \"all\" . }}", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := addHelmInvocationMarkers(&chart.File{Data: []byte(tt.source)})
			positions := map[string]bool{}
			for _, m := range regexp.MustCompile(`KICS_HELM_INVOCATION_\d+_\d+`).FindAllString(string(file.Data), -1) {
				positions[m] = true
			}
			require.Len(t, positions, tt.wantMarked)
			if tt.wantMarked == 0 {
				require.Equal(t, tt.source, string(file.Data), "an uninstrumented template is left unchanged")
			}
		})
	}
}

func TestAddHelmInvocationMarkersKeepsIncludeIndentation(t *testing.T) {
	source := "kind: Service\nmetadata:\n  labels:\n    {{ include \"l\" . | nindent 4 | trim }}\n"
	file := addHelmInvocationMarkers(&chart.File{Name: "templates/svc.yaml", Data: []byte(source)})
	require.Contains(t, string(file.Data), "\" }}    {{ include \"l\" . | nindent 4 | trim }}",
		"an indented include is not rewritten, which would move its output out of the indentation")
}

func TestAddHelmInvocationMarkersRewritesLineStartingInclude(t *testing.T) {
	source := "kind: Service\n{{- if .a }}\n{{ include \"docs\" . }}\n{{- end }}\n"
	file := addHelmInvocationMarkers(&chart.File{Name: "templates/svc.yaml", Data: []byte(source)})
	require.Contains(t, string(file.Data), "\n{{ regexReplaceAll ")
	require.Contains(t, string(file.Data),
		"(print \"# KICS_HELM_INVOCATION_3_0:\\n\" ( include \"docs\" . ) \"\\n# KICS_HELM_INVOCATION_END:\")")
}

func TestBlockScalarHeaderWithComment(t *testing.T) {
	require.True(t, insideBlockScalar("data:\n  cfg: | # keep\n"))
	require.True(t, insideBlockScalar("data:\n  cfg: >-  # folded\n    a\n"))
	require.False(t, insideBlockScalar("data:\n  cfg: a # | not a header\n"))
}

// A scalar is open only while every line after its header is indented more
// than the header's line.
func TestInsideBlockScalarEndsWithItsIndentation(t *testing.T) {
	require.True(t, insideBlockScalar("data:\n  script: |\n    echo hi\n"))
	require.True(t, insideBlockScalar("data:\n  script: |\n    echo hi\n\n      indented\n"))
	require.False(t, insideBlockScalar("data:\n  script: |\n    echo hi\n  other: x\n"))
	require.False(t, insideBlockScalar("data:\n  script: |\n    echo hi\nspec: x\n"))
	require.True(t, insideBlockScalar("data:\n  a: |\n    x\n  b: >\n    y\n"))
	require.True(t, insideBlockScalar("data:\n  a: |\n    {{ .Values.x }}\n"))
}

func TestAddHelmInvocationMarkersMixedManifest(t *testing.T) {
	tests := []struct {
		name       string
		file       string
		source     string
		wantMarked int
	}{
		{"standalone include", "templates/svc.yaml",
			"kind: Service\n{{- $x := 1 }}\n{{- if .a }}\n{{ include \"svc\" . }}\n{{- end }}\n", 1},
		{"standalone with pipe and indent", "templates/svc.yaml",
			"kind: Service\nmetadata:\n  labels:\n  {{ include \"l\" . | nindent 4 }}\n", 1},
		{"inline scalar", "templates/svc.yaml",
			"kind: Service\nmetadata:\n  name: {{ include \"n\" . }}\n", 0},
		{"trimmed include keeps gluing", "templates/svc.yaml",
			"kind: Service\nmetadata:\n  labels: {{- include \"l\" . | nindent 4 }}\n", 0},
		{"trimmed standalone include", "templates/svc.yaml",
			"kind: Service\nmetadata:\n  annotations:\n  {{- include \"a\" . | nindent 4 }}\n", 0},
		{"after right-trimmed include", "templates/cm.yaml",
			"metadata:\n  labels:\n    {{- include \"base\" . | nindent 4 -}}\n{{ include \"extra\" . | nindent 4 }}\n", 0},
		{"after right-trimmed if", "templates/cm.yaml",
			"kind: ConfigMap\ndata:\n{{- if .Values.extra -}}\n{{ include \"extra\" . | nindent 2 }}\n{{- end }}\n", 0},
		{"after right-trimmed action and blank line", "templates/cm.yaml",
			"kind: ConfigMap\ndata:\n{{- $x := 1 -}}\n\n{{ include \"extra\" . | nindent 2 }}\n", 0},
		{"after right-trimmed comment", "templates/cm.yaml",
			"kind: ConfigMap\ndata:\n{{- /* extra keys */ -}}\n{{ include \"extra\" . | nindent 2 }}\n", 0},
		{"text after include on the line", "templates/svc.yaml",
			"{{ include \"a\" . }}: value\n", 0},
		{"inside block scalar", "templates/cm.yaml",
			"kind: ConfigMap\ndata:\n  config: |\n{{ include \"c\" . | indent 4 }}\n", 0},
		{"after block scalar content", "templates/cm.yaml",
			"kind: ConfigMap\ndata:\n  config: |\n    a: b\n{{ include \"c\" . | indent 4 }}\n", 0},
		{"partial file", "templates/_helpers.tpl",
			"app: {{ .Chart.Name }}\n{{ include \"a\" . }}\n", 0},
		{"define inside manifest", "templates/svc.yaml",
			"{{- define \"p\" -}}\nx: 1\n{{ include \"q\" . }}\n{{- end -}}\nkind: Service\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := addHelmInvocationMarkers(&chart.File{Name: tt.file, Data: []byte(tt.source)})
			require.Equal(t, tt.wantMarked, strings.Count(string(file.Data), "print \"# KICS_HELM_INVOCATION_"))
			if tt.wantMarked == 0 {
				require.Equal(t, tt.source, string(file.Data), "an uninstrumented template is left unchanged")
			}
		})
	}
}

// The render without markers leaves templates untouched and keeps the same
// stamped sources as the render with them.
func TestSetIDWithoutMarkersLeavesTemplates(t *testing.T) {
	source := "kind: Service\n{{ include \"svc\" . }}\n"
	file := &chart.File{Name: "templates/t.yaml", Data: []byte(source)}
	sources := setID(&chart.Chart{Metadata: &chart.Metadata{Name: "c"}, Templates: []*chart.File{file}}, &invocationMarks{none: true})
	require.NotContains(t, string(file.Data), invocationPrefix)
	require.Equal(t, string(addID(&chart.File{Name: file.Name, Data: []byte(source)}, 0).Data), string(sources.of(file)))
}
