package helm

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
)

func TestHelm_DeterministicRendering(t *testing.T) {
	res := &Resolver{}
	ctx := context.Background()

	fixturePath := filepath.FromSlash("../../../test/fixtures/test_helm_nondeterministic")

	first, err := res.Resolve(ctx, fixturePath)
	require.NoError(t, err)
	require.NotEmpty(t, first.File, "first render must produce at least one file")

	second, err := res.Resolve(ctx, fixturePath)
	require.NoError(t, err)

	require.Equal(t, first.File, second.File, "helm rendering must be deterministic")
}

func TestHelm_NondeterministicFunctionsRenderLabels(t *testing.T) {
	res := &Resolver{}
	got, err := res.Resolve(context.Background(), filepath.FromSlash("../../../test/fixtures/test_helm_nondeterministic"))
	require.NoError(t, err)
	var job, service string
	for _, f := range got.File {
		switch {
		case strings.HasSuffix(filepath.ToSlash(f.FileName), "templates/job.yaml"):
			job = string(f.Content)
		case strings.HasSuffix(filepath.ToSlash(f.FileName), "templates/service.yaml"):
			service = string(f.Content)
		}
	}
	// The release is the chart's own name, as helm install <chart> names it.
	require.Contains(t, job, "name: test_helm_nondeterministic-test_helm_nondeterministic-<randAlphaNum>")
	require.Contains(t, job, "scan-id: <uuidv4>")
	require.Contains(t, job, "created-date: <now>")
	require.Contains(t, job, "image: nginx:latest")
	require.Contains(t, service, "port-seed: <randNumeric>")
	// What findings are located in is the template as written.
	for _, f := range got.File {
		require.NotContains(t, string(f.OriginalData), "<randAlphaNum>")
	}
}

// renderRewritten renders templates (file name to source) as chart "app"
// with values, after rewriting them to level, and returns each output.
func renderRewritten(t *testing.T, level rewriteLevel, values map[string]interface{}, templates map[string]string) (map[string]string, error) {
	t.Helper()
	ch := &chart.Chart{
		Metadata: &chart.Metadata{APIVersion: chart.APIVersionV2, Name: "app", Version: "1.0.0"},
		Values:   map[string]interface{}{},
	}
	for name, src := range templates {
		ch.Templates = append(ch.Templates, &chart.File{Name: "templates/" + name, Data: []byte(src)})
	}
	before := map[string]int{}
	for _, f := range ch.Templates {
		before[f.Name] = strings.Count(string(f.Data), "\n")
	}
	rewriteChart(ch, level)
	for _, f := range ch.Templates {
		require.Equal(t, before[f.Name], strings.Count(string(f.Data), "\n"), "line count of %s:\n%s", f.Name, f.Data)
	}
	vals, err := chartutil.ToRenderValues(ch, values,
		chartutil.ReleaseOptions{Name: "rel", Namespace: "ns", IsInstall: true}, chartutil.DefaultCapabilities)
	require.NoError(t, err)
	out, err := engine.Render(ch, vals)
	if err != nil {
		return nil, err
	}
	rendered := map[string]string{}
	for name, text := range out {
		rendered[strings.TrimPrefix(name, "app/templates/")] = text
	}
	return rendered, nil
}

func renderOne(t *testing.T, level rewriteLevel, values map[string]interface{}, src string) string {
	t.Helper()
	out, err := renderRewritten(t, level, values, map[string]string{"t.yaml": src})
	require.NoError(t, err)
	return out["t.yaml"]
}

func TestRewritePlaceholdersForAbsentValues(t *testing.T) {
	values := map[string]interface{}{
		"present": "here",
		"empty":   "",
		"zero":    0,
		"global":  map[string]interface{}{"dc": map[string]interface{}{"env": "prod"}},
		"enabled": false,
	}
	tests := []struct {
		name, src, want string
	}{
		{"absent value printed", `name: {{ .Chart.Name }}-{{ $.Values.env }}`, "name: app-<.Values.env>"},
		{"present value printed", `name: {{ .Values.present }}`, "name: here"},
		{"empty string kept", `name: x{{ .Values.empty }}y`, "name: xy"},
		{"zero kept", `n: {{ .Values.zero }}`, "n: 0"},
		{"field of an absent map", `env: {{ .Values.global.oci.registry }}`, "env: <.Values.global.oci.registry>"},
		{"field of an absent root map", `env: {{ .Values.images.app.tag }}`, "env: <.Values.images.app.tag>"},
		{"present nested value", `env: {{ .Values.global.dc.env }}`, "env: prod"},
		{"text functions keep the placeholder whole", `n: {{ .Values.env | lower | trunc 3 | quote }}`, "n: <.Values.env>"},
		{"text functions apply to a present value", `n: {{ .Values.present | upper | quote }}`, `n: "HERE"`},
		{"printf argument", `n: {{ printf "%s-%s" .Release.Name .Values.suffix }}`, "n: rel-<.Values.suffix>"},
		{"default still applies", `n: {{ .Values.tag | default "latest" }}`, "n: latest"},
		{"default of an absent default", `n: {{ default .Values.fallback .Values.tag }}`, "n: <.Values.fallback>"},
		{"absent condition stays false", `{{ if .Values.ingress.enabled }}on{{ else }}off{{ end }}`, "off"},
		{"absent with", `{{ with .Values.global.oci }}{{ .registry }}{{ else }}none{{ end }}`, "none"},
		{"with on present map", `{{ with .Values.global }}{{ .dc.env }}-{{ .dc.region }}{{ end }}`, "prod-<.Values.global.dc.region>"},
		{"range on absent list", `{{ range .Values.global.items }}x{{ end }}done`, "done"},
		{"comparison on absent value", `{{ if eq .Values.global.datacenter.environment "gov" }}gov{{ end }}x`, "x"},
		{"variable bound to a values map", `{{ $g := .Values.global }}{{ $g.dc.env }}/{{ $g.oci.registry }}`, "prod/<.Values.global.oci.registry>"},
		{"variable defaulting a map", `{{ $o := .Values.oci | default dict }}{{ $o.registry }}`, "<.Values.oci.registry>"},
		{"required on an absent value", `n: {{ required "env is required" .Values.env }}`, "n: <.Values.env>"},
		{"required on an empty value", `n: {{ required "empty is required" .Values.empty | quote }}`, "n: <.Values.empty>"},
		{"required on a present value", `n: {{ required "x" .Values.present }}`, "n: here"},
		{"required inside printf", `n: {{ printf "%s.%s" (required "x" .Values.a) .Values.present }}`, "n: <.Values.a>.here"},
		{"fail is neutralized", `{{ if not .Values.env }}{{ fail "env must be set" }}{{ end }}ok`, "ok"},
		{"toYaml of an absent map", `r: {{ toYaml .Values.resources.limits }}`, "r: null"},
		{"index with string keys", `n: {{ index .Values "my-key" "sub" }}`, "n: <.Values.my-key.sub>"},
		{"index on a present map", `n: {{ index .Values.global "dc" "env" }}`, "n: prod"},
		{"lookup field", `n: {{ (lookup "v1" "Secret" "ns" "s").data.password }}`, "n: <lookup>"},
		{"lookup variable", `{{ $s := lookup "v1" "Secret" "ns" "s" }}{{ if $s }}found{{ else }}{{ $s.data.password | default "new" }}{{ end }}`, "new"},
		{"range element field", `{{ range $k, $v := .Values.global }}{{ $k }}={{ $v.env }}{{ end }}`, "dc=prod"},
		{"bool kept", `b: {{ .Values.enabled }}`, "b: false"},
		{"trimmed action keeps trimming", "a:\n  {{- .Values.env | quote }}\nb", "a:<.Values.env>\nb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, renderOne(t, rewritePlaceholders, values, tt.src))
		})
	}
}

func TestRewriteTolerantPrintsNoPlaceholder(t *testing.T) {
	out := renderOne(t, rewriteTolerant, nil,
		`a: {{ .Values.env }} b: {{ .Values.global.dc.env }} c: {{ required "x" .Values.req }}`)
	require.Equal(t, "a:  b:  c: <.Values.req>", out)
}

func TestRewriteDeterministicKeepsHelmErrors(t *testing.T) {
	_, err := renderRewritten(t, rewriteDeterministic, nil, map[string]string{
		"t.yaml": `env: {{ .Values.global.dc.env }}`,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil pointer evaluating")
}

func TestRewriteNondeterministicFunctions(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"random suffix", `name: {{ $.Chart.Name }}-{{ randAlphaNum 8 | lower }}`, "name: app-<randAlphaNum>"},
		{"time based name", `name: {{ .Release.Name }}-migrate-{{ now | unixEpoch }}`, "name: rel-migrate-<now>"},
		{"nested in printf", `n: {{ printf "%s-%s" .Release.Name (randAlpha 5 | lower) }}`, "n: rel-<randAlpha>"},
		{"niladic argument", `n: {{ printf "id-%s" uuidv4 }}`, "n: id-<uuidv4>"},
		{"time function of now", `d: {{ date "2006" now }}`, "d: <now>"},
		{"time function of nested now", `d: {{ dateInZone "2006" (now) "UTC" }}`, "d: <now>"},
		{"variable holding a random string", `{{ $p := randAlphaNum 16 }}p: {{ $p | b64enc }} u: {{ printf "user:%s" $p }}`, "p: <randAlphaNum> u: user:<randAlphaNum>"},
		{"variable holding a time", `{{ $t := now }}t: {{ $t | date "2006" }} {{ $t }}`, "t: <now> <now>"},
		{"certificate fields", `{{ $ca := genCA "ca" 365 }}{{ $c := genSignedCert "x" nil nil 365 $ca }}crt: {{ $c.Cert | b64enc }} ca: {{ $ca.Cert }}`, "crt: <genSignedCert> ca: <genCA>"},
		{"with on a certificate", `{{ with genCA "ca" 365 }}{{ .Key }}{{ end }}`, "<genCA>"},
		{"random number in arithmetic", `n: {{ add 1 (randInt 0 9) }}`, "n: <randInt>"},
		{"name containing the function", `n: {{ .Values.now }}{{ $now := 1 }}{{ $now }}`, "n: <.Values.now>1"},
		{"function name in a string", `n: {{ printf "set this now" }}`, "n: set this now"},
		{"comment", "{{/* randAlphaNum 8 */}}n: {{ randAscii 3 }}", "n: <randAscii>"},
		{"quoted delimiter", `n: {{ printf "}}%s" (randAlphaNum 8) }}`, "n: }}<randAlphaNum>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, renderOne(t, rewritePlaceholders, nil, tt.src))
		})
	}
}

func TestRewriteIsDeterministicAtEveryLevel(t *testing.T) {
	src := `a: {{ randAlphaNum 8 }} b: {{ now | unixEpoch }} c: {{ uuidv4 }}`
	for _, level := range []rewriteLevel{rewriteDeterministic, rewriteTolerant, rewritePlaceholders} {
		require.Equal(t, "a: <randAlphaNum> b: <now> c: <uuidv4>", renderOne(t, level, nil, src))
	}
}

func TestRewriteMissingNamedTemplates(t *testing.T) {
	out, err := renderRewritten(t, rewritePlaceholders, nil, map[string]string{
		"_helpers.tpl": `{{- define "app.name" -}}{{ .Chart.Name }}{{- end -}}`,
		"t.yaml": "name: {{ include \"common.names.fullname\" . }}\nown: {{ include \"app.name\" . }}\n" +
			"labels:\n  {{- include \"common.labels.standard\" . | nindent 2 }}\n{{ template \"common.missing\" . }}end",
	})
	require.NoError(t, err)
	require.Equal(t, "name: <include common.names.fullname>\nown: app\nlabels:\n  \nend", out["t.yaml"])
}

func TestRewritePlaceholdersInNamedTemplates(t *testing.T) {
	templates := map[string]string{
		"_helpers.tpl": `{{- define "app.flag" -}}{{ .Values.flag }}{{- end -}}` +
			`{{- define "app.fullname" -}}{{ .Chart.Name }}-{{ .Values.env }}{{- end -}}`,
		// Helm makes an include of an absent value return "<no value>", which a
		// test takes for a value: a placeholder does not change that.
		"t.yaml": `{{ if include "app.flag" . }}flagged {{ end }}name: {{ include "app.fullname" . }}`,
	}
	out, err := renderRewritten(t, rewritePlaceholders, nil, templates)
	require.NoError(t, err)
	require.Equal(t, "flagged name: app-<.Values.env>", out["t.yaml"])
	out, err = renderRewritten(t, rewriteDeterministic, nil, templates)
	require.NoError(t, err)
	require.Equal(t, "flagged name: app-", out["t.yaml"])
}

func TestRewriteKeepsLines(t *testing.T) {
	src := "a: {{ .Values.global.dc.env\n }}\nb: {{ randAlphaNum\n 4 | lower }}\nc: {{- .Values.env\n | quote -}}\nd: {{ template \"missing\"\n . }}\n" +
		"f: {{ index .Values\n \"x\" }}\ng: {{ printf \"%s\" (required \"m\" (index .Values\n \"y\")) }}\nh: {{ (lookup \"v1\"\n \"Secret\" \"ns\" \"s\").data.x }}\ne"
	out := renderOne(t, rewritePlaceholders, nil, src)
	require.Equal(t, "a: <.Values.global.dc.env>\nb: <randAlphaNum>\nc:<.Values.env>d: \nf: <.Values.x>\ng: <.Values.y>\nh: <lookup>\ne", out)
}

func TestRewriteUnparsableTemplateIsKept(t *testing.T) {
	src := "a: {{ .Values.x "
	ch := &chart.Chart{
		Metadata:  &chart.Metadata{APIVersion: chart.APIVersionV2, Name: "app", Version: "1.0.0"},
		Templates: []*chart.File{{Name: "templates/t.yaml", Data: []byte(src)}},
	}
	rewriteChart(ch, rewritePlaceholders)
	require.Equal(t, src, string(ch.Templates[0].Data))
}

// renderPlain renders templates as chart "app" with values, as Helm does.
func renderPlain(t *testing.T, values map[string]interface{}, templates map[string]string) map[string]string {
	t.Helper()
	ch := &chart.Chart{
		Metadata: &chart.Metadata{APIVersion: chart.APIVersionV2, Name: "app", Version: "1.0.0"},
		Values:   map[string]interface{}{},
	}
	for name, src := range templates {
		ch.Templates = append(ch.Templates, &chart.File{Name: "templates/" + name, Data: []byte(src)})
	}
	vals, err := chartutil.ToRenderValues(ch, values,
		chartutil.ReleaseOptions{Name: "rel", Namespace: "ns", IsInstall: true}, chartutil.DefaultCapabilities)
	require.NoError(t, err)
	out, err := engine.Render(ch, vals)
	require.NoError(t, err)
	rendered := map[string]string{}
	for name, text := range out {
		rendered[strings.TrimPrefix(name, "app/templates/")] = text
	}
	return rendered
}

// Rewriting never changes what a template renders when the values it reads
// are there, nor how its tests of an absent value turn out.
func TestRewriteKeepsHelmSemantics(t *testing.T) {
	present := map[string]interface{}{
		"password": "secret",
		"env":      "prod",
		"a":        map[string]interface{}{"b": "c", "list": []interface{}{map[string]interface{}{"name": "x"}}},
		"image":    map[string]interface{}{"registry": "reg", "tag": "1"},
		"empty":    "",
	}
	templates := map[string]string{
		"_helpers.tpl": `{{- define "app.quoted" -}}{{ .Values.missing | quote }}{{- end -}}` +
			`{{- define "app.name" -}}{{ .Chart.Name }}-{{ .Values.env }}{{- end -}}`,
		"t.yaml": `{{- $p := .Values.password }}{{- if not $p }}{{- $p = randAlphaNum 16 }}{{- end }}p: {{ $p | b64enc }}
{{- $v := .Values }} v: {{ $v.env }} {{ $v.a.b }} {{ index $v "a" "b" }}{{ if $v.a.b }} set{{ end }}
{{- with .Values }} w: {{ .a.b }}{{ end }}
{{- $q := .Values.missing | quote }}{{ if $q }} q-set{{ else }} q-unset{{ end }}
{{- $r := default .Values.missing .Values.image.registry }}{{ if $r }} r: {{ $r }}{{ end }}
{{- $s := default .Values.missing .Values.alsoMissing }}{{ if $s }} s-set{{ else }} s-unset{{ end }}
{{- if include "app.quoted" . }} included{{ else }} not-included{{ end }}
 n: {{ include "app.name" . }}
{{- range .Values.a.list }} item: {{ .name }}{{ end }}
 e: [{{ .Values.empty }}]
`,
	}
	plain := renderPlain(t, present, templates)
	for _, level := range []rewriteLevel{rewriteDeterministic, rewriteTolerant, rewritePlaceholders} {
		out, err := renderRewritten(t, level, present, templates)
		require.NoError(t, err)
		require.Equal(t, plain["t.yaml"], out["t.yaml"], "level %d", level)
	}

	// Without the values, the tests turn out as in Helm.
	absent := map[string]interface{}{"image": map[string]interface{}{}}
	tests := `{{- $q := .Values.missing | quote }}{{ if $q }}q-set{{ else }}q-unset{{ end }}
{{- $r := default .Values.missing .Values.image.registry }}{{ if $r }} r-set{{ else }} r-unset{{ end }}
{{- if include "app.quoted" . }} included{{ else }} not-included{{ end }}`
	plainAbsent := renderPlain(t, absent, map[string]string{"_helpers.tpl": templates["_helpers.tpl"], "t.yaml": tests})
	out, err := renderRewritten(t, rewritePlaceholders, absent, map[string]string{"_helpers.tpl": templates["_helpers.tpl"], "t.yaml": tests})
	require.NoError(t, err)
	require.Equal(t, plainAbsent["t.yaml"], out["t.yaml"])
}
