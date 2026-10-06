package helm

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	helmdetector "github.com/DataDog/datadog-iac-scanner/pkg/detector/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const testChartYAML = "apiVersion: v2\nname: app\nversion: 1.0.0\n"

// multiConfigMapTpl defines "multi", which emits two ConfigMap documents.
const multiConfigMapTpl = "{{- define \"multi\" -}}\n{{- range list \"a\" \"b\" }}\n---\n" +
	"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ . }}\n{{- end }}\n{{- end -}}\n"

func renderChartErr(t *testing.T, files map[string]string) ([]model.ResolvedHelm, error) {
	t.Helper()
	root := t.TempDir()
	if _, ok := files["Chart.yaml"]; !ok {
		files["Chart.yaml"] = testChartYAML
	}
	writeTree(t, root, files)
	got, err := (&Resolver{}).Resolve(context.Background(), root)
	return got.File, err
}

// renderChart renders a chart made of files, with a default Chart.yaml.
func renderChart(t *testing.T, files map[string]string) []model.ResolvedHelm {
	t.Helper()
	got, err := renderChartErr(t, files)
	require.NoError(t, err)
	return got
}

// invocationsOf returns the first invocation of each rendered document of
// suffix whose content contains substr.
func invocationsOf(t *testing.T, files []model.ResolvedHelm, suffix, substr string) []model.ResourceLine {
	t.Helper()
	var invocations []model.ResourceLine
	for _, f := range findAllResolvedBySuffix(t, files, suffix) {
		require.NotContains(t, string(f.Content), kicsHelmInvocation)
		if strings.Contains(string(f.Content), substr) {
			invocations = append(invocations, f.HelmInvocations.First())
		}
	}
	return invocations
}

// Every include shape markEveryDocument rewrites still renders, and each
// document it emits carries the invocation.
func TestHelmResolveMarkEveryDocumentShapes(t *testing.T) {
	for _, action := range []string{
		`{{ include "multi" . }}`,
		`{{- include "multi" . }}`,
		`{{ include "multi" . -}}`,
		`{{- include "multi" . -}}`,
		`{{include "multi" .}}`,
		`{{- include "multi" (dict "k" .Values.x "n" (list 1 2)) -}}`,
		"{{ include \"multi\" (dict\n  \"k\" .) }}",
		`{{ include "multi" (dict "sep" "}}\n---\n") }}`,
		`{{ include "multi" . | trim }}`,
		`{{- include "multi" . | nindent 0 -}}`,
	} {
		t.Run(action, func(t *testing.T) {
			got := renderChart(t, map[string]string{
				"templates/_multi.tpl": multiConfigMapTpl,
				"templates/cm.yaml":    action + "\n",
			})
			documents := 0
			for _, f := range findAllResolvedBySuffix(t, got, "templates/cm.yaml") {
				if !strings.Contains(string(f.Content), "kind: ConfigMap") {
					continue
				}
				documents++
				require.Equal(t, 1, f.HelmInvocations.First().Line, "document %q", f.Content)
				require.NotContains(t, string(f.Content), kicsHelmInvocation)
				require.Equal(t, action+"\n", string(f.OriginalData))
			}
			require.Equal(t, 2, documents)
		})
	}
}

// An include name containing "}}" must not corrupt the marker rewrite: the
// chart renders and the executed invocation is attributed.
func TestHelmResolveInvocationWithQuotedActionEnd(t *testing.T) {
	got := renderChart(t, map[string]string{
		"templates/_helpers.tpl": "{{- define \"na}}# me\" -}}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: quoted\n{{- end -}}\n",
		"templates/cm.yaml":      "{{ include \"na}}# me\" . }}\n",
	})
	resolved := findResolvedBySuffix(t, got, "templates/cm.yaml")
	require.Equal(t, model.ResourceLine{Line: 1, Col: 0}, resolved.HelmInvocations.First())
	require.Contains(t, string(resolved.Content), "name: quoted")
}

func TestHelmResolveMarksEveryDocumentOfAnInclude(t *testing.T) {
	got := renderChart(t, map[string]string{
		"templates/_multi.tpl": multiConfigMapTpl,
		"templates/cm.yaml":    "\n{{ include \"multi\" . }}\n",
	})
	require.Equal(t, []model.ResourceLine{{Line: 2}, {Line: 2}}, invocationsOf(t, got, "templates/cm.yaml", "kind: ConfigMap"))
}

func TestHelmResolveMarksEveryDocumentOfAnIncludeInMixedManifest(t *testing.T) {
	got := renderChart(t, map[string]string{
		"templates/_multi.tpl": multiConfigMapTpl,
		"templates/cm.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n" +
			"{{- if true }}\n{{ include \"multi\" . }}\n{{- end }}\n",
	})
	// Line 6 of the source, shifted by the ID line stamped above its apiVersion.
	require.Equal(t, []model.ResourceLine{{Line: 7}, {Line: 7}}, invocationsOf(t, got, "templates/cm.yaml", "kind: ConfigMap"))
}

// Wrapper includes whose output a trim or an adjacent action glues together must
// still render, each document attributed to its own include.
func TestHelmResolveWrapperIncludesGluedByTrims(t *testing.T) {
	for _, wrapper := range []string{
		"{{- include \"a\" . -}}\n{{- include \"b\" . -}}\n",
		"{{ include \"a\" . }}\n{{- if true -}}\n{{ include \"b\" . }}\n{{- end }}\n",
		"{{ include \"a\" . }}{{ include \"b\" . }}\n",
	} {
		t.Run(wrapper, func(t *testing.T) {
			got := renderChart(t, map[string]string{
				"templates/_parts.tpl": "{{- define \"a\" -}}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n{{- end -}}\n" +
					"{{- define \"b\" -}}\n\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: b\n{{- end -}}\n",
				"templates/cm.yaml": wrapper,
			})
			for _, kind := range []string{"ConfigMap", "Secret"} {
				invocations := invocationsOf(t, got, "templates/cm.yaml", "kind: "+kind)
				require.Len(t, invocations, 1, "%s renders", kind)
				require.NotZero(t, invocations[0].Line)
			}
		})
	}
}

// Every separator form YAML accepts carries the invocation into the next
// document, while a separator ending the include's output does not claim the
// manifest's own document after it.
func TestHelmResolveMarksDocumentsAfterAnySeparator(t *testing.T) {
	for name, separator := range map[string]string{
		"plain": "---\n", "trailing space": "--- \n", "comment": "--- # next\n", "crlf": "---\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := renderChart(t, map[string]string{
				"templates/_multi.tpl": "{{- define \"multi\" -}}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n" +
					separator + "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n{{- end -}}\n",
				"templates/cm.yaml": "{{ include \"multi\" . }}\n",
			})
			require.Equal(t, []model.ResourceLine{{Line: 1}, {Line: 1}}, invocationsOf(t, got, "templates/cm.yaml", "kind: ConfigMap"))
		})
	}

	t.Run("trailing separator", func(t *testing.T) {
		got := renderChart(t, map[string]string{
			"templates/_a.tpl": "{{- define \"a\" -}}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\n{{ end -}}\n",
			"templates/m.yaml": "{{ include \"a\" . }}\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n",
		})
		// The Secret is written in m.yaml, not emitted by the include.
		require.Equal(t, []model.ResourceLine{{}}, invocationsOf(t, got, "templates/m.yaml", "kind: Secret"))
	})
}

// A marker is a comment line, which ends a plain multi-line value an include
// continues. The chart must still render, as it did before markers existed.
func TestHelmResolveIncludeContinuingPlainScalar(t *testing.T) {
	for name, include := range map[string]string{
		"column 0": "{{ include \"more\" . | indent 4 }}\n",
		"indented": "  {{ include \"more\" . | indent 4 }}\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := renderChart(t, map[string]string{
				"templates/_h.tpl":  "{{- define \"more\" -}}\nworld\n{{- end -}}\n",
				"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  msg: hello\n" + include,
			})
			cm := findResolvedBySuffix(t, got, "templates/cm.yaml")
			require.Contains(t, string(cm.Content), "msg: hello\n")
			require.Contains(t, string(cm.Content), "world")
			require.NotContains(t, string(cm.Content), kicsHelmInvocation)
		})
	}
}

// The render without markers is a retry, not a way to hide a chart that is
// broken for real.
func TestHelmResolveBrokenYAMLStillFails(t *testing.T) {
	_, err := renderChartErr(t, map[string]string{
		"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: [unclosed\n",
	})
	require.ErrorContains(t, err, "YAML parse error")
	require.ErrorContains(t, err, "templates/cm.yaml")
}

// A rewritten include must not add lines to the rendered output, which would
// shift the line of everything rendered after it.
func TestHelmResolveRewrittenIncludeKeepsRenderedLines(t *testing.T) {
	got := renderChart(t, map[string]string{
		"templates/_helpers.tpl": "{{- define \"labels\" -}}\napp: x\ntier: y\n{{- end -}}\n",
		"templates/role.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  labels:\n" +
			"{{ include \"labels\" . | indent 4 }}\ndata:\n  a: b\n",
	})
	cm := findResolvedBySuffix(t, got, "templates/role.yaml")
	require.Contains(t, string(cm.Content), "  labels:\n    app: x\n    tier: y\ndata:\n")
	require.NotContains(t, string(cm.Content), kicsHelmInvocation)
}

func TestHelmResolveTracksExecutedConditionalInvocation(t *testing.T) {
	got, err := (&Resolver{}).Resolve(
		context.Background(), helmFixturePath(t, "test_helm_conditional_invocations"),
	)
	require.NoError(t, err)

	resolved := findResolvedBySuffix(t, got.File, "templates/resources.yaml")
	require.Contains(t, string(resolved.Content), "resource-b")
	require.NotContains(t, string(resolved.Content), "resource-a")
	require.Equal(t, model.ResourceLine{Line: 5, Col: 0}, resolved.HelmInvocations.First())
	require.NotContains(t, string(resolved.Content), kicsHelmInvocation)
	require.NotContains(t, string(resolved.OriginalData), kicsHelmInvocation)
}

// A manifest that mixes logic with an include which emits the whole resource,
// as Bitnami's contour does: the resource is defined in a partial, so only the
// invocation can tell where it came from.
func TestHelmResolve_IncludeInMixedManifestKeepsInvocation(t *testing.T) {
	got := renderChart(t, map[string]string{
		"values.yaml": "enabled: true\n",
		"templates/_svc.tpl": "{{- define \"app.svc\" -}}\napiVersion: v1\nkind: Service\nmetadata:\n" +
			"  name: svc\n  annotations:\n    a: b\n{{- end -}}\n",
		"templates/svc.yaml": "{{- $unused := \"x\" }}\n{{- if .Values.enabled }}\n" +
			"{{ include \"app.svc\" . }}\n{{- end }}\n",
	})
	svc := findResolvedBySuffix(t, got, "templates/svc.yaml")
	require.Equal(t, model.ResourceLine{Line: 3, Col: 0}, svc.HelmInvocations.First())
	require.Contains(t, string(svc.Content), "name: svc")
	require.NotContains(t, string(svc.Content), kicsHelmInvocation)
}

// A document whose parts are emitted by different includes: a finding is
// attributed to the include that emitted its key, not to the first one.
func TestHelmResolve_DocumentComposedOfSeveralIncludes(t *testing.T) {
	got := renderChart(t, map[string]string{
		"templates/_parts.tpl": "{{- define \"header\" -}}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n{{- end -}}\n" +
			"{{- define \"spec\" -}}\nspec:\n  containers:\n  - name: c\n    image: nginx\n{{- end -}}\n",
		"templates/pod.yaml": "{{ include \"header\" . }}\n{{ include \"spec\" . }}\n",
	})
	pod := findResolvedBySuffix(t, got, "templates/pod.yaml")
	// Rendered lines of the stamped content: the header starts at the ID line (3), the spec at line 9.
	require.Equal(t, model.HelmInvocations{
		{RenderedLine: 3, Position: model.ResourceLine{Line: 1}},
		{RenderedLine: 9, Position: model.ResourceLine{Line: 2}},
	}, pod.HelmInvocations)
	require.NotContains(t, string(pod.Content), kicsHelmInvocation)

	file := &model.FileMetadata{
		Kind:                model.KindHELM,
		FilePath:            pod.FileName,
		HelmID:              pod.SplitID,
		OriginalData:        string(pod.OriginalData),
		LinesOriginalData:   utils.SplitLines(string(pod.OriginalData)),
		IDInfo:              pod.IDInfo,
		HelmInvocations:     pod.HelmInvocations,
		HelmRenderedContent: string(pod.Content),
	}
	detect := func(searchKey string) int {
		return (helmdetector.DetectKindLine{}).DetectLine(context.Background(), file, searchKey, 1).Line
	}
	require.Equal(t, 2, detect("spec.containers.name={{c}}.image"))
	require.Equal(t, 1, detect("metadata.name"))
}

// The datadog chart's idiom of a standalone include following a "-}}" action,
// which trims the newline a marker would sit after: the chart must render with
// its keys intact and no marker text in the output.
func TestHelmResolve_IncludeAfterRightTrimmedAction(t *testing.T) {
	got := renderChart(t, map[string]string{
		"values.yaml": "extra: true\n",
		"templates/_helpers.tpl": "{{- define \"base\" -}}\napp: glue\n{{- end -}}\n" +
			"{{- define \"extra\" -}}\ntier: web\n{{- end -}}\n",
		"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: glue\n  labels:\n" +
			"    {{- include \"base\" . | nindent 4 -}}\n{{ include \"extra\" . | nindent 4 }}\n" +
			"data:\n{{- if .Values.extra -}}\n{{ include \"extra\" . | nindent 2 }}\n{{- end }}\n",
	})
	cm := findResolvedBySuffix(t, got, "templates/cm.yaml")
	require.NotContains(t, string(cm.Content), kicsHelmInvocation)

	var doc struct {
		Metadata struct {
			Labels map[string]string `yaml:"labels"`
		} `yaml:"metadata"`
		Data map[string]string `yaml:"data"`
	}
	require.NoError(t, yaml.Unmarshal(cm.Content, &doc))
	require.Equal(t, map[string]string{"app": "glue", "tier": "web"}, doc.Metadata.Labels)
	require.Equal(t, map[string]string{"tier": "web"}, doc.Data)
}

// A chart rendered again without markers still gets its IDs and original
// sources; only the invocation lines are given up, for every template of it.
func TestHelmResolveRetryWithoutMarkersKeepsIDsAndSources(t *testing.T) {
	secret := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
	got := renderChart(t, map[string]string{
		"templates/_h.tpl":  "{{- define \"more\" -}}\nworld\n{{- end -}}\n",
		"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  msg: hello\n{{ include \"more\" . | indent 4 }}\n",
		"templates/s.yaml":  "{{ include \"sec\" . }}\n",
		"templates/_s.tpl":  "{{- define \"sec\" -}}\n" + secret + "{{- end -}}\n",
	})
	for suffix, source := range map[string]string{
		"templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  msg: hello\n{{ include \"more\" . | indent 4 }}\n",
		"templates/s.yaml":  "{{ include \"sec\" . }}\n",
	} {
		f := findResolvedBySuffix(t, got, suffix)
		require.Contains(t, string(f.OriginalData), source)
		require.NotContains(t, string(f.Content), kicsHelmInvocation)
		require.NotContains(t, string(f.OriginalData), kicsHelmInvocation)
		require.NotEmpty(t, f.IDInfo, suffix)
		require.Empty(t, f.HelmInvocations, "the retry gives up invocation lines for the whole chart")
	}
	require.Contains(t, string(findResolvedBySuffix(t, got, "templates/s.yaml").Content), "kind: Secret")
}

type panicOnReadDirFS struct{ vfs.FS }

func (panicOnReadDirFS) ReadDir(string) ([]fs.DirEntry, error) { panic("boom") }

// A panic while rendering is returned as an error, never swallowed as an empty
// successful result.
func TestResolveReturnsPanicAsError(t *testing.T) {
	memfs := vfs.NewMemFS(map[string][]byte{
		"chart/Chart.yaml":        []byte(testChartYAML),
		"chart/templates/cm.yaml": []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"),
	})
	got, err := NewResolver(panicOnReadDirFS{memfs}).Resolve(context.Background(), "chart")
	require.ErrorContains(t, err, "panic during resolve of chart: boom")
	require.Empty(t, got.File)
}
