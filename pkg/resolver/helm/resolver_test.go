package helm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	helmdetector "github.com/DataDog/datadog-iac-scanner/pkg/detector/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/release"
)

func helmFixturePath(t *testing.T, parts ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	require.True(t, ok)
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	require.NoError(t, err)
	return filepath.Join(append([]string{root, "test", "fixtures"}, parts...)...)
}

func pathSuffix(t *testing.T, path string) string {
	t.Helper()
	normalized := filepath.ToSlash(path)
	if idx := strings.Index(normalized, "test/fixtures/"); idx >= 0 {
		parts := strings.Split(strings.TrimPrefix(normalized[idx+len("test/fixtures/"):], "/"), "/")
		if len(parts) > 1 {
			return strings.Join(parts[1:], "/")
		}
	}
	if idx := strings.Index(normalized, "test_helm_subchart/"); idx >= 0 {
		return normalized[idx:]
	}
	return filepath.Base(normalized)
}

func findResolvedBySuffix(t *testing.T, files []model.ResolvedHelm, suffix string) model.ResolvedHelm {
	t.Helper()
	suffix = filepath.ToSlash(suffix)
	var matches []model.ResolvedHelm
	for _, f := range files {
		if strings.HasSuffix(filepath.ToSlash(f.FileName), suffix) {
			matches = append(matches, f)
		}
	}
	require.Len(t, matches, 1, "expected exactly one resolved file ending with %q", suffix)
	return matches[0]
}

func findAllResolvedBySuffix(t *testing.T, files []model.ResolvedHelm, suffix string) []model.ResolvedHelm {
	t.Helper()
	suffix = filepath.ToSlash(suffix)
	var matches []model.ResolvedHelm
	for _, f := range files {
		if strings.HasSuffix(filepath.ToSlash(f.FileName), suffix) {
			matches = append(matches, f)
		}
	}
	return matches
}

// A file:// dependency that was never vendored under charts/ is loaded from its
// path, as `helm dependency build` would, so the parent's includes resolve.
func TestHelm_Resolve_UnvendoredFileDependency(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("common/Chart.yaml", "apiVersion: v2\nname: common\nversion: 1.0.0\ntype: library\n")
	write("common/templates/_labels.tpl", "{{- define \"common.labels\" -}}\napp: {{ .Chart.Name }}\n{{- end -}}\n")
	write("app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n"+
		"dependencies:\n- name: common\n  version: 1.0.0\n  repository: file://../common\n")
	write("app/templates/cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  labels:\n"+
		"    {{- include \"common.labels\" . | nindent 4 }}\n")

	got, err := (&Resolver{}).Resolve(context.Background(), filepath.Join(root, "app"))
	require.NoError(t, err)
	cm := findResolvedBySuffix(t, got.File, "templates/cm.yaml")
	require.Contains(t, string(cm.Content), "app: app")
}

// A dependency without a local repository, provided by the build system rather
// than vendored, resolves from the only chart in the scan with its name and a
// compatible version.
func TestHelm_Resolve_DependencyFromScannedCharts(t *testing.T) {
	const helper = "{{- define \"common.labels\" -}}\napp: {{ .Chart.Name }}\n{{- end -}}\n"
	const app = "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: common\n  version: %s\n"
	const cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  labels:\n" +
		"    {{- include \"common.labels\" . | nindent 4 }}\n"
	tests := []struct {
		name       string
		libraries  map[string]string // dir -> version
		constraint string
		wantRender bool
	}{
		{"unique match", map[string]string{"libs/common": "1.2.0"}, "^1.0.0", true},
		{"no version constraint", map[string]string{"libs/common": "3.0.0"}, `""`, true},
		{"only an incompatible version", map[string]string{"libs/common": "2.0.0"}, "^1.0.0", true},
		{"ambiguous", map[string]string{"a/common": "1.0.0", "b/common": "1.1.0"}, "^1.0.0", false},
		{"ambiguity settled by version", map[string]string{"a/common": "1.0.0", "b/common": "2.0.0"}, "^1.0.0", true},
		{"ambiguity settled by nearest chart", map[string]string{"dom/common": "1.0.0", "other/common": "1.0.0"}, "^1.0.0", true},
		{"incompatible versions tied", map[string]string{"a/common": "2.0.0", "b/common": "2.1.0"}, "^1.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			write := func(rel, body string) {
				p := filepath.Join(root, filepath.FromSlash(rel))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
			}
			roots := []string{filepath.ToSlash(filepath.Join(root, "dom/app"))}
			for dir, version := range tt.libraries {
				write(dir+"/Chart.yaml", "apiVersion: v2\nname: common\ntype: library\nversion: "+version+"\n")
				write(dir+"/templates/_labels.tpl", helper)
				roots = append(roots, filepath.ToSlash(filepath.Join(root, dir)))
			}
			write("dom/app/Chart.yaml", fmt.Sprintf(app, tt.constraint))
			write("dom/app/templates/cm.yaml", cm)

			got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "dom/app"))
			if !tt.wantRender {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Contains(t, string(findResolvedBySuffix(t, got.File, "templates/cm.yaml").Content), "app: app")
		})
	}
}

func TestHelm_Resolve_WithCRDs(t *testing.T) {
	res := &Resolver{}
	ctx := context.Background()
	chartPath := helmFixturePath(t, "test_helm_with_crds")

	got, err := res.Resolve(ctx, chartPath)
	require.NoError(t, err)
	require.NotEmpty(t, got.Excluded, "excluded list should be non-empty after render")

	type crdExpect struct {
		suffix      string
		kind        string
		name        string
		fullLineMap bool // true for YAML CRDs, false for JSON (helmID=-1)
	}
	wantCRDs := []crdExpect{
		{suffix: "crds/widget.yaml", kind: "CustomResourceDefinition", name: "widgets.example.com", fullLineMap: true},
		{suffix: "crds/gadget.json", kind: "CustomResourceDefinition", name: "gadgets.example.com", fullLineMap: false},
		{suffix: "crds/nested/device.yaml", kind: "CustomResourceDefinition", name: "devices.example.com", fullLineMap: true},
		{suffix: "crds/nested/crds/repeated.yaml", kind: "CustomResourceDefinition", name: "repeated.example.com", fullLineMap: true},
	}

	for _, want := range wantCRDs {
		f := findResolvedBySuffix(t, got.File, want.suffix)

		require.Contains(t, string(f.Content), want.kind)
		require.Contains(t, string(f.Content), want.name)

		if want.fullLineMap {
			require.Equal(t, "# KICS_HELM_ID_0:", f.SplitID, "YAML CRD SplitID must anchor line mapping")
			require.Contains(t, string(f.OriginalData), kicsHelmID, "stamped original required for detector")
			require.Contains(t, string(f.OriginalData), want.kind)
			require.Contains(t, string(f.OriginalData), want.name)
			idInfo, ok := f.IDInfo[0].(model.HelmIDLineRange)
			require.True(t, ok, "IDInfo must map helm id 0 to source lines for YAML CRDs")
			require.GreaterOrEqual(t, idInfo.End, idInfo.Start, "IDInfo line range must not be empty for YAML CRDs")
		} else {
			require.Empty(t, f.SplitID, "JSON CRD has no inline stamp; SplitID must be empty")
		}
	}
}

func Test_looksLikeManifest(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "real manifest",
			input: "\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n",
			want:  true,
		},
		{
			name:  "real manifest with leading blank lines and comments",
			input: "\n\n# comment\napiVersion: v1\nkind: ConfigMap\n",
			want:  true,
		},
		{
			name:  "indented manifest",
			input: "\n  apiVersion: v1\n  kind: ConfigMap\n",
			want:  true,
		},
		{
			name:  "empty split",
			input: "   \n  \n",
			want:  false,
		},
		{
			name:  "kind before apiVersion",
			input: "\nkind: CustomResourceDefinition\napiVersion: apiextensions.k8s.io/v1\n",
			want:  true,
		},
		{
			name:  "source header after CRLF",
			input: "\r\n# Source: test_helm_with_crds/crds/widget.yaml\r\napiVersion: apiextensions.k8s.io/v1\n",
			want:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, looksLikeManifest(tc.input))
		})
	}
}

func TestHelm_Resolve_MultiDocCRD(t *testing.T) {
	res := &Resolver{}
	ctx := context.Background()

	got, err := res.Resolve(ctx, helmFixturePath(t, "test_helm_with_crds"))
	require.NoError(t, err)

	splits := findAllResolvedBySuffix(t, got.File, "crds/multi.yaml")
	require.Len(t, splits, 2, "multi-document CRD file must produce one split per document")

	// Both splits must have distinct, non-empty SplitIDs anchored to their document.
	require.Equal(t, "# KICS_HELM_ID_0:", splits[0].SplitID, "first document must use first marker")
	require.NotEmpty(t, splits[1].SplitID, "second document must have a non-empty SplitID")
	require.NotEqual(t, splits[0].SplitID, splits[1].SplitID, "each document must map to a distinct marker")

	// Both SplitIDs must exist in the shared stamped original.
	original := string(splits[0].OriginalData)
	require.Contains(t, original, splits[0].SplitID, "first SplitID must be present in stamped original")
	require.Contains(t, original, splits[1].SplitID, "second SplitID must be present in stamped original")

	// Content of each split must contain the right resource.
	require.Contains(t, string(splits[0].Content), "alphas.example.com")
	require.Contains(t, string(splits[1].Content), "betas.example.com")
}

func TestSplitHelmManifest_onlySplitsDocumentBoundaries(t *testing.T) {
	manifest := `---
# Source: chart/crds/gadget.json
{"description":"literal --- separator"}
---
# Source: chart/crds/widget.yaml
description: |
  literal --- separator
apiVersion: v1
kind: ConfigMap
`

	splits := splitHelmManifest(manifest)
	require.Len(t, splits, 2)
	require.Contains(t, splits[0], `"literal --- separator"`)
	require.Contains(t, splits[1], "literal --- separator")
}

func TestSplitHelmManifestPropagatesInvocationAcrossDocuments(t *testing.T) {
	manifest := `---
# Source: chart/templates/resources.yaml
# KICS_HELM_INVOCATION_5_0:
apiVersion: v1
kind: ConfigMap
metadata:
  name: first
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: second
`

	splits := splitHelmManifest(manifest)
	require.Len(t, splits, 2)
	for _, split := range splits {
		require.Contains(t, split, "# KICS_HELM_INVOCATION_5_0:")
	}
}

func Test_parseManifestSource(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantSource string
		wantOK     bool
	}{
		{
			name:       "unix header",
			input:      "\n# Source: test_helm/templates/service.yaml\napiVersion: v1\n",
			wantSource: "test_helm/templates/service.yaml",
			wantOK:     true,
		},
		{
			name:       "crlf header",
			input:      "\r\n# Source: test_helm_with_crds/crds/widget.yaml\r\napiVersion: apiextensions.k8s.io/v1\n",
			wantSource: "test_helm_with_crds/crds/widget.yaml",
			wantOK:     true,
		},
		{
			name:   "missing header",
			input:  "\napiVersion: v1\nkind: ConfigMap\n",
			wantOK: false,
		},
		{
			name:   "user source comment after manifest start",
			input:  "\napiVersion: v1\n# Source: user-authored\nkind: ConfigMap\n",
			wantOK: false,
		},
		{
			name:   "indented user source comment",
			input:  "\n  # Source: user-authored\napiVersion: v1\n",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, ok := parseManifestSource(tc.input)
			require.Equal(t, tc.wantOK, ok)
			if ok {
				require.Equal(t, tc.wantSource, source)
			}
		})
	}
}

func TestIsCRDManifest(t *testing.T) {
	require.True(t, isCRDManifest("crds/widget.yaml"))
	require.True(t, isCRDManifest(`crds\nested\widget.yaml`))
	require.False(t, isCRDManifest("examples/crds/widget.yaml"))
	require.False(t, isCRDManifest("templates/service.yaml"))
}

func TestCrdChartRelativePath(t *testing.T) {
	require.Equal(t, "crds/widget.yaml", crdChartRelativePath(`D:/a/repo/crds/widget.yaml`))
	require.Equal(t, "crds/widget.yaml", crdChartRelativePath(`charts/subchart/crds/widget.yaml`))
	require.Equal(t, "crds/zsub/crds/widget.yaml", crdChartRelativePath(`crds/zsub/crds/widget.yaml`))
}

func TestChartRelativeFromSource(t *testing.T) {
	rel, ok := chartRelativeFromSource("test_helm_with_crds/crds/widget.yaml")
	require.True(t, ok)
	require.Equal(t, "crds/widget.yaml", rel)

	rel, ok = chartRelativeFromSource(chartSourceKey(`test_helm_with_crds\crds\widget.yaml`))
	require.True(t, ok)
	require.Equal(t, "crds/widget.yaml", rel)

	rel, ok = chartRelativeFromSource("test_helm_subchart/charts/subchart/crds/widget.yaml")
	require.True(t, ok)
	require.Equal(t, "charts/subchart/crds/widget.yaml", rel)
}

func TestIsCRDSourcePath(t *testing.T) {
	tests := map[string]bool{
		"chart/crds/widget.yaml":                               true,
		`chart\crds\nested\widget.yaml`:                        true,
		"chart/charts/subchart/crds/widget.yaml":               true,
		"chart/charts/subchart/charts/nested/crds/widget.yaml": true,
		"crds/crds/widget.yaml":                                true,
		"crds/templates/widget.yaml":                           false,
		"chart/templates/widget.yaml":                          false,
		"chart/templates/crds/widget.yaml":                     false,
		"chart/files/crds/widget.yaml":                         false,
	}
	for path, expected := range tests {
		t.Run(path, func(t *testing.T) {
			require.Equal(t, expected, isCRDSourcePath(path))
		})
	}
}

func TestSplitManifestYAML_windowsCRDSourcePath(t *testing.T) {
	ch, err := loader.Load(helmFixturePath(t, "test_helm_with_crds"))
	require.NoError(t, err)
	setID(ch)

	manifest := strings.Join([]string{
		"---",
		"# Source: test_helm_with_crds\\crds\\widget.yaml",
		"apiVersion: apiextensions.k8s.io/v1",
		"kind: CustomResourceDefinition",
		"metadata:",
		"  name: widgets.example.com",
	}, "\n")

	splits, err := splitManifestYAML(&release.Release{Manifest: manifest}, ch, nil)
	require.NoError(t, err)
	require.Len(t, *splits, 1)
	require.Equal(t, "test_helm_with_crds/crds/widget.yaml", (*splits)[0].path)
	require.True(t, (*splits)[0].isCRD)
}

func TestSplitManifestYAML_dropsUnknownSourceHeader(t *testing.T) {
	ch, err := loader.Load(helmFixturePath(t, "test_helm_with_crds"))
	require.NoError(t, err)
	setID(ch)

	manifest := strings.Join([]string{
		"---",
		"# Source: test_helm_with_crds/crds/widget.yaml",
		"apiVersion: apiextensions.k8s.io/v1",
		"kind: CustomResourceDefinition",
		"---",
		"# Source: user-authored",
		"apiVersion: apiextensions.k8s.io/v1",
		"kind: CustomResourceDefinition",
		"---",
		"apiVersion: apiextensions.k8s.io/v1",
		"kind: CustomResourceDefinition",
	}, "\n")

	splits, err := splitManifestYAML(&release.Release{Manifest: manifest}, ch, nil)
	require.NoError(t, err)
	require.Len(t, *splits, 1)
	require.Equal(t, "test_helm_with_crds/crds/widget.yaml", (*splits)[0].path)
}

func TestSplitManifestYAML_emptyCRDDocumentDoesNotShiftSourceIndex(t *testing.T) {
	crd := &chart.File{
		Name: "crds/leading-empty.yaml",
		Data: []byte(strings.Join([]string{
			"# comment-only document",
			"---",
			"apiVersion: apiextensions.k8s.io/v1",
			"kind: CustomResourceDefinition",
			"metadata:",
			"  name: widgets.example.com",
		}, "\n")),
	}
	ch := &chart.Chart{
		Metadata: &chart.Metadata{Name: "test"},
		Files:    []*chart.File{crd},
	}
	setID(ch)

	manifest := strings.Join([]string{
		"---",
		"# Source: test/crds/leading-empty.yaml",
		string(crd.Data),
	}, "\n")
	splits, err := splitManifestYAML(&release.Release{Manifest: manifest}, ch, nil)
	require.NoError(t, err)
	require.NotEmpty(t, *splits)

	var resourceSplit *splitManifest
	for i := range *splits {
		if (*splits)[i].splitID != "" {
			resourceSplit = &(*splits)[i]
			break
		}
	}
	require.NotNil(t, resourceSplit)
	require.Zero(t, resourceSplit.sourceDocumentIndex)
}

func TestLocalCRDFiles_fromLoadedFixture(t *testing.T) {
	ch, err := loader.Load(helmFixturePath(t, "test_helm_with_crds"))
	require.NoError(t, err)
	require.Len(t, localCRDFiles(ch), 5)
}

func TestLocalCRDFiles_keepsDependencyCRDsOnDependency(t *testing.T) {
	ch, err := loader.Load(helmFixturePath(t, "test_helm_subchart"))
	require.NoError(t, err)
	require.Empty(t, localCRDFiles(ch))
	require.Len(t, ch.Dependencies(), 1)
	require.Len(t, localCRDFiles(ch.Dependencies()[0]), 1)
}

func TestLocalCRDFiles_windowsSeparators(t *testing.T) {
	ch := &chart.Chart{
		Metadata: &chart.Metadata{Name: "test"},
		Files: []*chart.File{
			{Name: `crds\widget.yaml`, Data: []byte("apiVersion: v1\n")},
		},
	}
	require.Len(t, localCRDFiles(ch), 1)
}

func TestLocalCRDFiles_keepsDistinctNestedCRDPaths(t *testing.T) {
	ch := &chart.Chart{
		Metadata: &chart.Metadata{Name: "test"},
		Files: []*chart.File{
			{Name: "crds/widget.yaml", Data: []byte("apiVersion: v1\n")},
			{Name: "crds/nested/crds/widget.yaml", Data: []byte("apiVersion: v1\n")},
		},
	}

	files := localCRDFiles(ch)
	require.Len(t, files, 2)
	require.Equal(t, "crds/widget.yaml", crdChartRelativePath(files[0].Name))
	require.Equal(t, "crds/nested/crds/widget.yaml", crdChartRelativePath(files[1].Name))
}

func TestAddID_multiDocumentUsesSourceLineIDs(t *testing.T) {
	original := strings.Join([]string{
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: nested-one",
		"spec:",
		"  ports:",
		"  - name: nested-one",
		"---",
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: nested-two",
		"spec:",
		"  ports:",
		"  - name: nested-two",
	}, "\n")
	file := addID(&chart.File{Name: "templates/nested.yaml", Data: []byte(original)})

	require.Contains(t, string(file.Data), "# KICS_HELM_ID_0:\napiVersion: v1")
	require.Contains(t, string(file.Data), "# KICS_HELM_ID_8:\napiVersion: v1")
}

func TestAddHelmInvocationMarkersInspectsEveryAction(t *testing.T) {
	file := &chart.File{Data: []byte(`{{- if .Values.enabled }}{{ include "resource" . }}{{- end }}`)}
	addHelmInvocationMarkers(file)

	positions := map[string]bool{}
	for _, m := range regexp.MustCompile(`KICS_HELM_INVOCATION_\d+_\d+`).FindAllString(string(file.Data), -1) {
		positions[m] = true
	}
	require.Equal(t, map[string]bool{"KICS_HELM_INVOCATION_1_25": true}, positions)
}

func TestAddHelmInvocationMarkersRestoresOriginalSource(t *testing.T) {
	for _, source := range []string{
		`{{ include "resource" . }}`,
		`{{- include "resource" (dict "a" .) -}}`,
		"{{ include \"a\" . }}\n---\n{{ template \"b\" . }}\n{{ include \"c\" . | nindent 0 }}",
		// A quoted "}}" defeats the lazy action regex, so the marker rewrite
		// falls back to a prefix marker; stripping must still restore this
		// source exactly.
		`{{ include "na}}me" . }}`,
	} {
		file := addHelmInvocationMarkers(&chart.File{Data: []byte(source)})
		require.NotEqual(t, source, string(file.Data))
		require.Equal(t, source, string(stripHelmInvocationActions(file.Data)))
	}
}

// TestAddHelmInvocationMarkersQuotedActionEnd covers an include whose quoted
// template name contains "}}": the lazy templateActionRE stops inside the
// quoted argument, so rewriting the action with markEveryDocument would feed
// Helm a corrupted template and fail the whole chart render. Such actions must
// fall back to the self-contained prefix marker, which the lazy regex strips
// whole, and never receive the markEveryDocument rewrite.
func TestAddHelmInvocationMarkersQuotedActionEnd(t *testing.T) {
	// The residue left by the quoted "}}" ("# me\" . }}") starts with a comment
	// marker, so the old lazy-regex wrapper check classified this template as
	// an action-only wrapper and the truncated span corrupted the rewrite.
	source := `{{ include "na}}# me" . }}`
	file := addHelmInvocationMarkers(&chart.File{Data: []byte(source)})
	marked := string(file.Data)

	// The rewrite is skipped: no "replace" pipeline, and the original action
	// is preserved verbatim after the inserted prefix marker.
	require.NotContains(t, marked, "| replace")
	require.Contains(t, marked, `# KICS_HELM_INVOCATION_1_0:`)
	require.Contains(t, marked, source)

	// The action is still parseable Go template text and round-trips through
	// the lazy stripper.
	require.Equal(t, source, string(stripHelmInvocationActions(file.Data)))
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
	// outcome, and the invocation marker still round-trips to the source.
	source = "{{- /* chart's helper, not emitted when disabled */ -}}\n{{ include \"mychart.labels\" . }}\n"
	require.True(t, isHelmInvocationWrapper(source))
	file := addHelmInvocationMarkers(&chart.File{Data: []byte(source)})
	require.Contains(t, string(file.Data), "KICS_HELM_INVOCATION_2_")
	require.Equal(t, source, string(stripHelmInvocationActions(file.Data)))
}

// TestHelmResolveInvocationWithQuotedActionEnd renders a chart whose include
// name contains "}}" end to end: the marker rewrite must not corrupt the
// template, so the chart renders and the executed invocation is attributed.
func TestHelmResolveInvocationWithQuotedActionEnd(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n")
	write("templates/_helpers.tpl",
		"{{- define \"na}}# me\" -}}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: quoted\n{{- end -}}\n")
	write("templates/cm.yaml", "{{ include \"na}}# me\" . }}\n")

	got, err := (&Resolver{}).Resolve(context.Background(), root)
	require.NoError(t, err)

	resolved := findResolvedBySuffix(t, got.File, "templates/cm.yaml")
	require.Equal(t, model.ResourceLine{Line: 1, Col: 0}, resolved.HelmInvocation)
	require.Contains(t, string(resolved.Content), "name: quoted")
}

func TestHelmResolveMarksEveryDocumentOfAnInclude(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n")
	write("templates/_multi.tpl", "{{- define \"multi\" -}}\n{{- range list \"a\" \"b\" }}\n---\n"+
		"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ . }}\n{{- end }}\n{{- end -}}\n")
	write("templates/cm.yaml", "\n{{ include \"multi\" . }}\n")

	got, err := (&Resolver{}).Resolve(context.Background(), root)
	require.NoError(t, err)
	var invocations []model.ResourceLine
	for _, f := range got.File {
		if strings.HasSuffix(f.FileName, "cm.yaml") && strings.Contains(string(f.Content), "kind: ConfigMap") {
			invocations = append(invocations, f.HelmInvocation)
			require.NotContains(t, string(f.Content), kicsHelmInvocation)
		}
	}
	require.Equal(t, []model.ResourceLine{{Line: 2, Col: 0}, {Line: 2, Col: 0}}, invocations)
}

func TestHelmResolveTracksExecutedConditionalInvocation(t *testing.T) {
	got, err := (&Resolver{}).Resolve(
		context.Background(), helmFixturePath(t, "test_helm_conditional_invocations"),
	)
	require.NoError(t, err)

	resolved := findResolvedBySuffix(t, got.File, "templates/resources.yaml")
	require.Contains(t, string(resolved.Content), "resource-b")
	require.NotContains(t, string(resolved.Content), "resource-a")
	require.Equal(t, model.ResourceLine{Line: 5, Col: 0}, resolved.HelmInvocation)
	require.NotContains(t, string(resolved.Content), kicsHelmInvocation)
	require.NotContains(t, string(resolved.OriginalData), kicsHelmInvocation)
}

func TestDetectLine_MultiDocumentTemplateUsesSourceLines(t *testing.T) {
	original := strings.Join([]string{
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: nested-one",
		"spec:",
		"  ports:",
		"  - name: nested-one",
		"---",
		"apiVersion: v1",
		"kind: Service",
		"metadata:",
		"  name: nested-two",
		"spec:",
		"  ports:",
		"  - name: nested-two",
	}, "\n")
	file := addID(&chart.File{Name: "templates/nested.yaml", Data: []byte(original)})
	idMap, err := getIDMap(file.Data)
	require.NoError(t, err)

	got := (helmdetector.DetectKindLine{}).DetectLine(context.Background(), &model.FileMetadata{
		Kind:              model.KindHELM,
		FilePath:          "templates/nested.yaml",
		HelmID:            "# KICS_HELM_ID_8:",
		OriginalData:      string(file.Data),
		LinesOriginalData: utils.SplitLines(string(file.Data)),
		IDInfo:            idMap,
	}, "KICS_HELM_ID_8.spec", 1)

	require.Equal(t, 13, got.Line)
	require.Equal(t, 13, got.VulnerablilityLocation.Start.Line)
	require.Equal(t, 13, got.VulnerablilityLocation.End.Line)

	got = (helmdetector.DetectKindLine{}).DetectLine(context.Background(), &model.FileMetadata{
		Kind:              model.KindHELM,
		FilePath:          "templates/nested.yaml",
		HelmID:            "# KICS_HELM_ID_8:",
		OriginalData:      string(file.Data),
		LinesOriginalData: utils.SplitLines(string(file.Data)),
		IDInfo:            idMap,
	}, "KICS_HELM_ID_8.spec.ports", 1)

	require.Equal(t, 14, got.Line)
	require.Equal(t, 14, got.VulnerablilityLocation.Start.Line)
	require.Equal(t, 14, got.VulnerablilityLocation.End.Line)
}

func TestAddID_ignoresIndentedAPIVersion(t *testing.T) {
	original := `description: |
  apiVersion: v1
  ---
  apiVersion: v2
  kind: Pod
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
`
	file := &chart.File{Data: []byte(original)}
	addID(file)

	require.Equal(t, 1, strings.Count(string(file.Data), kicsHelmID))
	require.Contains(t, string(file.Data), "  apiVersion: v1")
	require.Contains(t, string(file.Data), kicsHelmID)
}

func TestAddID_stampsIndentedRootAPIVersion(t *testing.T) {
	file := &chart.File{Data: []byte("  apiVersion: v1\n  kind: ConfigMap\n")}
	addID(file)

	require.Equal(t, 1, strings.Count(string(file.Data), kicsHelmID))
	require.Contains(t, string(file.Data), "# KICS_HELM_ID_0:\n  apiVersion: v1")
}

func TestAddID_stampsValidAPIVersionKeyStyles(t *testing.T) {
	file := &chart.File{Data: []byte(`"apiVersion": v1
kind: ConfigMap
---
'apiVersion' : v1
kind: Secret
---
{apiVersion: v1, kind: Service}
---
? apiVersion
: v1
kind: Pod
---
{
  apiVersion: v1,
  kind: ConfigMap
}
---
!tag apiVersion: v1
kind: Secret
---
&key apiVersion: v1
kind: Service
---
"api\u0056ersion": v1
kind: Pod
`)}
	file.Name = "crds/keys.yaml"
	addID(file)

	require.Equal(t, 8, strings.Count(string(file.Data), kicsHelmID))
}

func TestHelm_SupportedTypes(t *testing.T) {
	res := &Resolver{}
	want := []model.FileKind{model.KindHELM}
	t.Run("get_supported_type", func(t *testing.T) {
		got := res.SupportedTypes()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("SupportedTypes() = %v, want = %v", got, want)
		}
	})
}

func TestHelm_Resolve(t *testing.T) { //nolint
	res := &Resolver{}
	type args struct {
		filePath string
	}
	tests := []struct {
		name            string
		args            args
		fixture         string
		compareBySuffix bool
		want            model.ResolvedFiles
		wantErr         bool
	}{
		{
			name: "test_resolve_helm",
			args: args{
				filePath: filepath.FromSlash("../../../test/fixtures/test_helm"),
			},
			want: model.ResolvedFiles{
				File: []model.ResolvedHelm{
					{
						SplitID:  "# KICS_HELM_ID_0:",
						FileName: filepath.FromSlash("../../../test/fixtures/test_helm/templates/service.yaml"),
						IDInfo:   map[int]interface{}{0: model.HelmIDLineRange{Start: 0, End: 16}},
						Content: []byte(`
# Source: test_helm/templates/service.yaml
# KICS_HELM_ID_0:
apiVersion: v1
kind: Service
metadata:
  name: dd-helm-test_helm
  labels:
    helm.sh/chart: test_helm-0.1.0
    app.kubernetes.io/name: test_helm
    app.kubernetes.io/instance: dd-helm
    app.kubernetes.io/version: "1.16.0"
    app.kubernetes.io/managed-by: Helm
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app.kubernetes.io/name: test_helm
    app.kubernetes.io/instance: dd-helm
`),
						OriginalData: []byte(`# KICS_HELM_ID_0:
apiVersion: v1
kind: Service
metadata:
  name: {{ include "test_helm.fullname" . }}
  labels:
    {{- include "test_helm.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: http
      protocol: TCP
      name: http
  selector:
    {{- include "test_helm.selectorLabels" . | nindent 4 }}
`),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "err_resolve",
			args: args{
				filePath: filepath.FromSlash("../../../test/fixtures/all_auth_users_get_read_access"),
			},
			want:    model.ResolvedFiles{},
			wantErr: true,
		},
		{
			name:            "test_with_dependencies",
			fixture:         "test_helm_subchart",
			compareBySuffix: true,
			want: model.ResolvedFiles{
				File: []model.ResolvedHelm{
					{
						FileName: filepath.FromSlash("../../../test/fixtures/test_helm_subchart/templates/serviceaccount.yaml"),
						SplitID:  "# KICS_HELM_ID_1:",
						IDInfo:   map[int]interface{}{1: model.HelmIDLineRange{Start: 1, End: 13}},
						Content: []byte(`
# Source: test_helm_subchart/templates/serviceaccount.yaml
# KICS_HELM_ID_1:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dd-helm-test_helm_subchart
  labels:
    helm.sh/chart: test_helm_subchart-0.1.0
    app.kubernetes.io/name: test_helm_subchart
    app.kubernetes.io/instance: dd-helm
    app.kubernetes.io/version: "1.16.0"
    app.kubernetes.io/managed-by: Helm
`),
						OriginalData: []byte(`{{- if .Values.serviceAccount.create -}}
# KICS_HELM_ID_1:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "test_helm_subchart.serviceAccountName" . }}
  labels:
    {{- include "test_helm_subchart.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
`),
					},
					{
						FileName: filepath.FromSlash("../../../test/fixtures/test_helm_subchart/charts/subchart/templates/service.yaml"),
						SplitID:  "# KICS_HELM_ID_0:",
						IDInfo:   map[int]interface{}{0: model.HelmIDLineRange{Start: 0, End: 16}},
						Content: []byte(`
# Source: test_helm_subchart/charts/subchart/templates/service.yaml
# KICS_HELM_ID_0:
apiVersion: v1
kind: Service
metadata:
  name: dd-helm-subchart
  labels:
    helm.sh/chart: subchart-0.1.0
    app.kubernetes.io/name: subchart
    app.kubernetes.io/instance: dd-helm
    app.kubernetes.io/version: "1.16.0"
    app.kubernetes.io/managed-by: Helm
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app.kubernetes.io/name: subchart
    app.kubernetes.io/instance: dd-helm
`),
						OriginalData: []byte(`# KICS_HELM_ID_0:
apiVersion: v1
kind: Service
metadata:
  name: {{ include "subchart.fullname" . }}
  labels:
    {{- include "subchart.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: http
      protocol: TCP
      name: http
  selector:
    {{- include "subchart.selectorLabels" . | nindent 4 }}
`),
					},
				},
			},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.args.filePath
			if tt.fixture != "" {
				filePath = helmFixturePath(t, tt.fixture)
			}
			got, err := res.Resolve(ctx, filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Resolve() = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.compareBySuffix {
				require.NoError(t, err)
				require.NotEmpty(t, got.Excluded)
				for _, want := range tt.want.File {
					gotFile := findResolvedBySuffix(t, got.File, pathSuffix(t, want.FileName))
					require.Equal(t, want.SplitID, gotFile.SplitID)
					require.True(t, reflect.DeepEqual(want.IDInfo, gotFile.IDInfo))
					require.Equal(t, want.Content, gotFile.Content)
					require.Equal(t, want.OriginalData, gotFile.OriginalData)
				}
				crd := findResolvedBySuffix(t, got.File, "charts/subchart/crds/widget.yaml")
				require.Equal(t, "# KICS_HELM_ID_0:", crd.SplitID)
				require.Contains(t, string(crd.OriginalData), "# KICS_HELM_ID_")
				require.Contains(t, string(crd.Content), "widgets.subchart.example.com")
			} else {
				if !reflect.DeepEqual(got.File, tt.want.File) {
					t.Errorf("Resolve() = %v, want = %v", got, tt.want)
				}
				if err == nil {
					require.NotEmpty(t, got.Excluded)
				}
			}
		})
	}
}

func TestBlankTemplateActions(t *testing.T) {
	source := "a: {{ .Values.x }}\n{{- if .Values.y }}\nb: 1\n{{- end }}\nc: {{ include \"t\" .\n  | indent 4 }}\nd: 2\n"
	got := string(BlankTemplateActions([]byte(source)))
	require.Equal(t, "a: \n\nb: 1\n\nc: \n\nd: 2\n", got)
	require.Equal(t, strings.Count(source, "\n"), strings.Count(got, "\n"), "line count must be preserved")
}

// TestHelmResolve_ActionOnlyPartialKeepsScalarValues covers a library chart
// whose partials are action-only, as in Bitnami's common chart. Their output is
// used as a label value and as a scalar, so the invocation instrumentation must
// not add anything (a newline or a marker) to what they return.
func TestHelmResolve_ActionOnlyPartialKeepsScalarValues(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("common/Chart.yaml", "apiVersion: v2\nname: common\nversion: 1.0.0\ntype: library\n")
	write("common/templates/_names.tpl", "{{/* names */}}\n"+
		"{{- define \"common.labels.value\" -}}\n{{- . | toString | trunc 63 -}}\n{{- end -}}\n"+
		"{{- define \"common.names.chart\" -}}\n"+
		"{{- include \"common.labels.value\" (printf \"%s-%s\" .Chart.Name .Chart.Version) -}}\n{{- end -}}\n"+
		"{{- define \"common.names.if\" -}}\n{{- if .Values.enabled -}}\n{{ include \"common.names.chart\" . }}\n{{- end -}}\n{{- end -}}\n")
	write("app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n"+
		"dependencies:\n- name: common\n  version: 1.0.0\n  repository: file://../common\n")
	write("app/values.yaml", "enabled: true\n")
	write("app/templates/cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  labels:\n"+
		"    helm.sh/chart: {{ include \"common.names.chart\" . | quote }}\n"+
		"data:\n  chart: {{ include \"common.names.chart\" . }}\n  gated: {{ include \"common.names.if\" . }}\n")
	// A manifest template that is action-only still gets its invocation tracked.
	write("app/templates/_cm.tpl", "{{- define \"app.cm\" -}}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: wrapped\n{{- end -}}\n")
	write("app/templates/wrapped.yaml", "{{ include \"app.cm\" . }}\n")

	got, err := (&Resolver{}).Resolve(context.Background(), filepath.Join(root, "app"))
	require.NoError(t, err)

	cm := string(findResolvedBySuffix(t, got.File, "templates/cm.yaml").Content)
	require.Contains(t, cm, `helm.sh/chart: "app-1.0.0"`)
	require.Contains(t, cm, "chart: app-1.0.0\n")
	require.Contains(t, cm, "gated: app-1.0.0")
	require.NotContains(t, cm, kicsHelmInvocation)

	wrapped := findResolvedBySuffix(t, got.File, "templates/wrapped.yaml")
	require.Contains(t, string(wrapped.Content), "name: wrapped")
	require.Equal(t, model.ResourceLine{Line: 1, Col: 0}, wrapped.HelmInvocation)
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
			require.Equal(t, tt.source, string(stripHelmInvocationActions(file.Data)))
		})
	}
}

func TestAddHelmInvocationMarkersKeepsIncludeIndentation(t *testing.T) {
	source := "kind: Service\nmetadata:\n  labels:\n    {{ include \"l\" . | nindent 4 | trim }}\n"
	file := addHelmInvocationMarkers(&chart.File{Name: "templates/svc.yaml", Data: []byte(source)})
	require.Contains(t, string(file.Data), "\" }}    {{ include")
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
			require.Equal(t, tt.wantMarked, strings.Count(string(file.Data), "{{ print "))
			require.Equal(t, tt.source, string(stripHelmInvocationActions(file.Data)))
		})
	}
}

// TestHelmResolve_IncludeInMixedManifestKeepsInvocation covers a manifest that
// mixes logic with an include which emits the whole resource, as Bitnami's
// contour does: the resource is defined in a partial, so only the invocation
// can tell where it came from.
func TestHelmResolve_IncludeInMixedManifestKeepsInvocation(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	write("Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n")
	write("values.yaml", "enabled: true\n")
	write("templates/_svc.tpl", "{{- define \"app.svc\" -}}\napiVersion: v1\nkind: Service\nmetadata:\n"+
		"  name: svc\n  annotations:\n    a: b\n{{- end -}}\n")
	write("templates/svc.yaml", "{{- $unused := \"x\" }}\n{{- if .Values.enabled }}\n"+
		"{{ include \"app.svc\" . }}\n{{- end }}\n")

	got, err := (&Resolver{}).Resolve(context.Background(), root)
	require.NoError(t, err)
	svc := findResolvedBySuffix(t, got.File, "templates/svc.yaml")
	require.Equal(t, model.ResourceLine{Line: 3, Col: 0}, svc.HelmInvocation)
	require.Contains(t, string(svc.Content), "name: svc")
	require.NotContains(t, string(svc.Content), kicsHelmInvocation)
}
