package helm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	helmdetector "github.com/DataDog/datadog-iac-scanner/pkg/detector/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
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

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
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
	write := func(rel, body string) { writeTree(t, root, map[string]string{rel: body}) }
	write("common/Chart.yaml", "apiVersion: v2\nname: common\nversion: 1.0.0\ntype: library\n")
	write("common/templates/_labels.tpl", "{{- define \"common.labels\" -}}\napp: {{ .Chart.Name }}\n{{- end -}}\n")
	write("app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n"+
		"dependencies:\n- name: common\n  version: 1.0.0\n  repository: file://../common\n")
	write("app/templates/cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  labels:\n"+
		"    {{- include \"common.labels\" . | nindent 4 }}\n")

	roots := []string{filepath.Join(root, "app"), filepath.Join(root, "common")}
	got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "app"))
	require.NoError(t, err)
	cm := findResolvedBySuffix(t, got.File, "templates/cm.yaml")
	require.Contains(t, string(cm.Content), "app: app")
}

// A dependency without a local repository, provided by the build system rather
// than vendored, resolves from the only chart in the scan with its name and a
// compatible version.
func TestHelm_Resolve_DependencyFromScannedCharts(t *testing.T) {
	const helper = "{{- define \"common.labels\" -}}\napp: {{ .Chart.Name }}\nfrom: %s\n{{- end -}}\n"
	const app = "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: common\n  version: %s\n"
	const cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  labels:\n" +
		"    {{- include \"common.labels\" . | nindent 4 }}\n"
	tests := []struct {
		name        string
		libraries   map[string]string // dir -> version
		constraint  string
		repeatRoots bool
		wantFrom    string // library dir the include resolved from, "" for no render
	}{
		{name: "unique match", libraries: map[string]string{"libs/common": "1.2.0"}, constraint: "^1.0.0", wantFrom: "libs/common"},
		{name: "no version constraint", libraries: map[string]string{"libs/common": "3.0.0"}, constraint: `""`, wantFrom: "libs/common"},
		{name: "only an incompatible version", libraries: map[string]string{"libs/common": "2.0.0"}, constraint: "^1.0.0", wantFrom: "libs/common"},
		{name: "ambiguous", libraries: map[string]string{"a/common": "1.0.0", "b/common": "1.1.0"}, constraint: "^1.0.0"},
		{name: "ambiguity settled by version", libraries: map[string]string{"a/common": "1.0.0", "b/common": "2.0.0"},
			constraint: "^1.0.0", wantFrom: "a/common"},
		{name: "ambiguity settled by nearest chart", libraries: map[string]string{"dom/common": "1.0.0", "other/common": "1.0.0"},
			constraint: "^1.0.0", wantFrom: "dom/common"},
		{name: "incompatible versions tied", libraries: map[string]string{"a/common": "2.0.0", "b/common": "2.1.0"}, constraint: "^1.0.0"},
		// Overlapping scan paths record a root more than once, in more than one spelling.
		{name: "repeated chart root", libraries: map[string]string{"libs/common": "1.0.0"}, constraint: "^1.0.0",
			repeatRoots: true, wantFrom: "libs/common"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				"dom/app/Chart.yaml":        fmt.Sprintf(app, tt.constraint),
				"dom/app/templates/cm.yaml": cm,
			}
			roots := []string{filepath.ToSlash(filepath.Join(root, "dom/app"))}
			for dir, version := range tt.libraries {
				files[dir+"/Chart.yaml"] = "apiVersion: v2\nname: common\ntype: library\nversion: " + version + "\n"
				files[dir+"/templates/_labels.tpl"] = fmt.Sprintf(helper, dir)
				lib := filepath.ToSlash(filepath.Join(root, dir))
				roots = append(roots, lib)
				if tt.repeatRoots {
					roots = append(roots, lib+"/", lib)
				}
			}
			writeTree(t, root, files)

			got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "dom/app"))
			if tt.wantFrom == "" {
				require.ErrorContains(t, err, `no template "common.labels"`)
				return
			}
			require.NoError(t, err)
			content := string(findResolvedBySuffix(t, got.File, "templates/cm.yaml").Content)
			require.Contains(t, content, "app: app")
			require.Contains(t, content, "from: "+tt.wantFrom)
		})
	}
}

// A subchart unpacked under charts/ gets its own missing dependencies, here a
// library elsewhere in the scan, as the chart that vendors it does.
func TestHelm_Resolve_VendoredSubchartDependencyFromScannedCharts(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"libs/common/Chart.yaml":            "apiVersion: v2\nname: common\ntype: library\nversion: 1.0.0\n",
		"libs/common/templates/_labels.tpl": "{{- define \"common.labels\" -}}\napp: {{ .Chart.Name }}\n{{- end -}}\n",
		"app/Chart.yaml":                    "apiVersion: v2\nname: app\nversion: 1.0.0\n",
		"app/charts/mid-1.0/Chart.yaml": "apiVersion: v2\nname: mid\nversion: 1.0.0\n" +
			"dependencies:\n- name: common\n  version: ^1.0.0\n",
		"app/charts/mid-1.0/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: mid\n  labels:\n" +
			"    {{- include \"common.labels\" . | nindent 4 }}\n",
	})
	roots := []string{filepath.ToSlash(filepath.Join(root, "app")), filepath.ToSlash(filepath.Join(root, "libs/common"))}

	got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "app"))
	require.NoError(t, err)
	mid := findResolvedBySuffix(t, got.File, "mid-1.0/templates/cm.yaml")
	require.Contains(t, string(mid.Content), "app: mid")
	require.Equal(t, filepath.Join(root, "app", "charts", "mid-1.0", "templates", "cm.yaml"), mid.FileName)
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
			requireStampLine(t, f.SplitID, 0, "YAML CRD SplitID must anchor line mapping")
			require.Contains(t, string(f.OriginalData), helmmarker.IDPrefix, "stamped original required for detector")
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
	requireStampLine(t, splits[0].SplitID, 0, "first document must use first marker")
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
	stamped := setID(ch, nil)

	manifest := strings.Join([]string{
		"---",
		"# Source: test_helm_with_crds\\crds\\widget.yaml",
		"apiVersion: apiextensions.k8s.io/v1",
		"kind: CustomResourceDefinition",
		"metadata:",
		"  name: widgets.example.com",
	}, "\n")

	splits := splitManifestYAML(&release.Release{Manifest: manifest}, ch, stamped, nil)
	require.Len(t, *splits, 1)
	require.Equal(t, "test_helm_with_crds/crds/widget.yaml", (*splits)[0].path)
	require.True(t, (*splits)[0].isCRD)
}

func TestSplitManifestYAML_dropsUnknownSourceHeader(t *testing.T) {
	ch, err := loader.Load(helmFixturePath(t, "test_helm_with_crds"))
	require.NoError(t, err)
	stamped := setID(ch, nil)

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

	splits := splitManifestYAML(&release.Release{Manifest: manifest}, ch, stamped, nil)
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
	stamped := setID(ch, nil)

	manifest := strings.Join([]string{
		"---",
		"# Source: test/crds/leading-empty.yaml",
		string(crd.Data),
	}, "\n")
	splits := splitManifestYAML(&release.Release{Manifest: manifest}, ch, stamped, nil)
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
	file := addID(&chart.File{Name: "templates/nested.yaml", Data: []byte(original)}, 0)
	idMap := getIDMap(file.Data)

	got := (helmdetector.DetectKindLine{}).DetectLine(context.Background(), &model.FileMetadata{
		Kind:              model.KindHELM,
		FilePath:          "templates/nested.yaml",
		HelmID:            "# KICS_HELM_ID_0_8:",
		OriginalData:      string(file.Data),
		LinesOriginalData: utils.SplitLines(string(file.Data)),
		IDInfo:            idMap,
	}, "KICS_HELM_ID_0_8.spec", 1)

	require.Equal(t, 13, got.Line)
	require.Equal(t, 13, got.VulnerablilityLocation.Start.Line)
	require.Equal(t, 13, got.VulnerablilityLocation.End.Line)

	got = (helmdetector.DetectKindLine{}).DetectLine(context.Background(), &model.FileMetadata{
		Kind:              model.KindHELM,
		FilePath:          "templates/nested.yaml",
		HelmID:            "# KICS_HELM_ID_0_8:",
		OriginalData:      string(file.Data),
		LinesOriginalData: utils.SplitLines(string(file.Data)),
		IDInfo:            idMap,
	}, "KICS_HELM_ID_0_8.spec.ports", 1)

	require.Equal(t, 14, got.Line)
	require.Equal(t, 14, got.VulnerablilityLocation.Start.Line)
	require.Equal(t, 14, got.VulnerablilityLocation.End.Line)
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
						SplitID:  "# KICS_HELM_ID_2_0:",
						FileName: filepath.FromSlash("../../../test/fixtures/test_helm/templates/service.yaml"),
						IDInfo:   map[int]interface{}{0: model.HelmIDLineRange{Start: 0, End: 16}},
						Content: []byte(`
# Source: test_helm/templates/service.yaml
# KICS_HELM_ID_2_0:
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
						OriginalData: []byte(`# KICS_HELM_ID_2_0:
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
						SplitID:  "# KICS_HELM_ID_2_1:",
						IDInfo:   map[int]interface{}{1: model.HelmIDLineRange{Start: 1, End: 13}},
						Content: []byte(`
# Source: test_helm_subchart/templates/serviceaccount.yaml
# KICS_HELM_ID_2_1:
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
# KICS_HELM_ID_2_1:
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
						SplitID:  "# KICS_HELM_ID_5_0:",
						IDInfo:   map[int]interface{}{0: model.HelmIDLineRange{Start: 0, End: 16}},
						Content: []byte(`
# Source: test_helm_subchart/charts/subchart/templates/service.yaml
# KICS_HELM_ID_5_0:
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
						OriginalData: []byte(`# KICS_HELM_ID_5_0:
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
				requireStampLine(t, crd.SplitID, 0, "CRD stamp line")
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

// TestHelmResolve_ActionOnlyPartialKeepsScalarValues covers a library chart
// whose partials are action-only, as in Bitnami's common chart. Their output is
// used as a label value and as a scalar, so the invocation instrumentation must
// not add anything (a newline or a marker) to what they return.
func TestHelmResolve_ActionOnlyPartialKeepsScalarValues(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) { writeTree(t, root, map[string]string{rel: body}) }
	write("app/charts/common/Chart.yaml", "apiVersion: v2\nname: common\nversion: 1.0.0\ntype: library\n")
	write("app/charts/common/templates/_names.tpl", "{{/* names */}}\n"+
		"{{- define \"common.labels.value\" -}}\n{{- . | toString | trunc 63 -}}\n{{- end -}}\n"+
		"{{- define \"common.names.chart\" -}}\n"+
		"{{- include \"common.labels.value\" (printf \"%s-%s\" .Chart.Name .Chart.Version) -}}\n{{- end -}}\n"+
		"{{- define \"common.names.if\" -}}\n{{- if .Values.enabled -}}\n{{ include \"common.names.chart\" . }}\n{{- end -}}\n{{- end -}}\n")
	write("app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n"+
		"dependencies:\n- name: common\n  version: 1.0.0\n")
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
	require.NotContains(t, cm, invocationPrefix)

	wrapped := findResolvedBySuffix(t, got.File, "templates/wrapped.yaml")
	require.Contains(t, string(wrapped.Content), "name: wrapped")
	require.Equal(t, model.ResourceLine{Line: 1, Col: 0}, wrapped.HelmInvocations.First())
}

// requireStampLine asserts that stamp is a valid ID line anchored at source line.
func requireStampLine(t *testing.T, stamp string, line int, msg string) {
	t.Helper()
	id, ok := helmmarker.ParseIDLine(stamp)
	require.True(t, ok, "%s: %q is not an ID stamp", msg, stamp)
	require.Equal(t, line, id.Line, msg)
}
