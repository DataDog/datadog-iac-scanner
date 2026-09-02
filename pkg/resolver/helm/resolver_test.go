package helm

import (
	"context"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
			idInfo, ok := f.IDInfo[0].(map[int]int)
			require.True(t, ok, "IDInfo must map helm id 0 to source lines for YAML CRDs")
			require.NotEmpty(t, idInfo, "IDInfo line map must not be empty for YAML CRDs")
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

	splits, err := splitManifestYAML(&release.Release{Manifest: manifest}, ch)
	require.NoError(t, err)
	require.Len(t, *splits, 1)
	require.Equal(t, "test_helm_with_crds/crds/widget.yaml", (*splits)[0].path)
}

func TestSplitManifestYAML_userSourceCommentInLaterDocument(t *testing.T) {
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
	}, "\n")

	splits, err := splitManifestYAML(&release.Release{Manifest: manifest}, ch)
	require.NoError(t, err)
	require.Len(t, *splits, 2)
	require.Equal(t, "test_helm_with_crds/crds/widget.yaml", (*splits)[0].path)
	require.Equal(t, "test_helm_with_crds/crds/widget.yaml", (*splits)[1].path)
}

func TestLocalCRDFiles_fromLoadedFixture(t *testing.T) {
	ch, err := loader.Load(helmFixturePath(t, "test_helm_with_crds"))
	require.NoError(t, err)
	require.Len(t, localCRDFiles(ch), 4)
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

func TestAddID_ignoresIndentedAPIVersion(t *testing.T) {
	original := `description: |
  apiVersion: v1
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
		name    string
		args    args
		want    model.ResolvedFiles
		wantErr bool
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
						IDInfo: map[int]interface{}{0: map[int]int{0: 0, 1: 1, 2: 2, 3: 3, 4: 4,
							5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14, 15: 15, 16: 16}},
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
			name: "test_with_dependencies",
			args: args{
				filePath: filepath.FromSlash("../../../test/fixtures/test_helm_subchart"),
			},
			want: model.ResolvedFiles{
				File: []model.ResolvedHelm{
					{
						FileName: filepath.FromSlash("../../../test/fixtures/test_helm_subchart/templates/serviceaccount.yaml"),
						SplitID:  "# KICS_HELM_ID_1:",
						IDInfo: map[int]interface{}{1: map[int]int{1: 1, 2: 2, 3: 3, 4: 4,
							5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10, 11: 11, 12: 12, 13: 13}},
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
						IDInfo: map[int]interface{}{0: map[int]int{0: 0, 1: 1, 2: 2, 3: 3, 4: 4,
							5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14, 15: 15, 16: 16}},
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
			if tt.name == "test_with_dependencies" {
				filePath = helmFixturePath(t, "test_helm_subchart")
			}
			got, err := res.Resolve(ctx, filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Resolve() = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.name == "test_with_dependencies" {
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
