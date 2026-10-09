/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func resolvedPaths(files []model.ResolvedHelm) []string {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, filepath.ToSlash(f.FileName))
	}
	sort.Strings(paths)
	return paths
}

const (
	locationCM = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n"
	locationDB = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n"
)

// Every resolved file must name a file that exists in the scanned tree, however
// its chart was attached.
func TestHelm_Resolve_FilePathsAreRealPaths(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"apps/web/Chart.yaml": "apiVersion: v2\nname: web\nversion: 1.0.0\ndependencies:\n" +
			"- name: db\n  version: 1.0.0\n- name: cache\n  version: 1.0.0\n  repository: file://../../libs/cache\n" +
			"- name: aliased\n  alias: shadow\n  version: 1.0.0\n  repository: file://../../libs/aliased\n" +
			"- name: vendored\n  version: 1.0.0\n- name: renamed\n  version: 1.0.0\n",
		"apps/web/templates/cm.yaml":    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: web\n",
		"libs/db/Chart.yaml":            "apiVersion: v2\nname: db\nversion: 1.0.0\ndependencies:\n- name: inner\n  version: 1.0.0\n",
		"libs/db/templates/secret.yaml": locationDB,
		"libs/db/crds/db-crd.yaml": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n" +
			"metadata:\n  name: dbs.example.com\n",
		"libs/inner/Chart.yaml":                      "apiVersion: v2\nname: inner\nversion: 1.0.0\n",
		"libs/inner/templates/cm.yaml":               "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: inner\n",
		"libs/cache/Chart.yaml":                      "apiVersion: v2\nname: cache\nversion: 1.0.0\n",
		"libs/cache/templates/cm.yaml":               "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cache\n",
		"libs/aliased/Chart.yaml":                    "apiVersion: v2\nname: aliased\nversion: 1.0.0\n",
		"libs/aliased/templates/cm.yaml":             "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: aliased\n",
		"apps/web/charts/vendored/Chart.yaml":        "apiVersion: v2\nname: vendored\nversion: 1.0.0\n",
		"apps/web/charts/vendored/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: vendored\n",
		// A vendored chart whose directory is not named after the chart.
		"apps/web/charts/dir-named-otherwise/Chart.yaml": "apiVersion: v2\nname: renamed\nversion: 1.0.0\n",
		"apps/web/charts/dir-named-otherwise/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\n" +
			"metadata:\n  name: renamed\n",
	})
	// db declares inner as a sibling chart of the scan.
	roots := []string{
		filepath.Join(root, "apps/web"), filepath.Join(root, "libs/db"), filepath.Join(root, "libs/inner"),
		filepath.Join(root, "libs/cache"), filepath.Join(root, "libs/aliased"),
	}
	got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "apps/web"))
	require.NoError(t, err)

	want := []string{
		"libs/aliased/templates/cm.yaml",
		"libs/cache/templates/cm.yaml",
		"libs/db/crds/db-crd.yaml",
		"libs/db/templates/secret.yaml",
		"libs/inner/templates/cm.yaml",
		"apps/web/charts/vendored/templates/cm.yaml",
		"apps/web/charts/dir-named-otherwise/templates/cm.yaml",
		"apps/web/templates/cm.yaml",
	}
	for i := range want {
		want[i] = filepath.ToSlash(filepath.Join(root, want[i]))
	}
	sort.Strings(want)
	require.Equal(t, want, resolvedPaths(got.File))
	for _, f := range got.File {
		require.FileExists(t, f.FileName)
	}
}

func packChart(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// A dependency vendored as a packaged chart has no unpacked file to point at,
// and a line inside an archive cannot be opened: it is reported where the
// repository declares it.
func TestHelm_Resolve_PackagedDependencyReportedAtDeclaration(t *testing.T) {
	chartYAML := "apiVersion: v2\nname: web\nversion: 1.0.0\ndependencies:\n" +
		"- name: other\n  version: 1.0.0\n  condition: other.enabled\n" +
		"- name: pkg\n  version: 1.0.0\n"
	tests := []struct {
		name      string
		files     map[string]string
		wantFile  string
		wantLine  int
		wantInTxt string
	}{
		{"declared in Chart.yaml", map[string]string{"web/Chart.yaml": chartYAML}, "web/Chart.yaml", 8, "- name: pkg"},
		{"declared in requirements.yaml", map[string]string{
			"web/Chart.yaml":        "apiVersion: v2\nname: web\nversion: 1.0.0\n",
			"web/requirements.yaml": "dependencies:\n- name: pkg\n  version: 1.0.0\n",
		}, "web/requirements.yaml", 2, "- name: pkg"},
		{"declared under an alias", map[string]string{"web/Chart.yaml": "apiVersion: v2\nname: web\nversion: 1.0.0\n" +
			"dependencies:\n- name: other\n  version: 1.0.0\n- name: shadowed\n  alias: pkg\n  version: 1.0.0\n"},
			"web/Chart.yaml", 7, "- name: shadowed"},
		{"not declared", map[string]string{"web/Chart.yaml": "apiVersion: v2\nname: web\nversion: 1.0.0\n"},
			"web/Chart.yaml", 1, "apiVersion: v2"},
		{"aliased archive", map[string]string{"web/Chart.yaml": "apiVersion: v2\nname: web\nversion: 1.0.0\n" +
			"dependencies:\n- name: pkg\n  alias: cache\n  version: 1.0.0\n"},
			"web/Chart.yaml", 5, "- name: pkg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			web := filepath.Join(root, "web")
			files := map[string]string{"web/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: web\n"}
			for k, v := range tt.files {
				files[k] = v
			}
			writeTree(t, root, files)
			archive := packChart(t, map[string]string{
				"pkg/Chart.yaml":            "apiVersion: v2\nname: pkg\nversion: 1.0.0\n",
				"pkg/templates/secret.yaml": locationDB,
			})
			require.NoError(t, os.MkdirAll(filepath.Join(web, "charts"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(web, "charts", "pkg-1.0.0.tgz"), archive, 0o600))
			got, err := NewResolver(nil).Resolve(context.Background(), web)
			require.NoError(t, err)
			pkg := findResolvedBySuffix(t, got.File, "/templates/secret.yaml")
			require.NotNil(t, pkg.Reported)
			require.Equal(t, filepath.Join(root, tt.wantFile), pkg.Reported.Path)
			require.Equal(t, tt.wantLine, pkg.Reported.Line)
			require.Contains(t, pkg.Reported.LineText, tt.wantInTxt)
			require.NotEmpty(t, pkg.Reported.Snippet)
			require.Nil(t, findResolvedBySuffix(t, got.File, "web/templates/cm.yaml").Reported)
		})
	}
}

func TestReportedLocation_Apply(t *testing.T) {
	v := &model.Vulnerability{
		FileName: "web/charts/pkg/templates/s.yaml", Line: 46,
		VulnLines:             &[]model.CodeLine{{Position: 46, Line: "template line"}},
		LineWithVulnerability: "template line", ResourceSource: "x", FileSource: []string{"x"},
		BlockLocation:       model.ResourceLocation{Start: model.ResourceLine{Line: 40}},
		RemediationLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 44}},
		Remediation:         "privileged: false", RemediationType: "addition",
		SearchKey:           "dd-helm.spec", ResourceName: "dd-helm",
	}
	(&model.ReportedLocation{
		Path: "web/Chart.yaml", Line: 7, LineText: "- name: pkg",
		Snippet: []model.CodeLine{{Position: 6, Line: "a"}, {Position: 7, Line: "- name: pkg"}},
	}).Apply(v)

	require.Equal(t, "web/Chart.yaml", v.FileName)
	require.Equal(t, "web/charts/pkg/templates/s.yaml", v.DetectedFileName)
	require.Equal(t, "template line", v.DetectedLineWithVulnerability)
	require.Equal(t, 7, v.Line)
	require.Equal(t, 7, v.VulnerabilityLocation.Start.Line)
	require.Equal(t, "- name: pkg", v.LineWithVulnerability)
	require.Equal(t, []model.CodeLine{{Position: 6, Line: "a"}, {Position: 7, Line: "- name: pkg"}}, *v.VulnLines)
	require.Zero(t, v.BlockLocation)
	require.Zero(t, v.RemediationLocation)
	require.Empty(t, v.Remediation, "a fix of the detected file cannot apply to the reported one")
	require.Empty(t, v.RemediationType)
	require.Empty(t, v.ResourceSource)
	require.Nil(t, v.FileSource)
	require.Equal(t, "dd-helm.spec", v.SearchKey, "what the finding is about must survive the move")
	require.Equal(t, "dd-helm", v.ResourceName)
}

// A packaged dependency is reported at the declaration of the chart holding the
// archive, however that chart was reached, and named after where it would be
// unpacked there.
func TestHelm_Resolve_NestedPackagedDependencies(t *testing.T) {
	pkg := string(packChart(t, map[string]string{
		"pkg/Chart.yaml":            "apiVersion: v2\nname: pkg\nversion: 0.1.0\n",
		"pkg/templates/secret.yaml": locationDB,
	}))
	outer := string(packChart(t, map[string]string{
		"outer/Chart.yaml": "apiVersion: v2\nname: outer\nversion: 1.0.0\n" +
			"dependencies:\n- name: pkg\n  version: 0.1.0\n",
		"outer/charts/pkg-0.1.0.tgz": pkg,
	}))
	declaresPkg := "apiVersion: v2\nname: %s\nversion: 1.0.0\ndependencies:\n- name: pkg\n  version: 0.1.0\n"
	tests := []struct {
		name     string
		files    map[string]string
		roots    []string
		wantFile string // where the archive's secret would be unpacked
		wantAt   string
		wantLine int
		wantText string
	}{
		{
			name: "archive of a sibling chart attached by file://",
			files: map[string]string{
				"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
					"dependencies:\n- name: db\n  version: 1.0.0\n  repository: file://../db\n",
				"db/Chart.yaml":           fmt.Sprintf(declaresPkg, "db"),
				"db/charts/pkg-0.1.0.tgz": pkg,
			},
			roots:    []string{"app", "db"},
			wantFile: "db/charts/pkg/templates/secret.yaml", wantAt: "db/Chart.yaml", wantLine: 5, wantText: "- name: pkg",
		},
		{
			name: "archive inside an archive",
			files: map[string]string{
				"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
					"dependencies:\n- name: outer\n  version: 1.0.0\n",
				"app/charts/outer-1.0.0.tgz": outer,
			},
			wantFile: "app/charts/outer/charts/pkg/templates/secret.yaml", wantAt: "app/Chart.yaml", wantLine: 5,
			wantText: "- name: outer",
		},
		{
			name: "archive of an unpacked subchart in a directory named otherwise",
			files: map[string]string{
				"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
					"dependencies:\n- name: sub\n  version: 1.0.0\n",
				"app/charts/sub-dir/Chart.yaml":           fmt.Sprintf(declaresPkg, "sub"),
				"app/charts/sub-dir/charts/pkg-0.1.0.tgz": pkg,
			},
			wantFile: "app/charts/sub-dir/charts/pkg/templates/secret.yaml", wantAt: "app/charts/sub-dir/Chart.yaml", wantLine: 5,
			wantText: "- name: pkg",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, tt.files)
			roots := make([]string, 0, len(tt.roots))
			for _, r := range tt.roots {
				roots = append(roots, filepath.Join(root, r))
			}
			got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "app"))
			require.NoError(t, err)
			secret := findResolvedBySuffix(t, got.File, "/templates/secret.yaml")
			require.Equal(t, filepath.Join(root, filepath.FromSlash(tt.wantFile)), secret.FileName)
			require.NotNil(t, secret.Reported)
			require.Equal(t, filepath.Join(root, filepath.FromSlash(tt.wantAt)), secret.Reported.Path)
			require.Equal(t, tt.wantLine, secret.Reported.Line)
			require.Equal(t, tt.wantText, secret.Reported.LineText)
		})
	}
}

// Each alias renders the chart matching its version, and aliases sharing a
// chart each render their own copy of it.
func TestHelm_Resolve_Aliases(t *testing.T) {
	cm := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Chart.Name }}-{{ .Chart.Version }}\n"
	tests := []struct {
		name  string
		files map[string]string
		roots []string
		want  map[string]string // rendered name -> file it is reported in
	}{
		{
			name: "attached",
			files: map[string]string{
				"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n" +
					"- name: lib\n  alias: c1\n  version: 1.0.0\n- name: lib\n  alias: c2\n  version: 2.0.0\n" +
					"- name: lib\n  alias: c3\n  version: 2.0.0\n",
				"lib1/Chart.yaml":        "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
				"lib1/templates/cm.yaml": cm,
				"lib2/Chart.yaml":        "apiVersion: v2\nname: lib\nversion: 2.0.0\n",
				"lib2/templates/cm.yaml": cm,
			},
			roots: []string{"app", "lib1", "lib2"},
			want: map[string]string{
				"c1-1.0.0": "lib1/templates/cm.yaml", "c2-2.0.0": "lib2/templates/cm.yaml", "c3-2.0.0": "lib2/templates/cm.yaml",
			},
		},
		{
			name: "vendored",
			files: map[string]string{
				"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n" +
					"- name: lib\n  alias: v1\n  version: 1.0.0\n- name: lib\n  alias: v2\n  version: 1.0.0\n",
				"app/charts/lib/Chart.yaml":        "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
				"app/charts/lib/templates/cm.yaml": cm,
			},
			want: map[string]string{
				"v1-1.0.0": "app/charts/lib/templates/cm.yaml", "v2-1.0.0": "app/charts/lib/templates/cm.yaml",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.files["app/templates/cm.yaml"] = cm
			writeTree(t, root, tt.files)
			roots := make([]string, 0, len(tt.roots))
			for _, r := range tt.roots {
				roots = append(roots, filepath.Join(root, r))
			}
			got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "app"))
			require.NoError(t, err)
			rendered := map[string]string{}
			for _, f := range got.File {
				for _, line := range strings.Split(string(f.Content), "\n") {
					if name, ok := strings.CutPrefix(strings.TrimSpace(line), "name: "); ok {
						rel, err := filepath.Rel(root, f.FileName)
						require.NoError(t, err)
						rendered[name] = filepath.ToSlash(rel)
					}
				}
			}
			want := map[string]string{"app-1.0.0": "app/templates/cm.yaml"}
			for k, v := range tt.want {
				want[k] = v
			}
			require.Equal(t, want, rendered)
		})
	}
}

// A chart vendored under charts/ is reported, and fingerprinted, at the
// directory holding it, not at the path Helm names after its alias or chart.
func TestHelm_Resolve_VendoredChartKeepsItsRealPath(t *testing.T) {
	sts := "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: {{ .Chart.Name }}\n"
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name: "aliased",
			files: map[string]string{
				"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n" +
					"- name: postgresql\n  alias: primary-db\n  version: 1.0.0\n",
				"app/charts/postgresql/Chart.yaml": "apiVersion: v2\nname: postgresql\nversion: 1.0.0\n",
			},
			want: "app/charts/postgresql/templates/sts.yaml",
		},
		{
			name: "in a directory named otherwise",
			files: map[string]string{
				"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n" +
					"- name: postgresql\n  version: 1.0.0\n",
				"app/charts/pg/Chart.yaml": "apiVersion: v2\nname: postgresql\nversion: 1.0.0\n",
			},
			want: "app/charts/pg/templates/sts.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Dir(filepath.Dir(tt.want))
			tt.files[dir+"/templates/sts.yaml"] = sts
			writeTree(t, root, tt.files)
			got, err := NewResolver(nil).Resolve(context.Background(), filepath.Join(root, "app"))
			require.NoError(t, err)
			f := findResolvedBySuffix(t, got.File, "/templates/sts.yaml")
			require.Equal(t, filepath.Join(root, filepath.FromSlash(tt.want)), f.FileName)
			require.Nil(t, f.Reported, "the real path is the finding's identity, not a reported location")
		})
	}
}

// A chart the attached dependencies keep from rendering renders without them.
func TestHelm_Resolve_RendersWithoutAttachedDependenciesThatFail(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"app/Chart.yaml":        "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: lib\n  version: 1.0.0\n",
		"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
		"lib/Chart.yaml":        "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
		"lib/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ required \"password\" .Values.password }}\n",
	})
	roots := []string{filepath.Join(root, "app"), filepath.Join(root, "lib")}
	got, err := NewResolver(nil).WithChartRoots(roots).Resolve(context.Background(), filepath.Join(root, "app"))
	require.NoError(t, err)
	require.Equal(t, []string{filepath.ToSlash(filepath.Join(root, "app/templates/cm.yaml"))}, resolvedPaths(got.File))
}
