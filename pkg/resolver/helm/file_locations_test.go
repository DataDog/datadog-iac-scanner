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
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
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
		SearchKey:           "dd-helm.spec", ResourceName: "dd-helm",
	}
	(&model.ReportedLocation{
		Path: "web/Chart.yaml", Line: 7, LineText: "- name: pkg",
		Snippet: []model.CodeLine{{Position: 6, Line: "a"}, {Position: 7, Line: "- name: pkg"}},
	}).Apply(v)

	require.Equal(t, "web/Chart.yaml", v.FileName)
	require.Equal(t, "web/charts/pkg/templates/s.yaml", v.DetectedFileName)
	require.Equal(t, 7, v.Line)
	require.Equal(t, 7, v.VulnerabilityLocation.Start.Line)
	require.Equal(t, "- name: pkg", v.LineWithVulnerability)
	require.Equal(t, []model.CodeLine{{Position: 6, Line: "a"}, {Position: 7, Line: "- name: pkg"}}, *v.VulnLines)
	require.Zero(t, v.BlockLocation)
	require.Zero(t, v.RemediationLocation)
	require.Empty(t, v.ResourceSource)
	require.Nil(t, v.FileSource)
	require.Equal(t, "dd-helm.spec", v.SearchKey, "what the finding is about must survive the move")
	require.Equal(t, "dd-helm", v.ResourceName)
}

func TestArchiveLocations(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: dep\n  version: 1.2.3\n" +
			"- name: two\n  version: \">=1.0.0\"\n- name: redis\n  alias: cache\n  version: 1.0.0\n",
		"app/charts/dep-1.2.3.tgz":   "x",
		"app/charts/exact.tgz":       "x",
		"app/charts/two-1.0.0.tgz":   "x",
		"app/charts/two-2.0.0.tgz":   "x",
		"app/charts/redis-1.0.0.tgz": "x",
		"app/charts/dir/Chart.yaml":  "x",
	})
	chartYAML := filepath.Join(root, "app", "Chart.yaml")
	tests := []struct {
		name     string
		rel      string
		wantLine int    // 0 when the file is reported where it is
		wantText string // checked when set
	}{
		{name: "declared dependency", rel: "app/charts/dep/templates/a.yaml", wantLine: 5, wantText: "- name: dep"},
		{name: "two vendored versions share one declaration", rel: "app/charts/two/templates/a.yaml", wantLine: 7},
		{name: "an alias renders under its own name", rel: "app/charts/cache/templates/a.yaml", wantLine: 9,
			wantText: "- name: redis"},
		{name: "undeclared: top of Chart.yaml", rel: "app/charts/exact/templates/a.yaml", wantLine: 1},
		{name: "the parent chart is still a real path", rel: "app/charts/none/templates/a.yaml", wantLine: 1},
		{name: "no parent chart", rel: "other/charts/none/templates/a.yaml"},
		{name: "unpacked directory exists", rel: "app/charts/dir/templates/a.yaml"},
		{name: "no charts segment", rel: "app/templates/a.yaml"},
	}
	archives := newArchiveLocations(vfs.DiskFS{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := archives.of(filepath.Join(root, filepath.FromSlash(tt.rel)))
			if tt.wantLine == 0 {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, chartYAML, got.Path)
			require.Equal(t, tt.wantLine, got.Line)
			if tt.wantText != "" {
				require.Equal(t, tt.wantText, got.LineText)
			}
		})
	}
}
