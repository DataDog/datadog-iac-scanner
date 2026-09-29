package helm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli/values"
)

const bazelExports = "# Build metadata, not a manifest\nexports_files([\n    \"service.yaml\",\n])\n"
const chartMetadata = "apiVersion: v2\nname: example\nversion: 0.1.0\n"
const configMapManifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n"

func writeSyntheticChart(t *testing.T, files map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, content, 0o600))
	}
	return root
}

func TestBazelTemplatesDiskAndMemFS(t *testing.T) {
	files := map[string][]byte{
		"Chart.yaml":                           []byte(chartMetadata),
		"templates/BUILD.bazel":                []byte(bazelExports),
		"templates/service.yaml":               []byte(configMapManifest + "data:\n  helper: {{ include \"label\" . | quote }}\n  file: {{ .Files.Get \"BUILD.bazel\" | quote }}\n"),
		"templates/_helpers.tpl":               []byte("{{ define \"label\" }}present{{ end }}"),
		"BUILD.bazel":                          []byte("auxiliary data"),
		"templates/extensionless":              []byte(configMapManifest),
		"templates/resource.yml":               []byte(configMapManifest),
		"templates/resource.json":              []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"json"}}`),
		"crds/resource.yaml":                   []byte(configMapManifest),
		"charts/child/Chart.yaml":              []byte(strings.ReplaceAll(chartMetadata, "example", "child")),
		"charts/child/templates/BUILD.bazel":   []byte(bazelExports),
		"charts/child/templates/resource.yaml": []byte(configMapManifest),
	}
	root := writeSyntheticChart(t, files)
	// Packaged dependencies pass through the same recursive filter.
	archive, err := chartutil.Save(&chart.Chart{
		Metadata:  &chart.Metadata{APIVersion: "v2", Name: "packaged", Version: "0.1.0"},
		Templates: []*chart.File{{Name: "templates/BUILD.bazel", Data: []byte(bazelExports)}, {Name: "templates/resource.yaml", Data: []byte(configMapManifest)}},
	}, filepath.Join(root, "charts"))
	require.NoError(t, err)
	require.FileExists(t, archive)
	fsys := vfs.NewMemFS(chartFilesFromDir(t, root))
	for _, tt := range []struct {
		name, root string
		fsys       vfs.FS
	}{{"disk", root, vfs.DiskFS{}}, {"memory", "chart", fsys}} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			rel, ch, _, err := runInstall(ctx, tt.root, tt.fsys, newClient(ctx), &values.Options{})
			require.NoError(t, err)
			require.NotContains(t, rel.Manifest, "exports_files")
			for _, source := range []string{"templates/service.yaml", "templates/extensionless", "templates/resource.yml", "templates/resource.json", "charts/child/templates/resource.yaml", "charts/packaged/templates/resource.yaml"} {
				require.Contains(t, rel.Manifest, source)
			}
			require.Contains(t, rel.Manifest, "present")
			require.Contains(t, rel.Manifest, "auxiliary data")
			require.NotEmpty(t, ch.Raw)
			resolved, err := NewResolver(tt.fsys).Resolve(ctx, tt.root)
			require.NoError(t, err)
			entries := resolvedByRoot(t, resolved, tt.root)
			require.Contains(t, entries, "templates/service.yaml")
			require.NotEmpty(t, entries["templates/service.yaml"].IDInfo)
			require.Equal(t, "# KICS_HELM_ID_0:\n"+string(files["templates/service.yaml"]), string(entries["templates/service.yaml"].OriginalData))
		})
	}
}

func TestBazelTemplatesRecognitionIsNarrow(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		excluded      bool
	}{
		{"BUILD.bazel", bazelExports, true},
		{"BUILD.bazel", "exports_files(['service.yaml'])\n", true},
		{"BUILD", bazelExports, false},
		{"OTHER.bazel", bazelExports, false},
		{"BUILD.bazel.yaml", bazelExports, false},
		{"BUILD.bazel", configMapManifest, false},
		{"BUILD.bazel", "kind: [\n", false},
		{"BUILD.bazel", bazelExports + "---\n" + configMapManifest, false},
		{"BUILD.bazel", "# {{ fail \"still evaluated\" }}\n" + bazelExports, false},
		{"BUILD.bazel", "load(\"//:defs.bzl\", \"custom\")\ncustom()\n", false},
	} {
		file := &chart.File{Name: "templates/" + tt.name, Data: []byte(tt.content)}
		require.Equal(t, tt.excluded, isBazelExportsFile(file), "%s: %s", tt.name, tt.content)
	}
	// A real manifest with the reserved-looking name must still be rendered.
	root := writeSyntheticChart(t, map[string][]byte{"Chart.yaml": []byte(chartMetadata), "templates/BUILD.bazel": []byte(configMapManifest)})
	ctx := context.Background()
	rel, _, _, err := runInstall(ctx, root, vfs.DiskFS{}, newClient(ctx), &values.Options{})
	require.NoError(t, err)
	require.Contains(t, rel.Manifest, "templates/BUILD.bazel")
}

func TestBazelTemplatesPreserveRealFailures(t *testing.T) {
	for _, content := range []string{
		"kind: [\n",
		"{{ include \"missing.helper\" . }}\n",
		"{{ required \"team required\" .Values.team }}\n",
		"{{ fail \"real failure\" }}\n",
	} {
		root := writeSyntheticChart(t, map[string][]byte{"Chart.yaml": []byte(chartMetadata), "templates/BUILD.bazel": []byte(bazelExports), "templates/real.yaml": []byte(content)})
		ctx := context.Background()
		_, _, _, err := runInstall(ctx, root, vfs.DiskFS{}, newClient(ctx), &values.Options{})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "BUILD.bazel")
	}
}
