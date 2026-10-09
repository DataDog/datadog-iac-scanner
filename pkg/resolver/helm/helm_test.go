/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helm

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

func TestSilenceStdLogRestoresAfterLastRender(t *testing.T) {
	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(prev)

	endFirst := silenceStdLog()
	endSecond := silenceStdLog()
	endFirst()
	log.Print("while a render is still running")
	require.Empty(t, out.String())
	endSecond()
	log.Print("after every render")
	require.Contains(t, out.String(), "after every render")
}

// writeChartDir creates a chart directory with the given Chart.yaml body and
// returns its path.
func writeChartDir(t *testing.T, dir, chartYAML string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte(chartYAML), 0o600))
	return dir
}

func TestLoadChart_DropsNonTemplateFiles(t *testing.T) {
	dir := writeChartDir(t, filepath.Join(t.TempDir(), "app"), "apiVersion: v2\nname: app\nversion: 1.0.0\n")
	tpl := filepath.Join(dir, "templates")
	require.NoError(t, os.MkdirAll(filepath.Join(tpl, "docs"), 0o755))
	for name, body := range map[string]string{
		"cm.yaml":                "kind: ConfigMap\n",
		"_helpers.tpl":           "{{/* h */}}",
		"NOTES.txt":              "hi",
		"deployment.yaml.gotmpl": "kind: Deployment\n",
		"_create_buckets.sh":     "#!/bin/sh\n",
		"_README.md":             "{{/* partial */}}",
		"BUILD.bazel":            "filegroup(name = \"x\")",
		"BUILD":                  "filegroup(name = \"y\")",
		"defs.bzl":               "x = 1",
		"OWNERS":                 "me",
		"docs/README.md":         "# docs",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(tpl, name), []byte(body), 0o600))
	}

	kept := []string{
		"cm.yaml", "_helpers.tpl", "NOTES.txt", "deployment.yaml.gotmpl", "_create_buckets.sh", "_README.md",
	}
	templateNames := func(ch *chart.Chart) []string {
		var names []string
		for _, f := range ch.Templates {
			names = append(names, strings.TrimPrefix(f.Name, "templates/"))
		}
		return names
	}

	raw, err := loader.LoadDir(dir)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"templates/BUILD.bazel", "templates/BUILD", "templates/defs.bzl", "templates/OWNERS", "templates/docs/README.md",
	}, dropNonTemplateFiles(raw))
	require.ElementsMatch(t, kept, templateNames(raw), "templates with any extension and partials are kept")

	ch, err := loadChart(context.Background(), vfs.DiskFS{}, dir)
	require.NoError(t, err)
	require.ElementsMatch(t, kept, templateNames(ch), "loadChart drops the same files")
}
