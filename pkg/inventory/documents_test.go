/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestYAMLDocumentLines(t *testing.T) {
	content := `# leading comment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
---
---
# an empty document above
apiVersion: v1
kind: ConfigMap
data:
  script: |
    echo one
    echo two

...
---
apiVersion: v1
kind: Service
metadata:
  name: web
`
	require.Equal(t, []lineRange{{2, 5}, {9, 14}, {18, 21}}, parseYAMLFile(content).ranges)
	require.Empty(t, parseYAMLFile("# only a comment\n").ranges)
	require.Equal(t, []lineRange{{1, 1}}, parseYAMLFile("a: b\n---\nc: [\n").ranges, "documents before a syntax error are kept, as the parser keeps them")
	require.Equal(t, []lineRange{{1, 1}, {5, 5}}, parseYAMLFile("a: 1\n---\njust a string\n---\nb: 2\n").ranges,
		"a scalar document is skipped, as the parser skips it")
}

func TestSplitChartPath(t *testing.T) {
	dir, rel, ok := splitChartPath("/repo/charts/api/templates/deployment.yaml")
	require.True(t, ok)
	require.Equal(t, "/repo/charts/api", dir)
	require.Equal(t, "templates/deployment.yaml", rel)

	dir, rel, ok = splitChartPath("/repo/charts/api/charts/redis/templates/sts.yaml")
	require.True(t, ok)
	require.Equal(t, "/repo/charts/api/charts/redis", dir, "a subchart's template belongs to the subchart")
	require.Equal(t, "templates/sts.yaml", rel)

	dir, rel, ok = splitChartPath("/repo/charts/api/crds/crd.yaml")
	require.True(t, ok)
	require.Equal(t, "/repo/charts/api", dir)
	require.Equal(t, "crds/crd.yaml", rel)

	_, _, ok = splitChartPath("/repo/k8s/web.yaml")
	require.False(t, ok)
}

func TestDocumentResourcesInterleavedFiles(t *testing.T) {
	a := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a0\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: a1\n"
	b := "apiVersion: v1\nkind: Service\nmetadata:\n  name: b0\n---\n\napiVersion: v1\nkind: Pod\nmetadata:\n  name: b1\n"
	doc := func(path, content, id, kind, name string) *model.FileMetadata {
		return &model.FileMetadata{ID: id, FilePath: path, OriginalData: content, Platform: PlatformKubernetes,
			Document: model.Document{"apiVersion": "v1", "kind": kind, "metadata": map[string]interface{}{"name": name}}}
	}
	// Concurrent parsers store the documents of two files mixed.
	files := model.FileMetadatas{
		doc("a.yaml", a, "a0", "ConfigMap", "a0"),
		doc("b.yaml", b, "b0", "Service", "b0"),
		nil,
		doc("a.yaml", a, "a1", "Secret", "a1"),
		doc("b.yaml", b, "b1", "Pod", "b1"),
	}
	lines := make(map[string]lineRange)
	for _, r := range DocumentResources(context.Background(), files) {
		require.Equal(t, r.DocumentID, r.ResourceName)
		lines[r.DocumentID] = lineRange{r.LineStart, r.LineEnd}
	}
	require.Equal(t, map[string]lineRange{
		"a0": {1, 4}, "a1": {6, 9},
		"b0": {1, 4}, "b1": {7, 10},
	}, lines, "each document gets its own lines")
}
