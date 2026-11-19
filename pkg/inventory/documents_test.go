/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"testing"

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
