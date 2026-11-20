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

func TestKeyedRowsSearchKeyPrefix(t *testing.T) {
	compose := "services:\n  web:\n    image: nginx\n  web.api:\n    image: api\n"
	stack := "Resources:\n  Queue:\n    Type: AWS::SQS::Queue\n"
	files := model.FileMetadatas{
		{ID: "compose", FilePath: "compose.yaml", OriginalData: compose, Platform: PlatformDockerCompose,
			Document: model.Document{"services": map[string]interface{}{
				"web": map[string]interface{}{"image": "nginx"}, "web.api": map[string]interface{}{"image": "api"}}}},
		{ID: "stack", FilePath: "stack.yaml", OriginalData: stack, Platform: PlatformCloudFormation,
			Document: model.Document{"Resources": map[string]interface{}{
				"Queue": map[string]interface{}{"Type": "AWS::SQS::Queue"}}}},
	}
	prefixes := make(map[string]string)
	for _, r := range DocumentResources(context.Background(), files) {
		prefixes[r.ResourcePath] = r.searchKeyPrefix
	}
	require.Equal(t, map[string]string{
		"services.web":     "services.web",
		"services.web.api": "services.{{web.api}}",
		"Queue":            "Resources.Queue",
	}, prefixes, "a key with a dot is written within {{ }}, as search keys write it")
}

func TestKubernetesListDocuments(t *testing.T) {
	list := "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: ConfigMap\n    metadata:\n      name: settings\n"
	allow := "apiVersion: acme.io/v1\nkind: AllowList\nmetadata:\n  name: trusted\nitems:\n  - foo\n"
	object := func(kind, name string) map[string]interface{} {
		return map[string]interface{}{"apiVersion": "v1", "kind": kind, "metadata": map[string]interface{}{"name": name}}
	}
	files := model.FileMetadatas{
		{ID: "list", FilePath: "k8s/list.yaml", OriginalData: list, Platform: PlatformKubernetes,
			Document: model.Document{"apiVersion": "v1", "kind": "List", "items": []interface{}{object("ConfigMap", "settings")}}},
		{ID: "rendered", FilePath: "chart/templates/list.yaml", OriginalData: list, Platform: PlatformKubernetes, Kind: model.KindHELM,
			Document: model.Document{"apiVersion": "v1", "kind": "List", "items": []interface{}{object("ConfigMap", "a"), object("Service", "b")}}},
		// A typed list's members take its kind and version; a list in a list
		// holds objects too.
		{ID: "pods", FilePath: "k8s/pods.yaml", OriginalData: list, Platform: PlatformKubernetes,
			Document: model.Document{"apiVersion": "v1", "kind": "PodList", "items": []interface{}{
				map[string]interface{}{"metadata": map[string]interface{}{"name": "web"}}}}},
		{ID: "nested", FilePath: "k8s/nested.yaml", OriginalData: list, Platform: PlatformKubernetes,
			Document: model.Document{"apiVersion": "v1", "kind": "List", "items": []interface{}{
				map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": []interface{}{object("ConfigMap", "inner")}}}}},
		// A named object whose kind ends in List is one object.
		{ID: "allow", FilePath: "k8s/allow.yaml", OriginalData: allow, Platform: PlatformKubernetes,
			Document: model.Document{"apiVersion": "acme.io/v1", "kind": "AllowList",
				"metadata": map[string]interface{}{"name": "trusted"}, "items": []interface{}{"foo"}}},
	}
	type row struct {
		prefix      string
		owns, share bool
	}
	got := make(map[string]row)
	for _, r := range DocumentResources(context.Background(), files) {
		got[r.File+"|"+r.ResourcePath] = row{r.searchKeyPrefix, r.ownsDocument, r.sharedLines}
	}
	require.Equal(t, map[string]row{
		"k8s/list.yaml|v1/ConfigMap//settings":         {prefix: "items.0"},
		"chart/templates/list.yaml|v1/ConfigMap//a":    {prefix: "items.0", share: true},
		"chart/templates/list.yaml|v1/Service//b":      {prefix: "items.1", share: true},
		"k8s/allow.yaml|acme.io/v1/AllowList//trusted": {owns: true},
		"k8s/pods.yaml|v1/Pod//web":                    {prefix: "items.0"},
		"k8s/nested.yaml|v1/ConfigMap//inner":          {prefix: "items.0.items.0"},
	}, got)
}

func TestCommentStart(t *testing.T) {
	for written, want := range map[string]string{
		"{{ .Name }} # deployment-time name": "{{ .Name }} ",
		"{{ .Name }}":                        "{{ .Name }}",
		"web#1 # note":                       "web#1 ",
		`{{ default "a #b" .X }} # note`:     `{{ default "a #b" .X }} `,
		`'it''s' # note`:                     `'it''s' `,
	} {
		runes := []rune(written)
		require.Equal(t, want, string(runes[:commentStart(runes)]), written)
	}
}

func TestAnsibleSearchKeyPath(t *testing.T) {
	for path, want := range map[string]string{
		"tasks[2]":                    "playbooks.2",
		"tasks[2].block[0]":           "playbooks.2.block.0",
		"plays[0].tasks[1]":           "playbooks.0.tasks.1",
		"plays[1].handlers[0]":        "playbooks.1.handlers.0",
		"plays[0].pre_tasks[3]":       "playbooks.0.pre_tasks.3",
		"plays[0].tasks[1].rescue[2]": "playbooks.0.tasks.1.rescue.2",
	} {
		require.Equal(t, want, ansibleSearchKeyPath(path), path)
	}
}
