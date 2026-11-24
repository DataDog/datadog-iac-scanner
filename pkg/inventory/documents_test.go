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
	jsonparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
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
		return &model.FileMetadata{ID: id, FilePath: path, OriginalData: content, Platform: platforms.Kubernetes,
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
	for _, r := range collectDocumentResources(files) {
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
		{ID: "compose", FilePath: "compose.yaml", OriginalData: compose, Platform: platforms.DockerCompose,
			Document: model.Document{"services": map[string]interface{}{
				"web": map[string]interface{}{"image": "nginx"}, "web.api": map[string]interface{}{"image": "api"}}}},
		{ID: "stack", FilePath: "stack.yaml", OriginalData: stack, Platform: platforms.CloudFormation,
			Document: model.Document{"Resources": map[string]interface{}{
				"Queue": map[string]interface{}{"Type": "AWS::SQS::Queue"}}}},
	}
	prefixes := make(map[string]string)
	for _, r := range collectDocumentResources(files) {
		prefixes[r.ResourcePath] = r.searchKeyPrefix
	}
	require.Equal(t, map[string]string{
		"services.web":     "services.web",
		"services.web.api": "services.{{web.api}}",
		"Queue":            "Resources.Queue",
	}, prefixes, "a key with a dot is written within {{ }}, as search keys write it")
}

func TestCloudFormationForEachRows(t *testing.T) {
	const source = `Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Buckets:
    - Name
    - !Ref Names
    - Bucket${Name}:
        Type: AWS::S3::Bucket

  Plain:
    Type: AWS::SQS::Queue
  Fn::ForEach::Regions:
    - Region
    - !Ref Regions
    - Fn::ForEach::Tiers${Region}:
        - Tier
        - !Ref Tiers
        - Archive${Region}${Tier}:
            Type: AWS::S3::Bucket
  Fn::ForEach::Unknown:
    - Name
    - !Ref NoDefault
    - Missing${Name}:
        Type: AWS::S3::Bucket
Outputs:
  Name:
    Value: plain
Parameters:
  Names:
    Type: CommaDelimitedList
    Default: Blue,Green
  Regions:
    Type: CommaDelimitedList
    Default: East,West
  Tiers:
    Type: CommaDelimitedList
    Default: App
`
	f := lazyCloudFormationFile(t, source)
	resources, ok := f.Document["Resources"].(map[string]interface{})
	require.True(t, ok)
	require.Contains(t, resources, "Fn::ForEach::Unknown")
	require.Contains(t, resources, "BucketGreen")

	collector := NewCollector(t.TempDir())
	for _, row := range collectDocumentResources(model.FileMetadatas{f}) {
		collector.AddResource(&row)
	}
	collector.AddFinding(&Finding{Fingerprint: "green", DocumentID: f.ID,
		SearchKey: "Resources.BucketGreen.Type", Line: 3})
	collector.AddFinding(&Finding{Fingerprint: "collection", DocumentID: f.ID, SearchKey: "Resources", Line: 2})
	collector.AddFinding(&Finding{Fingerprint: "loop", DocumentID: f.ID, SearchKey: "Resources", Line: 3})
	inv := collector.Build(testMetadata())

	got := make(map[string]lineRange)
	for _, row := range inv.Resources {
		got[row.ResourcePath] = lineRange{row.LineStart, row.LineEnd}
	}
	require.Equal(t, map[string]lineRange{
		"BucketBlue": {3, 7}, "BucketGreen": {3, 7}, "Plain": {9, 10},
		"ArchiveEastApp": {11, 18}, "ArchiveWestApp": {11, 18},
	}, got)
	require.Equal(t, []FindingLink{
		{FindingFingerprint: "collection", ResourceRef: "stack.yaml|ArchiveEastApp"},
		{FindingFingerprint: "green", ResourceRef: "stack.yaml|BucketGreen"},
	}, inv.FindingLinks)
	require.Equal(t, 1, inv.Stats.FindingsUnlinked)

	t.Run("flow-style loops on the same line", testCloudFormationForEachRowsOnSameLine)
}

func testCloudFormationForEachRowsOnSameLine(t *testing.T) {
	// Both loop keys start on line 3. Only the second spans later lines.
	const source = `Transform: AWS::LanguageExtensions
Resources: {
  "Fn::ForEach::Buckets": [Name, !Ref Names, {"Bucket${Name}": {Type: "AWS::S3::Bucket"}}], "Fn::ForEach::Queues": [
    Name, !Ref Names, {"Queue${Name}": {
      Type: "AWS::SQS::Queue"
    }}
  ]
}
Parameters:
  Names:
    Type: CommaDelimitedList
    Default: Blue
`
	f := lazyCloudFormationFile(t, source)
	require.Nil(t, f.LineInfoDocument)
	rows := collectDocumentResources(model.FileMetadatas{f})
	require.Nil(t, f.LineInfoDocument, "inventory leaves the original line metadata unloaded")

	require.Len(t, rows, 2)
	got := make(map[string]lineRange, len(rows))
	for _, row := range rows {
		got[row.ResourcePath] = lineRange{row.LineStart, row.LineEnd}
	}
	require.Equal(t, map[string]lineRange{"BucketBlue": {3, 3}, "QueueBlue": {3, 3}}, got)
}

func TestCloudFormationJSONForEachRows(t *testing.T) {
	const source = `{
  "Transform": "AWS::LanguageExtensions",
  "Resources": {
    "Fn::ForEach::Buckets": ["Name", ["Blue", "Green"], {
      "Bucket${Name}": {"Type": "AWS::S3::Bucket"}
    }],
    "Plain": {"Type": "AWS::SQS::Queue"}
  },
  "Outputs": {}
}
`
	p := &jsonparser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(source), "stack.json", false, 1)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	resources, ok := docs[0]["Resources"].(map[string]interface{})
	require.True(t, ok)
	require.Contains(t, resources, "Fn::ForEach::Buckets")
	rows := collectDocumentResources(model.FileMetadatas{
		{ID: "stack", FilePath: "stack.json", OriginalData: source,
			Document: docs[0], Kind: model.KindJSON, Platform: platforms.CloudFormation},
	})
	require.Len(t, rows, 1)
	require.Equal(t, "Plain", rows[0].ResourcePath)
}

func TestKubernetesListDocuments(t *testing.T) {
	list := "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: ConfigMap\n    metadata:\n      name: settings\n"
	allow := "apiVersion: acme.io/v1\nkind: AllowList\nmetadata:\n  name: trusted\nitems:\n  - foo\n"
	object := func(kind, name string) map[string]interface{} {
		return map[string]interface{}{"apiVersion": "v1", "kind": kind, "metadata": map[string]interface{}{"name": name}}
	}
	files := model.FileMetadatas{
		{ID: "list", FilePath: "k8s/list.yaml", OriginalData: list, Platform: platforms.Kubernetes,
			Document: model.Document{"apiVersion": "v1", "kind": "List", "items": []interface{}{object("ConfigMap", "settings")}}},
		{ID: "rendered", FilePath: "chart/templates/list.yaml", OriginalData: list, Platform: platforms.Kubernetes, Kind: model.KindHELM,
			Document: model.Document{"apiVersion": "v1", "kind": "List", "items": []interface{}{object("ConfigMap", "a"), object("Service", "b")}}},
		// A typed list's members take its kind and version; a list in a list
		// holds objects too.
		{ID: "pods", FilePath: "k8s/pods.yaml", OriginalData: list, Platform: platforms.Kubernetes,
			Document: model.Document{"apiVersion": "v1", "kind": "PodList", "items": []interface{}{
				map[string]interface{}{"metadata": map[string]interface{}{"name": "web"}}}}},
		{ID: "nested", FilePath: "k8s/nested.yaml", OriginalData: list, Platform: platforms.Kubernetes,
			Document: model.Document{"apiVersion": "v1", "kind": "List", "items": []interface{}{
				map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": []interface{}{object("ConfigMap", "inner")}}}}},
		// A named object whose kind ends in List is one object.
		{ID: "allow", FilePath: "k8s/allow.yaml", OriginalData: allow, Platform: platforms.Kubernetes,
			Document: model.Document{"apiVersion": "acme.io/v1", "kind": "AllowList",
				"metadata": map[string]interface{}{"name": "trusted"}, "items": []interface{}{"foo"}}},
	}
	type row struct {
		prefix      string
		owns, share bool
	}
	got := make(map[string]row)
	for _, r := range collectDocumentResources(files) {
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

func lazyCloudFormationFile(t *testing.T, source string) *model.FileMetadata {
	t.Helper()
	ctx := context.Background()
	p := &yamlparser.Parser{}
	_, docs, _, _, err := p.Parse(model.WithLazyLineInfo(ctx), []byte(source), "stack.yaml", false, 1)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	f := &model.FileMetadata{ID: "stack", FilePath: "stack.yaml", OriginalData: source,
		Document: docs[0], Kind: model.KindYAML, Platform: platforms.CloudFormation}
	f.SetLineInfoLoader(func(ctx context.Context, fm *model.FileMetadata) (map[string]interface{}, error) {
		_, annotated, _, _, err := p.Parse(model.WithLineInfoOnly(ctx), []byte(fm.OriginalData), fm.FilePath, false, 1)
		if err != nil {
			return nil, err
		}
		return annotated[0], nil
	})
	return f
}

// collectDocumentResources returns the rows DocumentResources gives.
func collectDocumentResources(files model.FileMetadatas) []Resource {
	var rows []Resource
	DocumentResources(context.Background(), files, func(r *Resource) { rows = append(rows, *r) })
	return rows
}
