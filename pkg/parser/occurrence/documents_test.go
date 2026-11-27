/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package occurrence

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
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
	require.Equal(t, []lineRange{{3, 3}, {7, 7}, {9, 9}},
		parseYAMLFile("{}\n---\nfirst: {}\n---\n{}\n---\n[]\n---\nlast: {}\n").ranges,
		"runtime lazy parsing drops empty mappings but retains empty sequences")

	require.Equal(t, []lineRange{{1, 1}}, parseYAMLFile("a: b\n---\nc: [\n").ranges, "documents before a syntax error are kept, as the parser keeps them")
	require.Equal(t, []lineRange{{1, 1}, {5, 5}}, parseYAMLFile("a: 1\n---\njust a string\n---\nb: 2\n").ranges,
		"a scalar document is skipped, as the parser skips it")
	for _, tt := range []struct {
		platform, first, second, name1, name2 string
	}{
		{platforms.Kubernetes, "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: first}\n", "apiVersion: v1\nkind: Service\nmetadata: {name: second}\n", "first", "second"},
		{platforms.DockerCompose, "services: {first: {image: nginx}}\n", "services: {second: {image: nginx}}\n", "first", "second"},
		{platforms.CloudFormation, "Resources: {First: {Type: AWS::S3::Bucket}}\n", "Resources: {Second: {Type: AWS::SQS::Queue}}\n", "First", "Second"},
		{platforms.CICD, "on: push\njobs: {first: {runs-on: ubuntu-latest}}\n", "on: push\njobs: {second: {runs-on: ubuntu-latest}}\n", "first", "second"},
	} {
		t.Run(tt.platform, func(t *testing.T) {
			source := "{}\n---\n" + tt.first + "---\n{}\n---\n[]\n---\n" + tt.second
			_, docs, _, _, err := (&yamlparser.Parser{}).Parse(model.WithLazyLineInfo(context.Background()), []byte(source), "inventory.yml", false, 0)
			require.NoError(t, err)
			require.Len(t, docs, 3, "empty sequences remain in the runtime document list")
			var files model.FileMetadatas
			for _, doc := range docs {
				files = append(files, &model.FileMetadata{ID: "doc", FilePath: "inventory.yml", OriginalData: source, Platform: tt.platform, Document: doc})
			}
			rows := collectDocumentResources(files)
			require.Len(t, rows, 2)
			require.Equal(t, tt.name1, rows[0].ResourceName)
			require.Equal(t, tt.name2, rows[1].ResourceName)
			require.Equal(t, 0, rows[0].DocumentIndex)
			require.Equal(t, 2, rows[1].DocumentIndex)
			secondStart := strings.Count("{}\n---\n"+tt.first+"---\n{}\n---\n[]\n---\n", "\n") + 1
			offset := 0
			if tt.platform == platforms.CICD {
				offset = 1 // jobs follow the workflow's on key
			}
			require.Equal(t, lineRange{3 + offset, 2 + strings.Count(tt.first, "\n")},
				lineRange{rows[0].Source.Start.Line, rows[0].Source.End.Line})
			require.Equal(t, lineRange{secondStart + offset, secondStart + strings.Count(tt.second, "\n") - 1},
				lineRange{rows[1].Source.Start.Line, rows[1].Source.End.Line})
		})
	}
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
		lines[r.DocumentID] = lineRange{r.Source.Start.Line, r.Source.End.Line}
	}
	require.Equal(t, map[string]lineRange{
		"a0": {1, 4}, "a1": {6, 9},
		"b0": {1, 4}, "b1": {7, 10},
	}, lines, "each document gets its own lines")
}

func TestKeyedOccurrencePaths(t *testing.T) {
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
	paths := make(map[string]model.SourcePath)
	for _, r := range collectDocumentResources(files) {
		paths[r.ResourcePath] = r.StructuralPath
	}
	require.Equal(t, map[string]model.SourcePath{
		"services.web":     {{Key: "services"}, {Key: "web"}},
		"services.web.api": {{Key: "services"}, {Key: "web.api"}},
		"Queue":            {{Key: "Resources"}, {Key: "Queue"}},
	}, paths, "a key with a dot occupies one path segment")
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

	rows := collectDocumentResources(model.FileMetadatas{f})

	got := make(map[string]lineRange)
	for _, row := range rows {
		got[row.ResourcePath] = lineRange{row.Source.Start.Line, row.Source.End.Line}
	}
	require.Equal(t, map[string]lineRange{
		"BucketBlue": {3, 7}, "BucketGreen": {3, 7}, "Plain": {9, 10},
		"ArchiveEastApp": {11, 18}, "ArchiveWestApp": {11, 18},
	}, got)
	for _, row := range rows {
		if row.ResourcePath != "Plain" {
			require.Equal(t, 2, row.LegacyCollectionLine)
		}
	}
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
		got[row.ResourcePath] = lineRange{row.Source.Start.Line, row.Source.End.Line}
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
	item := func(i int) model.SourcePath {
		return model.SourcePath{{Key: "items"}, {Index: i, IsIndex: true}}
	}
	got := make(map[string]model.SourcePath)
	for _, r := range collectDocumentResources(files) {
		got[r.File+"|"+r.ResourcePath] = r.StructuralPath
		if r.Helm != nil {
			require.Zero(t, r.LegacySource.Start.Line, "rendered list members lack distinct written spans")
		}
	}
	require.Equal(t, map[string]model.SourcePath{
		"k8s/list.yaml|v1/ConfigMap//settings":         item(0),
		"chart/templates/list.yaml|v1/ConfigMap//a":    item(0),
		"chart/templates/list.yaml|v1/Service//b":      item(1),
		"k8s/allow.yaml|acme.io/v1/AllowList//trusted": nil,
		"k8s/pods.yaml|v1/Pod//web":                    item(0),
		"k8s/nested.yaml|v1/ConfigMap//inner":          append(item(0), item(0)...),
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

func TestAnsibleTaskPaths(t *testing.T) {
	f := &model.FileMetadata{FilePath: "site.yaml", Platform: platforms.Ansible,
		Document: model.Document{"playbooks": []interface{}{map[string]interface{}{
			"hosts": "all",
			"tasks": []interface{}{
				map[string]interface{}{"shell": "echo one"},
				map[string]interface{}{"block": []interface{}{map[string]interface{}{"shell": "echo two"}}},
			},
		}}},
	}
	rows := collectDocumentResources(model.FileMetadatas{f})
	require.Len(t, rows, 2)
	require.Equal(t, model.SourcePath{{Key: "playbooks"}, {Index: 0, IsIndex: true},
		{Key: "tasks"}, {Index: 0, IsIndex: true}}, rows[0].StructuralPath)
	require.Equal(t, model.SourcePath{{Key: "playbooks"}, {Index: 0, IsIndex: true},
		{Key: "tasks"}, {Index: 1, IsIndex: true}, {Key: "block"}, {Index: 0, IsIndex: true}}, rows[1].StructuralPath)
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

// collectDocumentResources collects the parsed occurrences.
func collectDocumentResources(files model.FileMetadatas) []model.ResourceOccurrence {
	var rows []model.ResourceOccurrence
	Documents(context.Background(), files, func(_ *model.FileMetadata, r *model.ResourceOccurrence) { rows = append(rows, *r) })
	return rows
}

func TestGitLabDeclaredJobOccurrences(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		spans        []lineRange
	}{
		{"empty mapping before jobs", "{}\n---\nbuild: {script: echo ok}\n", []lineRange{{3, 3}}},
		{"empty mapping between jobs", "build: {}\n---\n{}\n---\nbuild: {}\n", []lineRange{{1, 1}, {5, 5}}},
		{"repeated declaration ranges", "build:\n  script: echo first\n\n# another declaration\nbuild:\n  script: echo second\n", []lineRange{{1, 2}, {5, 6}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, docs, _, _, err := (&yamlparser.Parser{}).Parse(model.WithLazyLineInfo(context.Background()), []byte(tt.source), ".gitlab-ci.yml", false, 0)
			require.NoError(t, err)
			var files model.FileMetadatas
			for _, doc := range docs {
				files = append(files, &model.FileMetadata{ID: "doc", FilePath: ".gitlab-ci.yml", OriginalData: tt.source, Platform: platforms.CICD, ParseIdentity: model.ParseIdentity{Provider: "gitlab"}, Document: doc})
			}
			rows := collectDocumentResources(files)
			var spans []lineRange
			for _, row := range rows {
				require.Equal(t, "build", row.ResourceName)
				spans = append(spans, lineRange{row.Source.Start.Line, row.Source.End.Line})
			}
			require.Equal(t, tt.spans, spans)
		})
	}

	content := "# pipeline\ninclude: missing.yml\ndefault: {image: alpine}\n" +
		".base: &base {script: echo template}\n" +
		"build: {extends: .base}\n" +
		"release: {trigger: other/project}\n" +
		"artifacts: {}\nhooks: *base\n" +
		"id: {script: echo id}\nfile: {script: echo file}\n" +
		"_dd_lines: {script: echo lines}\n_parsed_run: {script: echo parsed}\n" +
		"'build.api[0]': {rules: [{when: never}]}\n" +
		"scalar: nope\nsequence: []\n" +
		"---\n# second document\nnext: {script: echo next}\n"
	_, docs, _, _, err := (&yamlparser.Parser{}).Parse(context.Background(), []byte(content), ".gitlab-ci.yml", false, 0)
	require.NoError(t, err)
	var files model.FileMetadatas
	for _, doc := range docs {
		files = append(files, &model.FileMetadata{ID: "doc", FilePath: "renamed.yml",
			OriginalData: content, Platform: platforms.CICD, ParseIdentity: model.ParseIdentity{Provider: "gitlab"}, Document: doc})
	}
	rows := collectDocumentResources(files)
	require.Len(t, rows, 10)
	wantLines := map[string]int{"build": 5, "release": 6, "artifacts": 7, "hooks": 8, "id": 9,
		"file": 10, "_dd_lines": 11, "_parsed_run": 12, "build.api[0]": 13, "next": 18}
	for _, row := range rows {
		require.Equal(t, "gitlab_ci_job", row.ResourceType)
		require.Equal(t, "renamed.yml", row.File)
		require.Equal(t, wantLines[row.ResourceName], row.Source.Start.Line, row.ResourceName)
		require.Equal(t, row.Source.Start.Line, row.Source.End.Line)
		require.Equal(t, row.ResourceName, row.ResourcePath)
		require.Equal(t, model.SourcePath{{Key: row.ResourceName}}, row.StructuralPath)
	}
	for _, global := range []string{"default", "include", "stages", "variables", "workflow", "spec",
		"image", "services", "cache", "before_script", "after_script", "types"} {
		source := global + ": {}\njob: {}\n"
		f := &model.FileMetadata{FilePath: ".gitlab-ci.yaml", OriginalData: source, Platform: platforms.CICD, ParseIdentity: model.ParseIdentity{Provider: "gitlab"}, Document: model.Document{"job": map[string]interface{}{}}}
		got := collectDocumentResources(model.FileMetadatas{f})
		require.Len(t, got, 1, global)
		require.Equal(t, "job", got[0].ResourceName)
	}
}
