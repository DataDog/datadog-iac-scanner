/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// gjsonLineBySearchLine is the previous marshal-and-query implementation of
// GetLineBySearchLine, kept as the reference the in-place walk must match.
func gjsonLineBySearchLine(pathItems []string, doc map[string]interface{}) int {
	content, err := json.Marshal(doc)
	if err != nil {
		return -1
	}
	if len(pathItems) == 0 {
		return 1
	}
	escape := func(s string) string { return strings.ReplaceAll(s, ".", "\\.") }
	objPath := escape(pathItems[0])
	arrPath := escape(pathItems[0])
	obj := pathItems[len(pathItems)-1]
	arrayObject := ""
	foundArrayIdx := false
	for i := len(pathItems) - 1; i >= 0; i-- {
		if _, err := strconv.Atoi(pathItems[i]); err == nil {
			foundArrayIdx = true
			continue
		}
		if foundArrayIdx {
			arrayObject = pathItems[i]
			break
		}
	}
	if arrayObject == objPath {
		arrPath = "_dd_lines._dd_" + arrayObject + "._dd_arr"
	}
	var inner []string
	if len(pathItems) > 1 {
		inner = pathItems[1 : len(pathItems)-1]
	}
	for _, item := range inner {
		if item == arrayObject {
			arrPath += "._dd_lines._dd_" + escape(item) + "._dd_arr"
		} else {
			arrPath += "." + escape(item)
		}
		objPath += "." + escape(item)
	}
	target := escape(obj)
	for _, p := range []string{
		objPath + "._dd_lines._dd_" + target + "._dd_line",
		objPath + "." + target + "._dd_lines._dd__default._dd_line",
		arrPath + "." + target + "._dd__default._dd_line",
		arrPath + "._dd_" + target + "._dd_line",
	} {
		if r := gjson.GetBytes(content, p); int(r.Int()) > 0 {
			return int(r.Int())
		}
	}
	return -1
}

// documentPaths lists every key and index path of a document's JSON form,
// skipping line markers and parser enrichment.
func documentPaths(doc map[string]interface{}) [][]string {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil
	}
	var paths [][]string
	var walk func(v interface{}, prefix []string)
	walk = func(v interface{}, prefix []string) {
		switch t := v.(type) {
		case map[string]interface{}:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if strings.HasPrefix(k, "_dd_") || strings.HasPrefix(k, "_parsed_") {
					continue
				}
				p := append(append([]string{}, prefix...), k)
				paths = append(paths, p)
				walk(t[k], p)
			}
		case []interface{}:
			for i, e := range t {
				p := append(append([]string{}, prefix...), strconv.Itoa(i))
				paths = append(paths, p)
				walk(e, p)
			}
		}
	}
	walk(generic, nil)
	return paths
}

func TestGetLineBySearchLineMatchesMarshalLookup(t *testing.T) {
	type docParser func(ctx context.Context, content []byte, path string) ([]model.Document, error)
	yamlParse := func(ctx context.Context, content []byte, path string) ([]model.Document, error) {
		_, docs, _, _, err := yamlParser.Parse(ctx, nil, content, path, false, 15)
		return docs, err
	}
	cicdParse := func(ctx context.Context, content []byte, path string) ([]model.Document, error) {
		_, docs, _, _, err := (&cicd.Parser{}).Parse(ctx, content, path, false, 15)
		return docs, err
	}
	jsonParse := func(ctx context.Context, content []byte, path string) ([]model.Document, error) {
		_, docs, _, _, err := (&jsonParser.Parser{}).Parse(ctx, content, path, false, 15)
		return docs, err
	}
	tfParse := func(ctx context.Context, content []byte, path string) ([]model.Document, error) {
		_, docs, _, _, err := terraform.NewDefault().Parse(ctx, content, path, false, 15)
		return docs, err
	}

	fixtures := map[string]docParser{
		"k8s.yaml":                  yamlParse,
		"cloudformation.yaml":       yamlParse,
		"ansible.yaml":              yamlParse,
		"github.yaml":               cicdParse,
		"azureResourceManager.json": jsonParse,
		"openAPI.json":              jsonParse,
		"terraform.tf":              tfParse,
	}

	for name, parse := range fixtures {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "test", "fixtures", "analyzer_test", name)
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			docs, err := parse(context.Background(), content, path)
			require.NoError(t, err)
			require.NotEmpty(t, docs)

			checked := 0
			for _, doc := range docs {
				file := &model.FileMetadata{LineInfoDocument: doc}
				for _, p := range documentPaths(doc) {
					got := GetLineBySearchLine(p, file)
					require.Equal(t, gjsonLineBySearchLine(p, doc), got, "path %v", p)
					checked++
				}
			}
			require.Positive(t, checked)
		})
	}
}

// TestSearchLinePathsDottedRootArrayObject pins the array-path root
// comparison: it must use the raw root key, not a dot-escaped rendering.
// The previous gjson implementation compared the array object against an
// escaped root, so a dotted root key that was also the array object (e.g.
// "actions.deploy.0.run") never matched and the array candidates were
// skipped. Paths now address map keys directly, so the raw comparison is
// correct and is the intended behavior.
func TestSearchLinePathsDottedRootArrayObject(t *testing.T) {
	objPath, arrPath, target := searchLinePaths([]string{"actions.deploy", "0", "run"})
	require.Equal(t, "run", target)
	require.Equal(t, []string{"actions.deploy", "0"}, objPath)
	// The array path descends into the marker of the dotted root itself.
	require.Equal(t, []string{"_dd_lines", "_dd_actions.deploy", "_dd_arr", "0"}, arrPath)

	// Without a trailing array index, the root is a plain object path.
	objPath, arrPath, target = searchLinePaths([]string{"actions.deploy", "run"})
	require.Equal(t, "run", target)
	require.Equal(t, []string{"actions.deploy"}, objPath)
	require.Equal(t, []string{"actions.deploy"}, arrPath)
}

// TestStructFieldByJSONNameEmbedded verifies that embedded (anonymous) struct
// fields resolve like encoding/json flattens them: their exported fields are
// reachable as the parent's own fields.
func TestStructFieldByJSONNameEmbedded(t *testing.T) {
	type metadata struct {
		Run  string `json:"run"`
		Line int    `json:"line"`
	}
	type outer struct {
		Name string `json:"name"`
		metadata
	}
	v := reflect.ValueOf(outer{Name: "job", metadata: metadata{Run: "echo", Line: 7}})
	got, ok := structFieldByJSONName(v, "run")
	require.True(t, ok)
	require.Equal(t, "echo", got)
	got, ok = structFieldByJSONName(v, "name")
	require.True(t, ok)
	require.Equal(t, "job", got)
	_, ok = structFieldByJSONName(v, "missing")
	require.False(t, ok)
}

func TestGitLabSharedValuesUseSiteLocations(t *testing.T) {
	const content = ".base:\n  variables: {INHERITED: yes, OWN: original}\n  script: [echo parent]\njob:\n  extends: .base\n  variables: {OWN: child}\nrefjob:\n  script: !reference [.base, script]\n.parent:\n  script: !reference [.base, script]\nchild:\n  extends: .parent\n"
	out, err := (&cicd.Parser{}).ParseOutput(context.Background(), []byte(content), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	file := &model.FileMetadata{Kind: model.KindYAML, FilePath: ".gitlab-ci.yml", OriginalData: content, Document: out.Documents[0], LineInfoDocument: out.Documents[0], LineOverlay: out.Sources[0].LineOverlay}
	for _, tc := range []struct {
		keys []string
		line int
	}{
		{[]string{"job", "script", "0"}, 5},
		{[]string{"job", "variables", "INHERITED"}, 5},
		{[]string{"job", "variables", "OWN"}, 6},
		{[]string{"refjob", "script", "0"}, 8},
		{[]string{"child", "script", "0"}, 12},
	} {
		require.Equal(t, tc.line, GetLineBySearchLine(tc.keys, file), tc.keys)
		path := make(model.SourcePath, len(tc.keys))
		for i, key := range tc.keys {
			if key == "0" {
				path[i] = model.PathSegment{IsIndex: true, Index: 0}
			} else {
				path[i] = model.PathSegment{Key: key}
			}
		}
		lines, err := NewDetectLine(0).DetectPath(context.Background(), file, path)
		require.NoError(t, err, tc.keys)
		require.Equal(t, tc.line, lines.Line, tc.keys)
		lines = NewDetectLine(0).DetectLine(context.Background(), file, strings.Join(tc.keys, "."))
		require.Equal(t, tc.line, lines.Line, tc.keys)
	}
}

func TestGitLabInputContainersUseSiteLocations(t *testing.T) {
	for _, expression := range []string{"'$[[ inputs.commands ]]'", "['$[[ inputs.commands ]]']"} {
		content := "spec:\n  inputs:\n    commands:\n      type: array\n      default: [echo a, echo b]\n---\njob:\n  script: " + expression + "\n"
		out, err := (&cicd.Parser{}).ParseOutput(context.Background(), []byte(content), ".gitlab-ci.yml", false, 15)
		require.NoError(t, err)
		file := &model.FileMetadata{Kind: model.KindYAML, FilePath: ".gitlab-ci.yml", OriginalData: content, Document: out.Documents[1], LineOverlay: out.Sources[1].LineOverlay}
		require.Equal(t, 8, GetLineBySearchLine([]string{"job", "script", "1"}, file))
		lines, err := NewDetectLine(0).DetectPath(context.Background(), file, model.SourcePath{{Key: "job"}, {Key: "script"}, {Index: 1, IsIndex: true}})
		require.NoError(t, err)
		require.Equal(t, 8, lines.Line)
	}
}

func TestGitLabContainerAliasesUseSiteLocations(t *testing.T) {
	const content = ".base: &base\n  script: &commands [echo inherited, echo again]\n  variables: {INHERITED: yes, OWN: original}\nalias: *base\nmerge:\n  <<: *base\n  variables: {OWN: child}\nwrapped:\n  script: [*commands]\nwrapped_ref:\n  script: [!reference [.base, script]]\n.rule: &rule {when: manual, allow_failure: true}\nrule_job:\n  script: echo rules\n  rules:\n    - <<: *rule\n      when: always\n"
	out, err := (&cicd.Parser{}).ParseOutput(context.Background(), []byte(content), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	file := &model.FileMetadata{Kind: model.KindYAML, FilePath: ".gitlab-ci.yml", OriginalData: content, Document: out.Documents[0], LineInfoDocument: out.Documents[0], LineOverlay: out.Sources[0].LineOverlay, DocumentDialect: out.Sources[0].Dialect}
	for _, tc := range []struct {
		keys []string
		line int
	}{
		{[]string{"alias", "script", "0"}, 4},
		{[]string{"alias", "variables", "INHERITED"}, 4},
		{[]string{"merge", "script", "0"}, 6},
		{[]string{"merge", "variables", "OWN"}, 7},
		{[]string{"wrapped", "script", "1"}, 9},
		{[]string{"wrapped_ref", "script", "1"}, 11},
		{[]string{"rule_job", "rules", "0", "when"}, 17},
		{[]string{"rule_job", "rules", "0", "allow_failure"}, 16},
	} {
		require.Equal(t, tc.line, GetLineBySearchLine(tc.keys, file), tc.keys)
		path := make(model.SourcePath, len(tc.keys))
		for i, key := range tc.keys {
			if index, err := strconv.Atoi(key); err == nil {
				path[i] = model.PathSegment{Index: index, IsIndex: true}
			} else {
				path[i] = model.PathSegment{Key: key}
			}
		}
		lines, err := NewDetectLine(0).DetectPath(context.Background(), file, path)
		require.NoError(t, err, tc.keys)
		require.Equal(t, tc.line, lines.Line, tc.keys)
	}
}

// Compiled provenance follows the same typed-path contract as written source:
// final missing properties locate their parent; invalid traversal is an error.
func TestGitLabStructuredLocationPathContract(t *testing.T) {
	text := "job:\n  script: [echo first]\n  variables: {'0': numeric}\n"
	out, err := (&cicd.Parser{}).ParseOutput(t.Context(), []byte(text), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	file := &model.FileMetadata{Kind: model.KindYAML, FilePath: ".gitlab-ci.yml", OriginalData: text, Document: out.Documents[0], LineOverlay: out.Sources[0].LineOverlay}
	for _, tc := range []struct {
		name    string
		path    model.SourcePath
		invalid bool
	}{
		{"array index", model.SourcePath{{Key: "job"}, {Key: "script"}, {IsIndex: true, Index: 0}}, false},
		{"numeric mapping key", model.SourcePath{{Key: "job"}, {Key: "variables"}, {Key: "0"}}, false},
		{"missing final property", model.SourcePath{{Key: "job"}, {Key: "variables"}, {Key: "absent"}}, false},
		{"index on mapping", model.SourcePath{{Key: "job"}, {Key: "variables"}, {IsIndex: true, Index: 0}}, true},
		{"key on array", model.SourcePath{{Key: "job"}, {Key: "script"}, {Key: "0"}}, true},
		{"index out of bounds", model.SourcePath{{Key: "job"}, {Key: "script"}, {IsIndex: true, Index: 3}}, true},
		{"missing intermediate", model.SourcePath{{Key: "job"}, {Key: "absent"}, {Key: "child"}}, true},
		{"scalar intermediate", model.SourcePath{{Key: "job"}, {Key: "script"}, {IsIndex: true, Index: 0}, {Key: "child"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDetectLine(0).DetectPath(t.Context(), file, tc.path)
			if tc.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	for _, root := range []string{"include: [ci/jobs.yml]\n", "include: [ci/jobs.yml]\n# root\n# unrelated\n# unrelated\n"} {
		included := "job:\n  script:\n    # contributing source\n    - echo included\n"
		fsys := vfs.NewMemFS(map[string][]byte{".gitlab-ci.yml": []byte(root), "ci/jobs.yml": []byte(included)})
		out, err := (&cicd.Parser{FS: fsys}).ParseOutput(t.Context(), []byte(root), ".gitlab-ci.yml", false, 15)
		require.NoError(t, err)
		file := &model.FileMetadata{Kind: model.KindYAML, FilePath: ".gitlab-ci.yml", OriginalData: root, Document: out.Documents[0], LineOverlay: out.Sources[0].LineOverlay}
		path := model.SourcePath{{Key: "job"}, {Key: "script"}, {IsIndex: true, Index: 0}}
		lines, err := NewDetectLine(0).DetectPath(t.Context(), file, path)
		require.NoError(t, err)
		require.Equal(t, 4, lines.Line)
		require.Equal(t, filepath.FromSlash("ci/jobs.yml"), lines.ResolvedFile)
		require.Contains(t, lines.LineWithVulnerability, "echo included")
		_, err = NewDetectLine(0).DetectPath(t.Context(), file, append(path, model.PathSegment{Key: "invalid"}))
		require.Error(t, err)
	}
}

func TestGitLabUnflattenedAliasLocations(t *testing.T) {
	text := ".db: &db {name: postgres}\njob:\n  script: echo ok\n  services:\n    - *db\n"
	out, err := (&cicd.Parser{}).ParseOutput(t.Context(), []byte(text), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	file := &model.FileMetadata{Kind: model.KindYAML, FilePath: ".gitlab-ci.yml", OriginalData: text, Document: out.Documents[0], LineInfoDocument: out.Documents[0], LineOverlay: out.Sources[0].LineOverlay}
	keys := []string{"job", "services", "0", "name"}
	require.Equal(t, 5, GetLineBySearchLine(keys, file))
	path := model.SourcePath{{Key: "job"}, {Key: "services"}, {Index: 0, IsIndex: true}, {Key: "name"}}
	lines, err := NewDetectLine(0).DetectPath(t.Context(), file, path)
	require.NoError(t, err)
	require.Equal(t, 5, lines.Line)
}

func TestGitLabMixedListSourceLocations(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, entry string
		first, group, last  int
	}{
		{"alias", ".commands: &commands [echo a, echo b]\n", "*commands", 4, 5, 6},
		{"reference", "include: [ci/commands.yml]\n", "!reference [.commands, script]", 4, 5, 6},
		{"input", "spec:\n  inputs:\n    commands: {type: array, default: [echo a, echo b]}\n---\n", "'$[[ inputs.commands ]]'", 7, 8, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.prefix + "job:\n  script:\n    - echo first\n    - " + tc.entry + "\n    - echo last\n"
			fsys := vfs.NewMemFS(map[string][]byte{".gitlab-ci.yml": []byte(text), "ci/commands.yml": []byte(".commands:\n  script:\n    - echo a\n    - echo b\n")})
			out, err := (&cicd.Parser{FS: fsys}).ParseOutput(t.Context(), []byte(text), ".gitlab-ci.yml", false, 15)
			require.NoError(t, err)
			index := len(out.Documents) - 1
			positions := out.Sources[index].LineOverlay
			for command, line := range []int{tc.first, tc.group, tc.group, tc.last} {
				position := positions.LookupSource([]string{"job", "script", strconv.Itoa(command)})
				require.Equal(t, line, position.Line)
				require.Equal(t, ".gitlab-ci.yml", position.Snapshot.Path)
			}
		})
	}
}

func TestGitLabLegacyCompiledSelectors(t *testing.T) {
	root := "include: [ci/jobs.yml]\n"
	included := "build:\n  image: alpine:latest\n  script:\n    - echo first\n    - echo selected\n  variables:\n    MODE: prod\n    'a=b': literal\n_parsed_build:\n  script: echo named\n  image: busybox:latest\n_dd_job:\n  script: echo named\n  image: ubuntu:latest\n"
	included = strings.Replace(included, "'a=b': literal", "'a=b': {nested: literal}", 1)
	included += "registryjob:\n  image: registry.example.invalid/team/app:latest\n  script: echo registry\n"
	files := map[string][]byte{".gitlab-ci.yml": []byte(root), "ci/jobs.yml": []byte(included)}
	out, err := (&cicd.Parser{FS: vfs.NewMemFS(files)}).ParseOutput(t.Context(), []byte(root), ".gitlab-ci.yml", false, 15)
	require.NoError(t, err)
	file := &model.FileMetadata{Kind: model.KindYAML, FilePath: ".gitlab-ci.yml", OriginalData: root, Document: out.Documents[0], LineOverlay: out.Sources[0].LineOverlay}
	for _, tc := range []struct {
		key  string
		line int
	}{
		{"image={{alpine:latest}}", 2},
		{"build.image={{alpine:latest}}", 2},
		{"build.image=alpine:latest", 2},
		{`build.variables["MODE"]`, 7},
		{"build.variables.{{MODE}}", 7},
		{`build.variables["a=b"]`, 8},
		{"build.variables.a=b", 8},
		{"build.variables.a=b.nested", 8},
		{"script={{echo selected}}", 5},
		{"build.script[1]", 5},
		{"image={{busybox:latest}}", 11},
		{"image={{ubuntu:latest}}", 14},
		{"registryjob.image=registry.example.invalid/team/app:latest", 16},
		{"registryjob.image={{registry.example.invalid/team/app:latest}}", 16},
		{"image=registry.example.invalid/team/app:latest", 16},
	} {
		t.Run(tc.key, func(t *testing.T) {
			lines := NewDetectLine(0).DetectLine(t.Context(), file, tc.key)
			require.Equal(t, tc.line, lines.Line)
			require.Equal(t, filepath.FromSlash("ci/jobs.yml"), lines.ResolvedFile)
		})
	}
}
