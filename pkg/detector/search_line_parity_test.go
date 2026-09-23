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
		_, docs, _, _, err := yamlParser.Parse(ctx, content, path, false, 15)
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
