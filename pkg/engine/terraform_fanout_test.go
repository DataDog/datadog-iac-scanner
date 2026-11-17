/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

const fanoutRoot = `resource "aws_security_group" "sg" {
  name = "sg"
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`

// fanoutRoots models roots a and b with the same content and root c with
// another one.
func fanoutRoots(t *testing.T) map[string]*terraformRoot {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"a/main.tf": fanoutRoot, "b/main.tf": fanoutRoot, "c/main.tf": `resource "aws_s3_bucket" "b" {}`}
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := tfmodel.Load(context.Background(), dir, &tfmodel.Options{})
	require.NoError(t, err)
	out := map[string]*terraformRoot{}
	for _, r := range scan.Roots {
		proj := project.Project([]*tfmodel.Root{r}, project.Options{Placeholder: resultsTestPlaceholder})
		out[filepath.Base(r.Dir)] = &terraformRoot{root: r, input: &terraformInput{projection: proj}}
	}
	require.Len(t, out, 3)
	return out
}

func blockIDOf(t *testing.T, r *terraformRoot, typ string) string {
	t.Helper()
	for id, loc := range r.input.projection.Blocks {
		if loc.Type == typ {
			return id
		}
	}
	t.Fatalf("no %s block in root %s", typ, r.root.ID)
	return ""
}

// Roots with the same content are evaluated once; the results of the unit are
// copied to the duplicate with its own block ids, evidence included.
func TestFanoutCopiesResultsToDuplicateRoots(t *testing.T) {
	roots := fanoutRoots(t)
	units, fan := dedupRoots(context.Background(), []*terraformRoot{roots["a"], roots["b"], roots["c"]})
	require.Len(t, units, 2)
	require.NotNil(t, fan)
	require.Same(t, roots["a"], units[0])
	require.Same(t, roots["c"], units[1])

	a, b := roots["a"], roots["b"]
	item := map[string]interface{}{
		blockResultField:    blockIDOf(t, a, "aws_s3_bucket"),
		"path":              []interface{}{"bucket"},
		evidenceResultField: []interface{}{[]interface{}{blockIDOf(t, a, "aws_security_group"), []interface{}{"name"}}},
	}
	other := map[string]interface{}{blockResultField: blockIDOf(t, roots["c"], "aws_s3_bucket")}
	blocks := map[string]*project.Located{}
	for _, r := range units {
		for id, loc := range r.input.projection.Blocks {
			blocks[id] = loc
		}
	}
	copies := fan.copies(rego.ResultSet{{Bindings: rego.Vars{"result": []interface{}{item, other}}}}, blocks)
	require.Len(t, copies, 1, "only the unit with a duplicate is copied")
	require.Same(t, b.input, copies[0].input)
	got, err := resultItems(copies[0].results)
	require.NoError(t, err)
	require.Len(t, got, 1)
	obj := got[0].(map[string]interface{})
	require.Equal(t, blockIDOf(t, b, "aws_s3_bucket"), obj[blockResultField])
	require.Equal(t, []interface{}{"bucket"}, obj["path"])
	ev := obj[evidenceResultField].([]interface{})[0].([]interface{})
	require.Equal(t, blockIDOf(t, b, "aws_security_group"), ev[0])
	require.Equal(t, blockIDOf(t, a, "aws_s3_bucket"), item[blockResultField], "the unit's result is left as is")
}

func TestDedupRootsKeepsDistinctRoots(t *testing.T) {
	roots := fanoutRoots(t)
	units, fan := dedupRoots(context.Background(), []*terraformRoot{roots["a"], roots["c"]})
	require.Nil(t, fan)
	ids := []string{units[0].root.ID, units[1].root.ID}
	sort.Strings(ids)
	require.Equal(t, []string{roots["a"].root.ID, roots["c"].root.ID}, ids)
	single, fan := dedupRoots(context.Background(), []*terraformRoot{roots["b"]})
	require.Nil(t, fan)
	require.Len(t, single, 1)
}
