/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfproperties

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/stretchr/testify/require"
)

// goldenGrids assembles the value cells the legacy-document goldens cover:
// the expansion grid (instances, modules, nested modules) and a sample of
// the value grid that rotates through the indirections. The attribute-state
// cells are materialized separately, from their own type.
func goldenGrids() []tfcorpus.Cell {
	cells := tfcorpus.ExpansionGrid()
	cells = append(cells, tfcorpus.CellsSample(tfcorpus.ValueGrid(), 13)...)
	return cells
}

// updateEnv names the directory an explicit run writes fresh goldens to.
const updateEnv = "TFGOLDEN_UPDATE"

// TestLegacyDocumentsMatchThePreviousEngine checks that the legacy documents
// the engine rebuilds from its model match what the previous engine parsed,
// cell by cell, over the golden grids. The committed goldens were produced
// by a build of the previous engine (see testdata/legacy_golden/README.md).
// Where the two builds differ on purpose, the intendedDifferences table
// below names the cell and document path and says why; a difference without
// an entry fails, and an entry that matches nothing fails, so the table can
// only shrink.
func TestLegacyDocumentsMatchThePreviousEngine(t *testing.T) {
	cells := goldenGrids()
	dir, names := tfcorpus.Materialize(t, cells)

	dump := map[string]any{}
	for i := range cells {
		root := filepath.Join(dir, names[i])
		docs := legacyDocsOfRoot(t, root)
		dump[names[i]] = json.RawMessage(tfcorpus.NormalizeDocs(root, docs))
	}

	// The attribute-state cells carry no probe attribute; they are here for
	// the written, unknown, template, JSON and null paths.
	state := tfcorpus.StateGrid()
	stateDir, stateNames := tfcorpus.MaterializeState(t, state)
	for i := range state {
		root := filepath.Join(stateDir, stateNames[i])
		docs := legacyDocsOfRoot(t, root)
		dump[stateNames[i]] = json.RawMessage(tfcorpus.NormalizeDocs(root, docs))
	}

	goldenDir := filepath.Join("testdata", "legacy_golden")
	if out := os.Getenv(updateEnv); out != "" {
		for name, content := range dump {
			raw, ok := content.(json.RawMessage)
			require.True(t, ok)
			require.NoError(t, tfcorpus.WriteGolden(filepath.Join(out, name+".json"), raw))
		}
		t.Logf("wrote %d golden files to %s", len(dump), out)
		return
	}

	// One file per cell keeps a difference local.
	failed := 0
	for i, cell := range cells {
		path := filepath.Join(goldenDir, names[i]+".json")
		golden, err := os.ReadFile(path)
		require.NoError(t, err, "missing golden for cell %s; generate the goldens from a build of the previous engine (see testdata/legacy_golden/README.md)", cell.Name())
		actual, ok := dump[names[i]].(json.RawMessage)
		require.True(t, ok)
		if string(golden) == string(actual) {
			continue
		}
		// Collect the differing paths and require each to be intended.
		diffs := diffJSON(t, golden, []byte(actual), "")
		unintended := make([]string, 0, len(diffs))
		for _, d := range diffs {
			if intendedDifference(cell.Name(), d.path) || intendedByContent(d) {
				continue
			}
			unintended = append(unintended, d.String())
		}
		if len(unintended) > 0 {
			failed++
			if failed <= 8 {
				t.Errorf("cell %s: the legacy documents differ from the previous engine beyond the intended differences:\n%s",
					cell.Name(), strings.Join(unintended, "\n"))
			}
		}
	}
	require.Zero(t, failed, "%d cells differ from the committed goldens beyond the intended differences", failed)

	// Every intended difference must still be in force: an entry that
	// matches no current difference is stale and hides a fixed behavior.
	matched := map[int]bool{}
	for i, cell := range cells {
		path := filepath.Join(goldenDir, names[i]+".json")
		golden, err := os.ReadFile(path)
		require.NoError(t, err)
		actual, ok := dump[names[i]].(json.RawMessage)
		require.True(t, ok)
		if string(golden) == string(actual) {
			continue
		}
		for _, d := range diffJSON(t, golden, []byte(actual), "") {
			for j := range intendedDifferences {
				p := intendedDifferences[j]
				if nameMatches(p.cells, cell.Name()) && strings.HasPrefix(d.path, p.path) {
					matched[j] = true
				}
			}
		}
	}
	for j, p := range intendedDifferences {
		require.True(t, matched[j], "stale intended difference for cells %q at %q: %s", p.cells, p.path, p.why)
	}
}

// legacyDocsOfRoot loads one root and rebuilds the legacy documents the way
// the engine feeds rules written for the previous engine.
func legacyDocsOfRoot(t *testing.T, root string) []map[string]any {
	t.Helper()
	scan, err := model.Load(t.Context(), root, &model.Options{})
	require.NoError(t, err)
	return docMaps(project.LegacyDocs(scan.Roots, project.LegacyOptions{
		Base:        root,
		Placeholder: value.NewPlaceholder(),
		FileID:      func(string) (string, bool) { return "doc", true },
	}))
}

// docMaps keeps the document bodies of the rebuilt legacy documents.
func docMaps(docs []*project.LegacyDoc) []map[string]any {
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Doc)
	}
	return out
}

// difference is one differing path between two JSON documents.
type difference struct {
	path string
	want string // what the previous engine produced
	got  string // what this engine produces
}

func (d difference) String() string {
	return fmt.Sprintf("%s\n  previous engine: %s\n  this engine:     %s", d.path, d.want, d.got)
}

// diffJSON walks two JSON documents and records every differing path.
func diffJSON(t *testing.T, want, got []byte, prefix string) []difference {
	t.Helper()
	var w, g any
	require.NoError(t, json.Unmarshal(want, &w))
	require.NoError(t, json.Unmarshal(got, &g))
	var out []difference
	var walk func(w, g any, path string)
	walk = func(w, g any, path string) {
		if fmt.Sprint(w) == fmt.Sprint(g) {
			bw, _ := json.Marshal(w)
			bg, _ := json.Marshal(g)
			if string(bw) == string(bg) {
				return
			}
		}
		wm, wObj := w.(map[string]any)
		gm, gObj := g.(map[string]any)
		if wObj && gObj {
			keys := map[string]bool{}
			for k := range wm {
				keys[k] = true
			}
			for k := range gm {
				keys[k] = true
			}
			sorted := make([]string, 0, len(keys))
			for k := range keys {
				sorted = append(sorted, k)
			}
			sort.Strings(sorted)
			for _, k := range sorted {
				walk(wm[k], gm[k], path+"/"+k)
			}
			return
		}
		wa, wArr := w.([]any)
		ga, gArr := g.([]any)
		if wArr && gArr {
			n := len(wa)
			if len(ga) > n {
				n = len(ga)
			}
			for i := 0; i < n; i++ {
				var wi, gi any
				if i < len(wa) {
					wi = wa[i]
				}
				if i < len(ga) {
					gi = ga[i]
				}
				walk(wi, gi, fmt.Sprintf("%s/%d", path, i))
			}
			return
		}
		bw, _ := json.Marshal(w)
		bg, _ := json.Marshal(g)
		out = append(out, difference{path: path, want: string(bw), got: string(bg)})
	}
	walk(w, g, prefix)
	return out
}

// intendedDifference reports whether a differing path of a cell is one the
// rebuild changes on purpose.
func intendedDifference(cell, path string) bool {
	for _, p := range intendedDifferences {
		if nameMatches(p.cells, cell) && strings.HasPrefix(path, p.path) {
			return true
		}
	}
	return false
}

// intendedByContent recognizes the two differences that are the rebuild
// working as designed wherever they appear:
//
//   - the previous engine left an expression it could not resolve as its
//     "${...}" source text; this engine's evaluator resolves the
//     indirection, so a value the previous engine left as "${...}" may read
//     as anything;
//   - the previous engine kept count and for_each meta-arguments in the
//     documents; this engine removes meta-arguments, so the entry
//     disappears.
func intendedByContent(d difference) bool {
	if strings.HasPrefix(d.want, `"${`) {
		return true
	}
	segments := strings.Split(strings.TrimPrefix(d.path, "/"), "/")
	last := segments[len(segments)-1]
	return d.got == "null" && (last == "count" || last == "for_each")
}

// nameMatches reports whether a cell-name pattern matches. A pattern is a
// slash-joined list of axis=value terms; a term matches when the cell name
// carries the same axis and value, and an absent axis matches anything.
func nameMatches(pattern, cell string) bool {
	if pattern == "" {
		return true
	}
	for _, term := range strings.Split(pattern, "/") {
		if term == "" {
			continue
		}
		if !strings.Contains(cell, term) {
			return false
		}
	}
	return true
}

// intendedDifferences lists the differences between the previous engine's
// documents and the rebuilt ones that are the rebuild working as designed.
// cells selects the cells a difference applies to ("" matches every cell);
// path is the document path prefix; why says, in plain words, what changed
// and why.
var intendedDifferences = []struct {
	cells, path, why string
}{
	{
		cells: "expansion=count1/block=resource",
		path:  "/sink.tf/0/resource/aws_s3_bucket/sink",
		why: "a counted block is one entry per instance, keyed by the instance " +
			"('sink[0]'), with the meta-arguments removed; the previous engine kept one " +
			"entry named after the block, carrying the count",
	},
	{
		cells: "expansion=count3/block=resource",
		path:  "/sink.tf/0/resource/aws_s3_bucket/sink",
		why:   "as for count1: one entry per instance, meta-arguments removed",
	},
	{
		cells: "expansion=count258/block=resource",
		path:  "/sink.tf/0/resource/aws_s3_bucket/sink",
		why: "the previous engine stopped expanding count past its cap of 256 instances; " +
			"this engine expands every instance, so the documents hold all 258",
	},
	{
		cells: "expansion=count1/block=data",
		path:  "/sink.tf/0/data/aws_s3_bucket/sink",
		why:   "as for count1: one entry per instance, meta-arguments removed",
	},
	{
		cells: "expansion=count1/block=ephemeral",
		path:  "/sink.tf/0/ephemeral/aws_s3_bucket/sink",
		why: "the meta-arguments are removed from the documents; the ephemeral block " +
			"itself is evaluated as written",
	},
	{
		cells: "expansion=foreach_map/block=resource",
		path:  "/sink.tf/0/resource/aws_s3_bucket/sink",
		why: "a for_each block is one entry per instance, keyed by the instance key, " +
			"with each.value resolved; the previous engine kept one entry carrying the " +
			"for_each and the each.value expression text",
	},
	{
		cells: "expansion=foreach_set/block=resource",
		path:  "/sink.tf/0/resource/aws_s3_bucket/sink",
		why:   "as for foreach_map: one entry per instance, each.value resolved",
	},
	{
		cells: "expansion=foreach_set/block=data",
		path:  "/sink.tf/0/data/aws_s3_bucket/sink",
		why:   "as for foreach_map: one entry per instance, each.value resolved",
	},
	{
		cells: "expansion=foreach_set/block=ephemeral",
		path:  "/sink.tf/0/ephemeral/aws_s3_bucket/sink",
		why:   "the meta-arguments are removed from the documents",
	},
	{
		cells: "kind=count",
		path:  "/sink.tf/0/resource/aws_s3_bucket/sink",
		why:   "as for the counted blocks: one entry per instance, meta-arguments removed",
	},
	{
		cells: "kind=for_each",
		path:  "/sink.tf/0/resource/aws_s3_bucket/sink",
		why:   "as for the for_each blocks: one entry per instance, each.value resolved",
	},
	{
		cells: "kind=local",
		path:  "/locals.tf/0/locals",
		why: "a file may declare locals blocks more than once; the documents report one " +
			"locals entry per file, so repeated blocks merge",
	},
	{
		cells: "kind=module_io",
		path:  "/main.tf/0/module",
		why: "a call to a local module is evaluated through the module's own documents; " +
			"reporting the call too would flag one problem twice, so the call is not a block " +
			"of the written file's document",
	},
	{
		cells: "kind=module_sink",
		path:  "/main.tf/0/module",
		why:   "as for module calls generally: the call is not a block of the written file",
	},
	{
		cells: "kind=module_io",
		path:  "/neighbor.tf/0/module",
		why:   "as for module calls generally: a second call of the same module is not a block either",
	},
	{
		cells: "kind=module_sink",
		path:  "/neighbor.tf/0/module",
		why:   "as for module calls generally: a second call of the same module is not a block either",
	},
	{
		cells: "kind=module_sink",
		path:  "/mod/main.tf",
		why: "the written file of a module keeps the module body as written, with the " +
			"expressions the written file cannot answer left as their source text; each " +
			"evaluated module instance is a document of its own, with the values resolved",
	},
	{
		cells: "block=module",
		path:  "",
		why: "the blocks of a module instance are one document per instance, so each call " +
			"is evaluated and attributed separately; the previous engine wrote the module's " +
			"blocks onto the document of the written file",
	},
}
