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
// the expansion grid (instances, modules, nested modules), a sample of the
// value grid that rotates through the indirections, and the composed pairs.
// The attribute-state cells are materialized separately, from their own
// type. It must match the cell selection of the golden generator command.
func goldenGrids() []tfcorpus.Cell {
	cells := tfcorpus.ExpansionGrid()
	cells = append(cells, tfcorpus.CellsSample(tfcorpus.ValueGrid(), 13)...)
	cells = append(cells, tfcorpus.PairGrid()...)
	return cells
}

// updateEnv names the directory an explicit run writes fresh goldens to.
const updateEnv = "TFGOLDEN_UPDATE"

// markPlaceholder substitutes the run's placeholder in a rebuilt document
// with a stable marker, so the comparison carries no random value. It is
// assigned at the start of the test.
var markPlaceholder func(content []byte, placeholder string) []byte

// transformCount counts the applications of each exact transformation, so
// the test can require every one of them to have changed a baseline.
var transformCount = map[string]int{}

// TestLegacyDocumentsMatchThePreviousEngine checks that the legacy documents
// the engine rebuilds from its model match what the previous engine parsed,
// cell by cell, over the golden grids. The committed goldens were produced
// by a build of the previous engine (see testdata/legacy_golden/README.md).
//
// Where the two builds differ on purpose, the exact transformations below
// rewrite the previous engine's documents into what this engine must
// produce, and the comparison against the rebuild is exact: a difference
// the transformations do not produce fails, and a transformation that
// changes no baseline anywhere is stale and fails.
func TestLegacyDocumentsMatchThePreviousEngine(t *testing.T) {
	markPlaceholder = func(content []byte, placeholder string) []byte {
		escaped := strings.ReplaceAll(placeholder, "\u0000", `\u0000`)
		out := strings.ReplaceAll(string(content), placeholder, "\u0000PH")
		return []byte(strings.ReplaceAll(out, escaped, `\u0000PH`))
	}

	cells := goldenGrids()
	dir, names := tfcorpus.Materialize(t, cells)

	type dumped struct {
		raw     json.RawMessage
		cell    tfcorpus.Cell
		state   tfcorpus.StateCell
		isState bool
	}
	dump := map[string]dumped{}
	for i := range cells {
		root := filepath.Join(dir, names[i])
		docs, ph := legacyDocsOfRoot(t, root)
		dump[names[i]] = dumped{raw: json.RawMessage(markPlaceholder(tfcorpus.NormalizeDocs(root, docs), ph)), cell: cells[i]}
	}

	// The attribute-state cells carry no probe attribute; they are here for
	// the written, unknown, template, JSON and null paths.
	state := tfcorpus.StateGrid()
	stateDir, stateNames := tfcorpus.MaterializeState(t, state)
	placeholders := map[string]string{}
	for i := range state {
		root := filepath.Join(stateDir, stateNames[i])
		docs, ph := legacyDocsOfRoot(t, root)
		placeholders[stateNames[i]] = ph
		dump[stateNames[i]] = dumped{
			raw:   json.RawMessage(markPlaceholder(tfcorpus.NormalizeDocs(root, docs), ph)),
			state: state[i], isState: true,
		}
	}

	goldenDir := filepath.Join("testdata", "legacy_golden")
	if out := os.Getenv(updateEnv); out != "" {
		for name, d := range dump {
			require.NoError(t, tfcorpus.WriteGolden(filepath.Join(out, name+".json"), d.raw))
		}
		t.Logf("wrote %d golden files to %s", len(dump), out)
		return
	}

	// The committed goldens are exactly the dumped cells: none missing,
	// none extra.
	onDisk := map[string]bool{}
	entries, err := os.ReadDir(goldenDir)
	require.NoError(t, err)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			onDisk[strings.TrimSuffix(e.Name(), ".json")] = true
		}
	}
	for name := range dump {
		require.True(t, onDisk[name], "no committed golden for cell %s; generate the goldens from a build of the previous engine (see testdata/legacy_golden/README.md)", name)
	}
	for name := range onDisk {
		_, ok := dump[name]
		require.True(t, ok, "the committed golden %s.json matches no generated cell; regenerate the goldens", name)
	}

	failed := 0
	for name, d := range dump {
		golden, err := os.ReadFile(filepath.Join(goldenDir, name+".json"))
		require.NoError(t, err)
		var expected []byte
		if d.isState {
			expected = transformStateGolden(t, d.state, golden, placeholders[name])
		} else {
			expected = transformGolden(t, d.cell, golden)
		}
		if string(expected) != string(d.raw) {
			failed++
			if failed <= 8 {
				diffs := diffJSON(t, expected, []byte(d.raw), "")
				messages := make([]string, 0, len(diffs))
				for _, diff := range diffs {
					messages = append(messages, diff.String())
				}
				t.Errorf("cell %s: the legacy documents differ from the exact transformation of the previous engine's documents:\n%s",
					name, strings.Join(messages, "\n"))
			}
		}
	}
	require.Zero(t, failed, "%d cells differ from the transformed goldens", failed)

	// Every transformation must have changed a baseline somewhere: one that
	// changed nothing is stale and hides a fixed behavior.
	for _, class := range []string{"dropModuleCalls", "splitModuleDoc", "rekeySink", "dropBlockMetaArgs", "resolveChain", "mergeLocals", "repeatModuleDocs", "stateRekey", "stateNull", "stateUnknownCount", "stateDynamic", "stateUnknownRender"} {
		require.NotZero(t, transformCount[class],
			"the exact transformation %q changed no baseline; it is stale", class)
	}
}

// legacyDocsOfRoot loads one root and rebuilds the legacy documents the way
// the engine feeds rules written for the previous engine. It also returns
// the placeholder the rebuild used.
func legacyDocsOfRoot(t *testing.T, root string) ([]map[string]any, string) {
	t.Helper()
	placeholder := value.NewPlaceholder()
	scan, err := model.Load(t.Context(), root, &model.Options{})
	require.NoError(t, err)
	docs := project.LegacyDocs(scan.Roots, project.LegacyOptions{
		Base:        root,
		Placeholder: placeholder,
		FileID:      func(string) (string, bool) { return "doc", true },
	})
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Doc)
	}
	return out, placeholder
}

// transformGolden applies the exact transformations the rebuild makes on
// purpose to one value cell's previous-engine documents.
func transformGolden(t *testing.T, cell tfcorpus.Cell, golden []byte) []byte {
	t.Helper()
	var byFile map[string][]map[string]any
	require.NoError(t, json.Unmarshal(golden, &byFile))
	probeValue := cell.ExpectedProbeValue()
	fileNames := make([]string, 0, len(byFile))
	for f := range byFile {
		fileNames = append(fileNames, f)
	}
	sort.Strings(fileNames)
	for _, f := range fileNames {
		docs := byFile[f]
		// A call to a local module is evaluated through the module's own
		// documents; the call itself is not a block of the written file's
		// document. A mod file keeps the calls it declares.
		if hasModuleCalls(cell) && !strings.Contains(f, "/") {
			for _, doc := range docs {
				if _, ok := doc["module"]; ok {
					delete(doc, "module")
					transformCount["dropModuleCalls"]++
				}
			}
		}
		// A mod file that carries the module's blocks and its variables in
		// one document splits into one document each.
		if strings.HasPrefix(f, "mod/") && len(docs) == 1 {
			doc := docs[0]
			resource, hasResource := doc["resource"]
			variable, hasVariable := doc["variable"]
			if hasResource && hasVariable {
				byFile[f] = []map[string]any{
					{"file": doc["file"], "resource": resource},
					{"file": doc["file"], "variable": variable},
				}
				docs = byFile[f]
				transformCount["splitModuleDoc"]++
			}
		}
		// One document per module instance: the mod file's block documents
		// repeat once per instance.
		if n := moduleDocCopies(cell, f); n > 1 {
			var repeated []map[string]any
			for i := 0; i < n; i++ {
				repeated = append(repeated, docs...)
			}
			byFile[f] = repeated
			docs = repeated
			transformCount["repeatModuleDocs"]++
		}
		for _, doc := range docs {
			if rekeysSink(cell) {
				if rekeySinkEntry(cell, doc, probeValue) {
					transformCount["rekeySink"]++
				}
			}
			if dropBlockMetaArgs(doc) {
				transformCount["dropBlockMetaArgs"]++
			}
			if resolveChain(cell, doc, probeValue) {
				transformCount["resolveChain"]++
			}
			_ = tryObjectProbe
			if tryObjectProbe(cell) {
				// The previous engine's try over the whole object fell back
				// to the literal; the rebuild keeps the object itself.
				if resource, ok := doc["resource"].(map[string]any); ok {
					if byName, ok := resource["aws_s3_bucket"].(map[string]any); ok {
						if entry, ok := byName["sink"].(map[string]any); ok {
							if _, isObj := entry["probe"].(map[string]any); isObj {
								entry["probe"] = probeValue
								transformCount["resolveChain"]++
							}
						}
					}
				}
			}
			if mergeLocals(doc) {
				transformCount["mergeLocals"]++
			}
			// The unknown rendering walks from each block entry: a wholly
			// unknown attribute of an entry keeps its source text, one
			// nested inside a known value renders as the placeholder.
			walkBlockEntries(doc, func(entry map[string]any) {
				if renderUnknowns(entry, "\u0000PH", 0) {
					transformCount["stateUnknownRender"]++
				}
			})
		}
	}
	return tfcorpus.NormalizeDocs(".", flatten(byFile))
}

// tryObjectProbe reports whether the cell's try reads a whole object: the
// previous engine fell back to the literal object, the rebuild keeps the
// object itself.
func tryObjectProbe(c tfcorpus.Cell) bool {
	return c.Indirection == "try" && (c.Source == "resource_object" || c.Source == "lookalike")
}

// walkBlockEntries visits every block entry of a document.
func walkBlockEntries(doc map[string]any, visit func(map[string]any)) {
	for _, section := range []string{"resource", "data", "ephemeral", "module", "variable", "output", "provider", "locals"} {
		byType, ok := doc[section].(map[string]any)
		if !ok {
			continue
		}
		for _, byNameAny := range byType {
			switch byName := byNameAny.(type) {
			case map[string]any:
				for _, entryAny := range byName {
					if entry, ok := entryAny.(map[string]any); ok {
						visit(entry)
					}
				}
			case []any:
				for _, entryAny := range byName {
					if entry, ok := entryAny.(map[string]any); ok {
						visit(entry)
					}
				}
			}
		}
	}
}

// transformStateGolden applies the exact transformations the rebuild makes
// on purpose to one state cell's previous-engine documents.
func transformStateGolden(t *testing.T, cell tfcorpus.StateCell, golden []byte, placeholder string) []byte {
	t.Helper()
	var byFile map[string][]map[string]any
	require.NoError(t, json.Unmarshal(golden, &byFile))
	fileNames := make([]string, 0, len(byFile))
	for f := range byFile {
		fileNames = append(fileNames, f)
	}
	sort.Strings(fileNames)
	for _, f := range fileNames {
		for _, doc := range byFile[f] {
			// A call to a local module is not a block of the written file;
			// a mod file keeps the calls it declares.
			if _, ok := doc["module"]; ok && !strings.Contains(f, "mod/") {
				delete(doc, "module")
				transformCount["dropModuleCalls"]++
			}
			// A mod file that carries the module's blocks and its variables
			// in one document splits into one document each.
			if strings.HasPrefix(f, "mod/") && len(byFile[f]) == 1 {
				if resource, okR := doc["resource"]; okR {
					if variable, okV := doc["variable"]; okV {
						byFile[f] = []map[string]any{
							{"file": doc["file"], "resource": resource},
							{"file": doc["file"], "variable": variable},
						}
						transformCount["splitModuleDoc"]++
					}
				}
			}
			walkBlockEntries(doc, func(entry map[string]any) {
				if renderUnknowns(entry, "\u0000PH", 0) {
					transformCount["stateUnknownRender"]++
				}
			})
			// The sink entry of the state cell.
			if resource, ok := doc["resource"].(map[string]any); ok {
				if byName, ok := resource["aws_s3_bucket"].(map[string]any); ok {
					if entry, ok := byName["sink"].(map[string]any); ok {
						if cell.Placement == "module" && cell.State == "known" {
							// The module input carries the state's value.
							if s, ok := entry["attr"].(string); ok && strings.HasPrefix(s, "${") {
								entry["attr"] = "value"
							}
						}

						if cell.Placement == "instance" && cell.State != "absent" {
							// One entry per instance, the for_each
							// meta-argument removed.
							attr := entry["attr"]
							delete(byName, "sink")
							byName[`sink["one"]`] = map[string]any{"attr": attr}
							byName[`sink["two"]`] = map[string]any{"attr": attr}
							if cell.State == "known" {
								byName[`sink["one"]`] = map[string]any{"attr": "x"}
								byName[`sink["two"]`] = map[string]any{"attr": "y"}
							}
							transformCount["stateRekey"]++
						} else {
							transformStateSink(cell, entry, "\u0000PH")
						}
					}
				}
			}
		}
	}
	return tfcorpus.NormalizeDocs(".", flatten(byFile))
}

// transformStateSink edits one state cell's sink entry to the exact rebuilt
// content, for the states the generic walks do not cover.
func transformStateSink(cell tfcorpus.StateCell, entry map[string]any, marker string) {
	switch cell.State {
	case "null":
		// A null attribute is absent from the documents.
		delete(entry, "attr")
		if settings, ok := entry["settings"].(map[string]any); ok {
			delete(settings, "attr")
		}
		transformCount["stateNull"]++
	case "unknown_count":
		delete(entry, "count")
		transformCount["stateUnknownCount"]++
	case "unknown_dynamic":
		// An unknown dynamic block is one unknown element.
		for k := range entry {
			delete(entry, k)
		}
		entry["d"] = []any{marker}
		transformCount["stateDynamic"]++
	case "template":
		// A template inside a nested block renders wholly as the
		// placeholder; at the top level its known parts stay.
		if cell.Placement == "nested" {
			if settings, ok := entry["settings"].(map[string]any); ok {
				settings["attr"] = marker
			}
		}
	case "json":
		// A JSON document carries the escaped placeholder.
		entry["attr"] = `{"k":"` + strings.ReplaceAll(marker, "\u0000", `\u0000`) + `"}`
	}
}

// hasModuleCalls reports whether the cell declares local module calls whose
// sections the rebuilt documents drop from the root files.
func hasModuleCalls(c tfcorpus.Cell) bool {
	if c.SinkKind == "module" {
		return true
	}
	switch c.Indirection {
	case "module_io", "module_sink":
		return true
	}
	return strings.Contains(c.Indirection, "module_io")
}

// moduleDocCopies is the number of documents a mod file holds per module
// instance, or 0 when the cell has no module instances.
func moduleDocCopies(c tfcorpus.Cell, file string) int {
	if !strings.HasPrefix(file, "mod/") || c.SinkKind != "module" {
		return 0
	}
	if n := expansionCount(c); n > 0 {
		return n
	}
	return 1
}

// expansionCount is the number of instances the cell's sink expands to, or
// 0 when the cell does not expand its sink.
func expansionCount(c tfcorpus.Cell) int {
	switch c.Expansion {
	case "count1":
		return 1
	case "count3":
		return 3
	case "count258":
		return 258
	case "foreach_map":
		return 2
	case "foreach_set":
		return 1
	case "foreach_set3":
		return 3
	case "module_count":
		return 1
	case "module_count3":
		return 3
	case "module_foreach":
		return 2
	}
	return 0
}

// rekeysSink reports whether the cell's unexpanded sink entry becomes
// per-instance entries in the rebuilt documents.
func rekeysSink(c tfcorpus.Cell) bool {
	if expansionCount(c) > 0 && (c.SinkKind == "resource" || c.SinkKind == "data") {
		return true
	}
	switch c.Indirection {
	case "count", "for_each", "data_count":
		return true
	}
	return false
}

// instanceKeys is the entry key of each instance the re-keying writes.
func instanceKeys(c tfcorpus.Cell) []string {
	switch c.Expansion {
	case "count1", "count3", "count258":
		n := expansionCount(c)
		keys := make([]string, n)
		for i := 0; i < n; i++ {
			keys[i] = fmt.Sprintf("sink[%d]", i)
		}
		return keys
	case "foreach_map":
		return []string{`sink["one"]`, `sink["two"]`}
	case "foreach_set":
		return []string{`sink["k"]`}
	case "foreach_set3":
		return []string{`sink["k1"]`, `sink["k2"]`, `sink["k3"]`}
	}
	switch c.Indirection {
	case "count", "data_count":
		return []string{"sink[0]"}
	case "for_each":
		return []string{`sink["fire"]`}
	}
	return nil
}

// rekeySinkEntry replaces a counted or for_each sink entry with one entry
// per instance, meta-arguments removed and each.value resolved.
func rekeySinkEntry(c tfcorpus.Cell, doc map[string]any, probeValue any) bool {
	changed := false
	for _, section := range []string{"resource", "data", "ephemeral"} {
		byType, ok := doc[section].(map[string]any)
		if !ok {
			continue
		}
		byName, ok := byType["aws_s3_bucket"].(map[string]any)
		if !ok {
			continue
		}
		entry, ok := byName["sink"].(map[string]any)
		if !ok {
			continue
		}
		keys := instanceKeys(c)
		if len(keys) == 0 {
			continue
		}
		attrs := map[string]any{}
		for k, v := range entry {
			if k == "count" || k == "for_each" {
				continue
			}
			attrs[k] = v
		}
		if s, ok := attrs["probe"].(string); ok && strings.HasPrefix(s, "${") {
			attrs["probe"] = probeValue
		}
		delete(byName, "sink")
		for _, k := range keys {
			byName[k] = attrs
		}
		changed = true
	}
	return changed
}

// dropBlockMetaArgs removes the count and for_each meta-arguments from
// every block entry.
func dropBlockMetaArgs(doc map[string]any) bool {
	changed := false
	for _, section := range []string{"resource", "data", "ephemeral"} {
		byType, ok := doc[section].(map[string]any)
		if !ok {
			continue
		}
		for _, byNameAny := range byType {
			byName, ok := byNameAny.(map[string]any)
			if !ok {
				continue
			}
			for _, entryAny := range byName {
				entry, ok := entryAny.(map[string]any)
				if !ok {
					continue
				}
				for _, meta := range []string{"count", "for_each"} {
					if _, ok := entry[meta]; ok {
						delete(entry, meta)
						changed = true
					}
				}
			}
		}
	}
	return changed
}

// resolveChain replaces the unresolved expression text of the paths the
// probe chain reads with the value they resolve to: the probe attribute of
// a sink entry, the locals a data source feeds through, and the output of
// the observed module call.
func resolveChain(c tfcorpus.Cell, doc map[string]any, probeValue any) bool {
	changed := false
	resolve := func(node map[string]any, key string) {
		if s, ok := node[key].(string); ok && strings.HasPrefix(s, "${") {
			// The empty resource object the module call carries resolves to
			// the empty object.
			if s == "${aws_instance.empty}" {
				node[key] = map[string]any{}
			} else {
				node[key] = probeValue
			}
			changed = true
		}
	}
	for _, section := range []string{"resource", "data", "ephemeral"} {
		byType, ok := doc[section].(map[string]any)
		if !ok {
			continue
		}
		for _, byNameAny := range byType {
			byName, ok := byNameAny.(map[string]any)
			if !ok {
				continue
			}
			for nameKey, entryAny := range byName {
				entry, ok := entryAny.(map[string]any)
				if !ok {
					continue
				}
				if nameKey == "sink" {
					resolve(entry, "probe")
					// The empty resource object the observed call carries.
					resolve(entry, "extraArg")
				}
				// The missing-attribute output resolves where the call's
				// input is the plain object (the read errors into the
				// fallback); an instance object answers unknown and the
				// try keeps it as the source text. The plain object is
				// the observed call's input for the lookalike source and
				// the second call's input for the resource source.
				if nameKey == "sink4" && c.Source == "lookalike" {
					resolve(entry, "probe")
				}
				if nameKey == "sink2" && c.Source == "resource_object" {
					resolve(entry, "probe")
				}
				if section == "data" {
					// The data attribute the chain feeds resolves too.
					resolve(entry, "value")
				}
			}
		}
	}
	if locals, ok := doc["locals"].(map[string]any); ok {
		if _, ok := locals["val"]; ok {
			resolve(locals, "val")
		}
	}
	if output, ok := doc["output"].(map[string]any); ok {
		if outVal, ok := output["out_val"].(map[string]any); ok {
			resolve(outVal, "value")
		}
		if outMissing, ok := output["out_missing"].(map[string]any); ok {
			if c.Source == "lookalike" {
				// The observed call's input is the plain lookalike object:
				// the missing-attribute read errors into the fallback.
				resolve(outMissing, "value")
			}
		}
	}
	return changed
}

// mergeLocals folds repeated locals blocks of one document into one entry.
func mergeLocals(doc map[string]any) bool {
	list, ok := doc["locals"].([]any)
	if !ok {
		return false
	}
	merged := map[string]any{}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range m {
			merged[k] = v
		}
	}
	doc["locals"] = merged
	return true
}

// losesFindings reports whether the cell is on the known-findings list:
// the concrete finding of its second module call turns unknown today, so
// its probe stays unresolved in the rebuilt documents.
func losesFindings(c tfcorpus.Cell) bool {
	raw, err := os.ReadFile(filepath.Join("testdata", "known_findings_lost.json"))
	if err != nil {
		return false
	}
	var known []struct {
		Cell string `json:"cell"`
	}
	if err := json.Unmarshal(raw, &known); err != nil {
		return false
	}
	for _, k := range known {
		if k.Cell == c.Name() {
			return true
		}
	}
	return false
}

// renderUnknowns walks a block entry: an unknown value nested inside a
// known one renders as the placeholder, a wholly unknown attribute keeps
// its expression source text, and a template or JSON document with unknown
// parts renders those parts as the placeholder.
func renderUnknowns(node map[string]any, marker string, depth int) bool {
	changed := false
	for k, v := range node {
		switch tv := v.(type) {
		case string:
			if !strings.Contains(tv, "${var.") {
				continue
			}
			if isWholeUnknownExpr(tv) {
				if depth >= 1 {
					node[k] = marker
					changed = true
				}
				continue
			}
			node[k] = replaceVarExprs(tv, marker)
			changed = true
		case map[string]any:
			if renderUnknowns(tv, marker, depth+1) {
				changed = true
			}
		case []any:
			for _, e := range tv {
				if m, ok := e.(map[string]any); ok {
					if renderUnknowns(m, marker, depth+1) {
						changed = true
					}
				}
			}
		}
	}
	return changed
}

// isWholeUnknownExpr reports whether a string is exactly one unknown
// variable's expression text.
func isWholeUnknownExpr(s string) bool {
	if !strings.HasPrefix(s, "${var.") || !strings.HasSuffix(s, "}") {
		return false
	}
	inner := s[2 : len(s)-1]
	return !strings.Contains(inner, "${")
}

// replaceVarExprs renders every unknown variable part of a string as the
// placeholder.
func replaceVarExprs(s, marker string) string {
	for {
		start := strings.Index(s, "${var.")
		if start < 0 {
			return s
		}
		end := strings.Index(s[start:], "}")
		if end < 0 {
			return s
		}
		s = s[:start] + marker + s[start+end+1:]
	}
}

// flatten maps the per-file documents back to the flat list NormalizeDocs
// keys by their file field.
func flatten(byFile map[string][]map[string]any) []map[string]any {
	fileNames := make([]string, 0, len(byFile))
	for f := range byFile {
		fileNames = append(fileNames, f)
	}
	sort.Strings(fileNames)
	var out []map[string]any
	for _, f := range fileNames {
		out = append(out, byFile[f]...)
	}
	return out
}

// difference is one differing path between two JSON documents.
type difference struct {
	path string
	want string // what the exact transformation produces
	got  string // what this engine produces
}

func (d difference) String() string {
	return fmt.Sprintf("%s\n  transformed baseline: %s\n  this engine:          %s", d.path, d.want, d.got)
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
		if string(bw) == string(bg) {
			return
		}
		out = append(out, difference{path: path, want: string(bw), got: string(bg)})
	}
	walk(w, g, prefix)
	return out
}
