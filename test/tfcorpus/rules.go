/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfcorpus

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// ruleVariants lists the literal variants of each read: the conditions a
// rule family needs to cover every shape the read applies to. The list
// variant covers list and set cells, whose projected value is an array
// either way; the objmap variant covers cells whose value is a resource's
// attributes (the whole object, a lookalike, a merge).
var ruleVariants = map[string][]string{
	"eq":         {"scalar", "list", "map", "nested", "empty", "null", "objmap", "objmerged"},
	"membership": {"seq", "map"},
	"count":      {""},
	"index":      {"seq", "map", "objmap"},
	"helper":     {""},
	"path":       {""},
}

// ruleCondition is the Rego condition of one probe rule: it holds exactly
// when the probe attribute holds the firing value, read the rule's way.
func ruleCondition(read, variant string) string {
	switch read {
	case "eq":
		return fmt.Sprintf("b.probe == %s", eqLiteral[variant])
	case "membership":
		if variant == "map" {
			return `some k; b.probe[k] == "fire"`
		}
		return `"fire" in b.probe`
	case "count":
		return "count(b.probe) == 1"
	case "index":
		switch variant {
		case "map":
			return `b.probe.a == "fire"`
		case "objmap":
			return `b.probe.probe_source == "fire"`
		}
		return `b.probe[0] == "fire"`
	case "helper":
		return `tf.matches(b.probe, "fire")`
	case "path":
		return `b.probe.a.b == "fire"`
	}
	panic("unknown read " + read)
}

// Materialize writes one Terraform root per cell under a temporary
// directory. A root per cell keeps failures local: a scan covers the whole
// grid at once, and a failing cell names itself. It returns the directory
// and, in cell order, the name of each cell's directory under it.
func Materialize(t *testing.T, cells []Cell) (string, []string) {
	t.Helper()
	dir, names, err := MaterializeAt("", cells)
	if err != nil {
		t.Fatal(err)
	}
	return dir, names
}

// MaterializeState writes one root per state cell under a temporary
// directory, with each cell's directory name in cell order.
func MaterializeState(t *testing.T, cells []StateCell) (string, []string) {
	t.Helper()
	dir, names, err := MaterializeStateAt("", cells)
	if err != nil {
		t.Fatal(err)
	}
	return dir, names
}

// oneLabelRe matches a block header taking one quoted label (the block
// kind and its name); twoLabelRe matches one taking two (the kind, the
// resource type, and the name).
var (
	oneLabelRe = regexp.MustCompile(`(?m)^(module|variable|output)\s+"([^"]+)"\s*\{`)
	twoLabelRe = regexp.MustCompile(`(?m)^(resource|data|ephemeral)\s+"([^"]+)"\s+"([^"]+)"\s*\{`)
)

// checkLabels rejects a root that declares the same labeled block twice:
// a collision would make two cells' fixtures overlap and the findings
// unattributable. Identity is the declaring directory scope (a module
// directory holds its own scope, where the same name may repeat legally),
// the block kind, the labels, and the resource type for the two-label
// kinds. The module source does not take part: two same-name calls in one
// scope are one call whatever they point at.
func checkLabels(cell Cell) error {
	seen := map[string]string{}
	scope := func(file string) string {
		if i := strings.LastIndex(file, "/"); i >= 0 {
			return file[:i]
		}
		return ""
	}
	for name, content := range cell.files {
		dir := scope(name)
		for _, m := range oneLabelRe.FindAllStringSubmatch(content, -1) {
			key := dir + "\x00" + m[1] + " " + m[2]
			if prev, ok := seen[key]; ok {
				return fmt.Errorf("cell %s declares %s twice (%s and %s)", cell.Name(), key, prev, name)
			}
			seen[key] = name
		}
		for _, m := range twoLabelRe.FindAllStringSubmatch(content, -1) {
			key := dir + "\x00" + m[1] + " " + m[2] + " " + m[3]
			if prev, ok := seen[key]; ok {
				return fmt.Errorf("cell %s declares %s twice (%s and %s)", cell.Name(), key, prev, name)
			}
			seen[key] = name
		}
	}
	return nil
}

// localRefRe and varRefRe match references to a local or a variable in an
// expression.

// refsOf parses one Terraform file and returns the locals and variables it
// declares and the locals and variables its expressions read. The walk is
// the HCL syntax tree, so a nested object inside a locals block never looks
// like a declaration and a local after a nested object is still found.
func refsOf(content string) (declaredLocals, declaredVars, readLocals, readVars map[string]bool) {
	declaredLocals, declaredVars = map[string]bool{}, map[string]bool{}
	readLocals, readVars = map[string]bool{}, map[string]bool{}
	file, diags := hclsyntax.ParseConfig([]byte(content), "fixture.tf", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		// The materializers already reject files that do not parse; treat
		// an unreadable file as declaring and reading nothing.
		return declaredLocals, declaredVars, readLocals, readVars
	}
	for _, b := range file.Body.(*hclsyntax.Body).Blocks {
		switch b.Type {
		case "locals":
			for name, attr := range b.Body.Attributes {
				declaredLocals[name] = true
				collectRefs(attr.Expr, readLocals, readVars)
			}
		case "variable":
			for _, label := range b.Labels {
				declaredVars[label] = true
			}
		}
	}
	for _, attr := range file.Body.(*hclsyntax.Body).Attributes {
		collectRefs(attr.Expr, readLocals, readVars)
	}
	for _, b := range file.Body.(*hclsyntax.Body).Blocks {
		if b.Type == "locals" {
			continue
		}
		walkBlockExprs(b.Body, readLocals, readVars)
	}
	return declaredLocals, declaredVars, readLocals, readVars
}

// walkBlockExprs collects the references in every attribute of a block,
// recursing into nested blocks.
func walkBlockExprs(body *hclsyntax.Body, readLocals, readVars map[string]bool) {
	for _, attr := range body.Attributes {
		collectRefs(attr.Expr, readLocals, readVars)
	}
	for _, nested := range body.Blocks {
		walkBlockExprs(nested.Body, readLocals, readVars)
	}
}

// collectRefs records the local and variable names an expression reads.
func collectRefs(expr hcl.Expression, readLocals, readVars map[string]bool) {
	if expr == nil {
		return
	}
	_ = hclsyntax.VisitAll(nodeOf(expr), func(node hclsyntax.Node) hcl.Diagnostics {
		if scope, ok := node.(*hclsyntax.ScopeTraversalExpr); ok {
			switch scope.Traversal.RootName() {
			case "local":
				if len(scope.Traversal) > 1 {
					if name, ok := scope.Traversal[1].(hcl.TraverseAttr); ok {
						readLocals[name.Name] = true
					}
				}
			case "var":
				if len(scope.Traversal) > 1 {
					if name, ok := scope.Traversal[1].(hcl.TraverseAttr); ok {
						readVars[name.Name] = true
					}
				}
			}
		}
		return nil
	})
}

// scopeOf is the module directory a file declares in: the path up to its
// last separator, or the root when the file sits at the top.
func scopeOf(file string) string {
	if i := strings.LastIndex(file, "/"); i >= 0 {
		return file[:i]
	}
	return ""
}

// nodeOf adapts an expression to the syntax node interface.
func nodeOf(expr hcl.Expression) hclsyntax.Node {
	if n, ok := expr.(hclsyntax.Node); ok {
		return n
	}
	return nil
}

// checkRefs rejects a root that reads a local or a variable its own
// directory scope never declares: an undefined input evaluates as
// unknown-or-error depending on the engine, which turns a fixture mistake
// into an engine-behavior reading. A reference in one module directory
// resolves only against declarations in that directory; the root's files
// resolve against the root alone.
func checkRefs(cell Cell) error {
	declaredLocals := map[string]map[string]bool{}
	declaredVars := map[string]map[string]bool{}
	scopes := map[string]bool{}
	for name := range cell.files {
		scopes[scopeOf(name)] = true
	}
	for s := range scopes {
		declaredLocals[s] = map[string]bool{}
		declaredVars[s] = map[string]bool{}
	}
	reads := map[string][2]map[string]bool{}
	for name, content := range cell.files {
		dl, dv, rl, rv := refsOf(content)
		s := scopeOf(name)
		for l := range dl {
			declaredLocals[s][l] = true
		}
		for v := range dv {
			declaredVars[s][v] = true
		}
		reads[name] = [2]map[string]bool{rl, rv}
	}
	for name, refs := range reads {
		s := scopeOf(name)
		for l := range refs[0] {
			if !declaredLocals[s][l] {
				return fmt.Errorf("cell %s reads local.%s in %s, which that directory scope declares nowhere", cell.Name(), l, name)
			}
		}
		for v := range refs[1] {
			if !declaredVars[s][v] {
				return fmt.Errorf("cell %s reads var.%s in %s, which that directory scope declares nowhere", cell.Name(), v, name)
			}
		}
	}
	return nil
}

// MaterializeAt writes the cells under dir (a new temporary directory when
// empty), for callers outside a test.
func MaterializeAt(dir string, cells []Cell) (string, []string, error) {
	files := make([]map[string]string, len(cells))
	names := make([]string, len(cells))
	for i, c := range cells {
		if err := checkLabels(c); err != nil {
			return "", nil, err
		}
		if err := checkRefs(c); err != nil {
			return "", nil, err
		}
		names[i] = DirName(i, c.Name())
		files[i] = c.files
	}
	d, err := writeCells(dir, "tfcorpus", names, files)
	return d, names, err
}

// MaterializeStateAt writes the state cells under dir (a new temporary
// directory when empty), for callers outside a test.
func MaterializeStateAt(dir string, cells []StateCell) (string, []string, error) {
	files := make([]map[string]string, len(cells))
	names := make([]string, len(cells))
	for i, c := range cells {
		// The state cells pass the same validity checks as the rest of
		// the corpus.
		if err := checkLabels(Cell{files: c.files}); err != nil {
			return "", nil, err
		}
		if err := checkRefs(Cell{files: c.files}); err != nil {
			return "", nil, err
		}
		names[i] = DirName(i, c.Name())
		files[i] = c.files
	}
	d, err := writeCells(dir, "tfcorpus-state", names, files)
	return d, names, err
}

// writeCells writes one root per entry under dir.
func writeCells(dir, tempPattern string, names []string, files []map[string]string) (string, error) {
	if dir == "" {
		d, err := os.MkdirTemp("", tempPattern)
		if err != nil {
			return "", err
		}
		dir = d
	}
	for i := range names {
		if err := writeTree(filepath.Join(dir, names[i]), files[i]); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// DirName is the directory name of cell i with the given cell name.
func DirName(i int, name string) string {
	return fmt.Sprintf("%04d_%s", i, sanitize(name))
}

// writeTree writes the files of one root.
func writeTree(root string, files map[string]string) error {
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// sanitize turns a cell name into one path element.
func sanitize(name string) string {
	return strings.NewReplacer("/", "--", "=", "-", "\"", "", " ", "").Replace(name)
}

// WriteRulesMulti writes the probe rules plus one rule that fires twice per
// matching instance and reports every finding under the same resource name
// and search key, so the instances of one block share one finding identity.
// The two results of an instance differ in their remediation, a field the
// engine reports as written and CompareFindings orders on, so the findings
// of one identity group are distinguishable and the first-of-identity
// selection is observable. It exists for the check that
// identity compaction keeps the finding of an identity group that compares
// first.
func WriteRulesMulti(t *testing.T) string {
	t.Helper()
	dir := WriteRules(t)
	writeQuery(t, dir, "probe-legacy-resource-multi", `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	some name, b in doc.resource.aws_s3_bucket
	startswith(name, "sink")
	b.probe == "fire"
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": "sink",
		"searchKey": sprintf("aws_s3_bucket[%s].probe#1", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "probe",
		"keyActualValue": "probe",
		"remediation": "aa-first",
	}
}

DatadogPolicy contains result if {
	some doc in input.document
	some name, b in doc.resource.aws_s3_bucket
	startswith(name, "sink")
	b.probe == "fire"
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": "sink",
		"searchKey": sprintf("aws_s3_bucket[%s].probe#2", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "probe",
		"keyActualValue": "probe",
		"remediation": "zz-later",
	}
}`, "legacy shared identity")
	return dir
}

// WriteRules writes the probe rules: the eq read in one rule per literal
// variant, the other reads in one rule each, for the contract input and for
// the legacy documents of each block kind. Every rule matches only the sink
// type, so neighbor and source blocks stay quiet. The rules need the shared
// Terraform and common libraries, which the caller passes as the libraries
// path.
func WriteRules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for read, variants := range ruleVariants {
		for _, v := range variants {
			suffix := variantSuffix(v)
			writeQuery(t, dir, "probe-contract-"+read+suffix, contractRule(read, v, "resource"), "contract "+read+" "+v)
			if read == "eq" {
				// The data and ephemeral block inventories are separate keys
				// of the contract input; the expansion cells that sink there
				// get their own eq probes.
				writeQuery(t, dir, "probe-contract-data-eq"+suffix, contractRule("eq", v, "data"), "contract data eq "+v)
				writeQuery(t, dir, "probe-contract-ephemeral-eq"+suffix, contractRule("eq", v, "ephemeral"), "contract ephemeral eq "+v)
			}
			for _, kind := range []string{"resource", "data", "ephemeral"} {
				writeQuery(t, dir, "probe-legacy-"+kind+"-"+read+suffix, legacyRule(read, v, kind), "legacy "+kind+" "+read+" "+v)
			}
		}
	}
	return dir
}

// variantSuffix is the name suffix of a rule variant: empty for the reads
// with a single condition.
func variantSuffix(v string) string {
	if v == "" {
		return ""
	}
	return "-" + v
}

// writeQuery writes one rule directory.
func writeQuery(t *testing.T, dir, name, rule, title string) {
	t.Helper()
	d := filepath.Join(dir, "terraform", name)
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	metadata := fmt.Sprintf(`{
  "id": %q,
  "queryName": %q,
  "severity": "LOW",
  "category": "Best Practices",
  "descriptionText": "Probe rule that fires on the sink block.",
  "descriptionUrl": "https://example.invalid/probe",
  "platform": "Terraform",
  "descriptionID": "probe",
  "cloudProvider": "aws"
}`, name, title)
	if err := os.WriteFile(filepath.Join(d, "metadata.json"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "query.rego"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Probe identifies which rule input a probe rule reads.
const (
	ProbeContract = "contract"
	ProbeLegacy   = "legacy"
)

// eqLiteral is the Rego literal of each eq variant.
var eqLiteral = map[string]string{
	"scalar":    `"fire"`,
	"list":      `["fire"]`,
	"map":       `{"a": "fire"}`,
	"nested":    `{"a": {"b": "fire"}}`,
	"empty":     `[]`,
	"null":      `null`,
	"objmap":    `{"probe_source": "fire"}`,
	"objmerged": `{"label": "x", "probe_source": "fire"}`,
}

// contractRule is a rule on the contract input: every sink block whose probe
// attribute holds the firing value, read the rule's way. The block kind
// decides which inventory of the contract input the rule reads.
func contractRule(read, variant, kind string) string {
	blocks := `tf.blocks("aws_s3_bucket")`
	switch kind {
	case "data":
		blocks = `tf.blocks_data("aws_s3_bucket")`
	case "ephemeral":
		blocks = `tf.blocks_ephemeral("aws_s3_bucket")`
	}
	return fmt.Sprintf(`package datadog

import rego.v1

import data.generic.common as common

import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in %s
	%s
	result := common.finding(b, ["probe"], {})
}
`, blocks, ruleCondition(read, variant))
}

// legacyRule is a rule on the legacy documents: every sink entry whose probe
// attribute holds the firing value.
func legacyRule(read, variant, kind string) string {
	return fmt.Sprintf(`package datadog

import rego.v1

import data.generic.terraform as tf

DatadogPolicy contains result if {
	some doc in input.document
	some name, b in doc.%s.aws_s3_bucket
	%s
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%%s].probe", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "probe",
		"keyActualValue": "probe",
	}
}
`, kind, ruleCondition(read, variant))
}

// RuleID is the id of the probe rule that fires on this cell: the contract
// input or the legacy documents, the cell's read and variant, and for the
// legacy documents the block kind. The legacy documents of a module sink are
// resource documents.
func (c Cell) RuleID(probe string) string {
	kind := ""
	if probe == ProbeLegacy || c.SinkKind == "data" || c.SinkKind == "ephemeral" {
		sink := c.SinkKind
		if sink == "" || sink == "module" {
			sink = "resource"
		}
		kind = "-" + sink
	}
	return "probe-" + probe + kind + "-" + c.Read + variantSuffix(ruleVariantOf(c))
}

// ruleVariantOf returns the rule variant name a cell's shape and source
// need, without its leading dash.
func ruleVariantOf(c Cell) string {
	if c.Read == "eq" && c.Variant != "" {
		return c.Variant
	}
	switch c.Read {
	case "eq":
		if c.Source == "merged" {
			return "objmerged"
		}
		if objectSource(c) {
			return "objmap"
		}
		if c.Shape == "set" {
			return "list"
		}
		return c.Shape
	case "membership", "index":
		if objectSource(c) && c.Read == "index" {
			return "objmap"
		}
		if c.Shape == "map" || objectSource(c) {
			return "map"
		}
		return "seq"
	}
	return ""
}

// ExpectedProbeValue is the JSON value the cell's probe attribute resolves
// to: the firing or non-firing value of its shape, or the object its source
// yields for the object-source variants.
func (c Cell) ExpectedProbeValue() any {
	// The splat composes its own two-element list from the items local; the
	// shape's list literal does not apply to it.
	if c.Indirection == "splat" {
		if c.Fire {
			return []any{"fire"}
		}
		return []any{"safe", "x"}
	}
	if objectSource(c) || c.Variant == "objmap" || c.Variant == "objmerged" {
		value := "fire"
		extra := map[string]any{}
		if !c.Fire {
			value = "safe"
			// The plain object gains a second attribute so no count read
			// can mistake it for the firing single-attribute object; the
			// merged object already carries one.
			if c.Variant != "objmerged" {
				extra["extra"] = "x"
			} else {
				extra["label"] = "x"
			}
		}
		if c.Variant == "objmerged" {
			// The merged object always carries the label attribute.
			extra["label"] = "x"
		}
		out := map[string]any{"probe_source": value}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	fire, noFire := shapes[c.Shape].fire, shapes[c.Shape].noFire
	expr := fire
	if !c.Fire {
		expr = noFire
	}
	return hclLiteralToJSON(expr)
}

// hclLiteralToJSON converts the corpus's HCL fire and non-fire literals to
// their JSON values.
func hclLiteralToJSON(expr string) any {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "toset(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSuffix(strings.TrimPrefix(expr, "toset("), ")")
	}
	switch {
	case expr == `null`:
		return nil
	case strings.HasPrefix(expr, `"`):
		return strings.Trim(expr, `"`)
	case strings.HasPrefix(expr, "["):
		inner := strings.TrimSuffix(strings.TrimPrefix(expr, "["), "]")
		var items []any
		for _, part := range strings.Split(inner, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			items = append(items, hclLiteralToJSON(part))
		}
		if items == nil {
			items = []any{}
		}
		return items
	case strings.HasPrefix(expr, "{"):
		inner := strings.TrimSuffix(strings.TrimPrefix(expr, "{"), "}")
		out := map[string]any{}
		for _, part := range strings.Split(inner, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			out[strings.TrimSpace(kv[0])] = hclLiteralToJSON(kv[1])
		}
		return out
	}
	return expr
}
