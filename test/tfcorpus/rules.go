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
	"strings"
	"testing"
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

// MaterializeAt writes the cells under dir (a new temporary directory when
// empty), for callers outside a test.
func MaterializeAt(dir string, cells []Cell) (string, []string, error) {
	if dir == "" {
		d, err := os.MkdirTemp("", "tfcorpus")
		if err != nil {
			return "", nil, err
		}
		dir = d
	}
	names := make([]string, len(cells))
	for i, c := range cells {
		names[i] = DirName(i, c.Name())
		if err := writeTree(filepath.Join(dir, names[i]), c.files); err != nil {
			return "", nil, err
		}
	}
	return dir, names, nil
}

// MaterializeStateAt writes the state cells under dir (a new temporary
// directory when empty), for callers outside a test.
func MaterializeStateAt(dir string, cells []StateCell) (string, []string, error) {
	if dir == "" {
		d, err := os.MkdirTemp("", "tfcorpus-state")
		if err != nil {
			return "", nil, err
		}
		dir = d
	}
	names := make([]string, len(cells))
	for i, c := range cells {
		names[i] = DirName(i, c.Name())
		if err := writeTree(filepath.Join(dir, names[i]), c.files); err != nil {
			return "", nil, err
		}
	}
	return dir, names, nil
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
			writeQuery(t, dir, "probe-contract-"+read+suffix, contractRule(read, v), "contract "+read+" "+v)
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
// attribute holds the firing value, read the rule's way.
func contractRule(read, variant string) string {
	return fmt.Sprintf(`package datadog

import rego.v1

import data.generic.common as common

import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	%s
	result := common.finding(b, ["probe"], {})
}
`, ruleCondition(read, variant))
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
	if probe == ProbeLegacy {
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
