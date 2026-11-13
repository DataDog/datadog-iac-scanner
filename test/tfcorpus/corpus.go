/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfcorpus generates Terraform scan fixtures from small tables of
// axes. Every cell is one Terraform root; the generator is deterministic, so
// the same tables always produce the same corpus.
//
// A value cell writes one attribute, `probe`, on a sink block, through an
// indirection (a variable, a local, a module output, ...), with a value of a
// given shape (scalar, list, ...). The generated probe rules fire exactly when
// the attribute holds the firing value, so the findings of a cell show what
// the evaluator resolved the indirection to, after the unknown gate decided
// what is certain. The literal cell of a shape and read is its oracle.
package tfcorpus

import (
	"fmt"
	"sort"
	"strings"
)

// The sink resource type every value cell writes. The probe rules read only
// this type, so neighbor and source blocks never add findings.
const SinkType = "aws_s3_bucket"

// Fire marks whether a cell configures the firing value (true) or a
// same-shape value the probe must not fire on (false).
type Cell struct {
	// Indirection is how the probe attribute reaches its value: the empty
	// string is a literal (the oracle); the others are configuration
	// indirections (local, variable, module output, ...).
	Indirection string
	// Shape is the value's type: scalar, list, set, map, nested (an object of
	// objects), empty, null.
	Shape string
	// Read is how the probe rule reads the attribute: eq, membership, count,
	// index, helper (a library function), path (a nested attribute path).
	Read string
	// Source is where the firing value originates: written (a literal in this
	// root), resource_attr, resource_object, lookalike (an ordinary object
	// equal to a resource's attributes), merged (that object merged with
	// another one).
	Source string
	// Neighbor is an unknown value the sink's finding does not depend on:
	// same_block, sibling, related, computed, module_arg, module_empty_arg.
	Neighbor string
	// Expansion is how the sink repeats: none, count1, count3, count258 (the
	// previous count cap plus two), foreach_map, foreach_set for a block
	// sink; module_count, module_foreach, nested for a module sink.
	Expansion string
	// SinkKind is the kind of the sink block: resource, data, ephemeral,
	// module. Value cells always use resource.
	SinkKind string
	// Fire tells whether the cell configures the firing value.
	Fire bool
	// Keys are the instance keys the sink declares, as the legacy documents
	// write them ("sink", "sink[0]", `sink["k"]`). Empty for value cells,
	// whose sink has one unkeyed instance.
	Keys []string
	// WantChains is the number of module call chains the cell evaluates (1
	// for most cells, 2 for a module call expanded over two instances). Zero
	// means the cell makes no assertion about the chains.
	WantChains int
	// variant pins the eq rule literal a cell needs, when its source makes
	// the read value an object of a resource's attributes. The oracle of
	// such a cell carries the same variant.
	Variant string
	// files are the Terraform files of the root.
	files map[string]string
}

// Name identifies a cell: its axis values joined by slashes.
func (c Cell) Name() string {
	parts := []string{}
	add := func(axis, v string) {
		if v != "" {
			parts = append(parts, axis+"="+v)
		}
	}
	add("kind", c.Indirection)
	add("shape", c.Shape)
	add("read", c.Read)
	add("source", c.Source)
	add("neighbor", c.Neighbor)
	add("expansion", c.Expansion)
	add("block", c.SinkKind)
	add("variant", c.Variant)
	add("value", map[bool]string{true: "fire", false: "nofire"}[c.Fire])
	return strings.Join(parts, "/")
}

// Repro returns a minimal reproduction: every Terraform file of the cell,
// ready to paste into a scratch root.
func (c Cell) Repro() string {
	names := make([]string, 0, len(c.files))
	for name := range c.files {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "// %s\n%s\n", name, c.files[name])
	}
	return b.String()
}

// shapeDef holds the firing and non-firing literal of a shape, and the value
// the projected attribute becomes in Rego for the firing one.
type shapeDef struct {
	fire, noFire string // HCL expressions
	regoFire     string // Rego literal compared against
}

var shapes = map[string]shapeDef{
	"scalar": {fire: `"fire"`, noFire: `"safe"`, regoFire: `"fire"`},
	"list":   {fire: `["fire"]`, noFire: `["safe", "x"]`, regoFire: `["fire"]`},
	"set":    {fire: `toset(["fire"])`, noFire: `toset(["safe", "x"])`, regoFire: `["fire"]`},
	"map":    {fire: `{a = "fire"}`, noFire: `{a = "safe"}`, regoFire: `{"a": "fire"}`},
	"nested": {fire: `{a = {b = "fire"}}`, noFire: `{a = {b = "safe"}}`, regoFire: `{"a": {"b": "fire"}}`},
	"empty":  {fire: `[]`, noFire: `["x"]`, regoFire: `[]`},
	"null":   {fire: `null`, noFire: `"safe"`, regoFire: `null`},
}

// readsOf lists, per shape, the read kinds a probe can apply to it.
var readsOf = map[string][]string{
	"scalar": {"eq", "helper"},
	"list":   {"eq", "membership", "count", "index"},
	"set":    {"eq", "membership", "count"},
	"map":    {"eq", "membership", "count", "index"},
	"nested": {"path"},
	"empty":  {"eq"},
	"null":   {"eq"},
}

// regoShapeFire is the Rego value of the projected attribute for a shape
// whose source is an object (the whole resource, a lookalike, a merge).
const objectRegoFire = `{"probe_source": "fire"}`

// probeCondition is the Rego condition that holds exactly when value v holds
// the cell's firing value, read the way the cell's read kind reads it.
func probeCondition(read, shape, v string, objectSource bool) string {
	fire := shapes[shape].regoFire
	if objectSource {
		fire = objectRegoFire
	}
	switch read {
	case "eq":
		return fmt.Sprintf("%s == %s", v, fire)
	case "membership":
		return fmt.Sprintf(`"fire" in %s`, v)
	case "count":
		return fmt.Sprintf("count(%s) == 1", v)
	case "index":
		return fmt.Sprintf(`%s[0] == "fire"`, v)
	case "helper":
		return fmt.Sprintf(`tf.matches(%s, "fire")`, v)
	case "path":
		return fmt.Sprintf(`%s.a.b == "fire"`, v)
	}
	panic("unknown read " + read)
}

// objectSource reports whether the cell's source makes the read value the
// attributes of a resource (the whole object, a lookalike, a merge of one).
func objectSource(c Cell) bool {
	switch c.Source {
	case "resource_object", "lookalike", "merged":
		return true
	}
	return false
}

// Oracle returns the literal cell of the same shape and read: the same value
// written directly on the sink, no indirection, no unknown neighbor.
func (c Cell) Oracle() Cell {
	o := c
	o.Indirection = ""
	o.Source = "written"
	o.Neighbor = ""
	o.files = nil
	buildLiteral(&o)
	return o
}
