/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfcorpus

import "fmt"

// kinds lists the configuration indirections the value grid generates, with
// the shapes, sources and unknown neighbors each applies to. A source or
// neighbor absent from a list means that combination is not meaningful for
// the indirection: a variable default cannot read a resource, for example.
var kinds = map[string]struct {
	shapes    []string
	sources   []string
	neighbors []string
}{
	"variable": {
		shapes:    []string{"scalar", "list", "map"},
		sources:   []string{"written"},
		neighbors: []string{"none", "same_block", "sibling", "related", "computed"},
	},
	"local": {
		shapes:    []string{"scalar", "list", "set", "map", "nested", "empty"},
		sources:   []string{"written", "resource_attr", "resource_object", "lookalike", "merged"},
		neighbors: []string{"none", "same_block", "sibling", "related", "computed"},
	},
	"module_io": {
		shapes:    []string{"scalar", "list", "map"},
		sources:   []string{"written", "resource_attr", "resource_object", "lookalike", "merged"},
		neighbors: []string{"none", "sibling", "related", "computed", "module_arg", "module_empty_arg"},
	},
	"module_sink": {
		shapes:    []string{"scalar"},
		sources:   []string{"written"},
		neighbors: []string{"none", "sibling", "related", "computed", "module_arg", "module_empty_arg"},
	},
	"data_source": {
		shapes:    []string{"scalar", "list", "map"},
		sources:   []string{"written", "resource_attr"},
		neighbors: []string{"none", "same_block", "sibling", "computed"},
	},
	"try": {
		shapes:    []string{"scalar"},
		sources:   []string{"written", "resource_attr", "lookalike", "resource_object"},
		neighbors: []string{"none", "same_block", "computed"},
	},
	"coalesce": {
		shapes:    []string{"scalar"},
		sources:   []string{"written"},
		neighbors: []string{"none", "same_block"},
	},
	"conditional": {
		shapes:    []string{"scalar"},
		sources:   []string{"written", "resource_attr"},
		neighbors: []string{"none", "same_block"},
	},
	"for_expr": {
		shapes:    []string{"list", "set", "map"},
		sources:   []string{"written", "resource_attr"},
		neighbors: []string{"none", "sibling"},
	},
	"for_each": {
		shapes:    []string{"scalar"},
		sources:   []string{"written"},
		neighbors: []string{"none", "same_block"},
	},
	"count": {
		shapes:    []string{"scalar"},
		sources:   []string{"written"},
		neighbors: []string{"none", "same_block"},
	},
	"splat": {
		shapes:    []string{"list"},
		sources:   []string{"written", "resource_attr"},
		neighbors: []string{"none", "sibling"},
	},
	"nested": {
		shapes:    []string{"scalar", "nested"},
		sources:   []string{"written", "resource_attr", "resource_object"},
		neighbors: []string{"none", "same_block"},
	},
}

// neighborsEveryKindCannotTake lists the neighbors that require an unexpanded
// sink: a related block references the sink by address, which an expanded
// one does not have.
var unexpandedOnlyNeighbors = map[string]bool{"related": true}

// ValueGrid generates every meaningful combination of indirection, shape,
// read, source, unknown neighbor and polarity. The firing cells come first
// in name order, so callers that shard by prefix keep whole kinds together.
func ValueGrid() []Cell {
	var cells []Cell
	for _, kind := range sortedKeys(kinds) {
		spec := kinds[kind]
		for _, shape := range spec.shapes {
			for _, read := range readsOf[shape] {
				for _, source := range spec.sources {
					if source == "merged" && read == "count" {
						// A merged object holds two attributes, so the
						// single-element count read cannot apply to it.
						continue
					}
					if objectSourceName(source) && shape != "map" {
						// A resource object, a lookalike and a merge make the
						// read value an object, so only the object shape
						// applies to them.
						continue
					}
					for _, neighbor := range spec.neighbors {
						if unexpandedOnlyNeighbors[neighbor] && expansionOfKind(kind) != "" {
							continue
						}
						cells = append(cells, buildCell(Cell{
							Indirection: kind, Shape: shape, Read: read,
							Source: source, Neighbor: neighbor, SinkKind: "resource", Fire: true,
						}))
						// One polarity per scalar shape keeps the grid
						// bounded: the non-firing value proves the probe
						// does not fire on a same-shape near miss.
						if shape == "scalar" {
							cells = append(cells, buildCell(Cell{
								Indirection: kind, Shape: shape, Read: read,
								Source: source, Neighbor: neighbor, SinkKind: "resource", Fire: false,
							}))
						}
					}
				}
			}
		}
	}
	return cells
}

// expansionOfKind returns the expansion a kind writes on the sink: for_each
// and count kinds expand it; the rest leave it unexpanded.
func expansionOfKind(kind string) string {
	switch kind {
	case "for_each":
		return "foreach_set"
	case "count":
		return "count1"
	}
	return ""
}

// expansionSpecs lists the expansion × block kind × shape combinations of the
// parity grid, with the instance keys each declares. The count258 expansion
// is the previous count cap plus two, so a cap regression loses instances.
var expansionSpecs = []struct {
	expansion, sinkKind string
	shapes              []string
	chains              int
	keys                func(name string) []string
}{
	{expansion: "none", sinkKind: "resource", shapes: []string{"scalar", "list"}, chains: 1,
		keys: func(name string) []string { return []string{name} }},
	{expansion: "none", sinkKind: "data", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name} }},
	{expansion: "none", sinkKind: "ephemeral", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name} }},
	{expansion: "count1", sinkKind: "resource", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name + "[0]"} }},
	{expansion: "count1", sinkKind: "data", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name + "[0]"} }},
	{expansion: "count1", sinkKind: "ephemeral", shapes: []string{"scalar"}, chains: 1,
		// Ephemeral blocks are evaluated as written, so their count keeps
		// one unkeyed instance.
		keys: func(name string) []string { return []string{name} }},
	{expansion: "count3", sinkKind: "resource", shapes: []string{"scalar", "list"}, chains: 1,
		keys: func(name string) []string { return instances(name, 3) }},
	{expansion: "count258", sinkKind: "resource", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return instances(name, 258) }},
	{expansion: "foreach_map", sinkKind: "resource", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name + `["one"]`, name + `["two"]`} }},
	{expansion: "foreach_set", sinkKind: "resource", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name + `["k"]`} }},
	{expansion: "foreach_set", sinkKind: "data", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name + `["k"]`} }},
	{expansion: "foreach_set", sinkKind: "ephemeral", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name} }},
	{expansion: "module_count", sinkKind: "module", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name + "[0]"} }},
	{expansion: "module_foreach", sinkKind: "module", shapes: []string{"scalar"}, chains: 2,
		keys: func(name string) []string { return []string{name + `["one"]`, name + `["two"]`} }},
	{expansion: "nested", sinkKind: "module", shapes: []string{"scalar"}, chains: 1,
		keys: func(name string) []string { return []string{name} }},
}

// instances lists name[i] for i in [0, n).
func instances(name string, n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("%s[%d]", name, i)
	}
	return out
}

// ExpansionGrid generates the parity cells: one sink per expansion, block
// kind and shape, its probe attribute written literally. Every instance of a
// sink must yield the same finding shape as its siblings.
func ExpansionGrid() []Cell {
	var cells []Cell
	for _, spec := range expansionSpecs {
		for _, shape := range spec.shapes {
			for _, fire := range []bool{true, false} {
				cells = append(cells, buildExpansion(Cell{
					Shape: shape, Expansion: spec.expansion, SinkKind: spec.sinkKind,
					Fire: fire, Keys: spec.keys("sink"), WantChains: spec.chains,
				}))
			}
		}
	}
	return cells
}

// sortedKeys lists the keys of a string-keyed map in sorted order.
func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// objectSourceName reports whether a source makes the read value the
// attributes of a resource.
func objectSourceName(source string) bool {
	switch source {
	case "resource_object", "lookalike", "merged":
		return true
	}
	return false
}
