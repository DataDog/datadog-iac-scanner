/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// unitGraph orders the resource blocks and module calls of a module directory
// by what each reads of the others, so evaluation runs a block after the
// blocks it reads rather than for a fixed number of passes. Units are numbered
// with the resource blocks first, in file order, and then the module calls. A
// block reads another by naming it, through a local that does, or through data
// blocks, which read the blocks they name.
//
// The graph depends on the module's HCL alone, so it is built once per parse
// and shared by every evaluation of the directory.
type unitGraph struct {
	resources int
	units     int

	// components holds the strongly connected components of the units in
	// dependency order: each comes after every component it reads. Terraform
	// rejects a cycle; a component with several units, or one reading itself,
	// is evaluated repeatedly until its values settle.
	components [][]int
	cyclic     []bool

	// edges holds the units each unit reads, through locals and data blocks
	// included.
	edges [][]int

	// viaLocals holds, for each unit, the units the locals it reads read in
	// turn, and readsData is set for a unit reading data.*, directly or through
	// a local. They tell which evaluated units a refresh of the locals or the
	// data blocks must wait for.
	viaLocals [][]int
	readsData []bool
	// dataUnits are the units the data blocks read.
	dataUnits []int
}

// unitRefs resolves what a traversal names to units.
//
// A module can declare one address twice, across files that Terraform would
// reject; a reference then reads the first declaration, and depends on all.
type unitRefs struct {
	managed        map[string][]int
	managedByType  map[string][]int
	ephemeral      map[string][]int
	ephemeralTypes map[string][]int
	allEphemeral   []int
	modules        map[string][]int
	allModules     []int
}

func refKeyOf(typ, name string) string { return typ + "\x00" + name }

func newUnitRefs(resources, modules []*hclsyntax.Block) *unitRefs {
	r := &unitRefs{
		managed:        map[string][]int{},
		managedByType:  map[string][]int{},
		ephemeral:      map[string][]int{},
		ephemeralTypes: map[string][]int{},
		modules:        map[string][]int{},
	}
	for i, rb := range resources {
		if len(rb.Labels) < 2 {
			continue
		}
		key := refKeyOf(rb.Labels[0], rb.Labels[1])
		if rb.Type == blockTypeEphemeral {
			r.ephemeral[key] = append(r.ephemeral[key], i)
			r.ephemeralTypes[rb.Labels[0]] = append(r.ephemeralTypes[rb.Labels[0]], i)
			r.allEphemeral = append(r.allEphemeral, i)
			continue
		}
		r.managed[key] = append(r.managed[key], i)
		r.managedByType[rb.Labels[0]] = append(r.managedByType[rb.Labels[0]], i)
	}
	for j, mb := range modules {
		r.allModules = append(r.allModules, len(resources)+j)
		if label := blockLabel(mb); label != "" {
			r.modules[label] = append(r.modules[label], len(resources)+j)
		}
	}
	return r
}

// traversalReads is what a set of traversals reads.
type traversalReads struct {
	units  []int
	locals []int
	data   bool
}

func (r *unitRefs) classify(g *localGraph, traversals []hcl.Traversal) traversalReads {
	var out traversalReads
	for _, t := range traversals {
		if len(t) == 0 || t.IsRelative() {
			continue
		}
		switch root := t.RootName(); root {
		case blockTypeModule:
			if name, ok := staticAttributeName(t); ok {
				out.units = append(out.units, r.modules[name]...)
			} else {
				out.units = append(out.units, r.allModules...)
			}
		case rootLocal:
			if name, ok := terraform.LocalTraversalName(t); ok {
				if v, declared := g.index[name]; declared {
					out.locals = append(out.locals, v)
				}
			} else {
				for v := range g.names {
					out.locals = append(out.locals, v)
				}
			}
		case blockTypeData:
			out.data = true
		case blockTypeEphemeral:
			out.units = append(out.units, r.ephemeralUnits(t)...)
		case rootVar, rootEach, metaArgCount, rootSelf, rootPath, rootTerraform:
		default:
			if name, ok := staticAttributeName(t); ok {
				out.units = append(out.units, r.managed[refKeyOf(root, name)]...)
			} else {
				out.units = append(out.units, r.managedByType[root]...)
			}
		}
	}
	return out
}

// ephemeralUnits returns the ephemeral blocks ephemeral.<type>.<name> names.
func (r *unitRefs) ephemeralUnits(t hcl.Traversal) []int {
	if len(t) < 2 {
		return r.allEphemeral
	}
	typ, ok := traverserName(t[1])
	if !ok {
		return r.allEphemeral
	}
	if len(t) < 3 {
		return r.ephemeralTypes[typ]
	}
	name, ok := traverserName(t[2])
	if !ok {
		return r.ephemeralTypes[typ]
	}
	return r.ephemeral[refKeyOf(typ, name)]
}

// traverserName is the name an attribute step or a constant string index
// selects.
func traverserName(step hcl.Traverser) (string, bool) {
	return staticAttributeName(hcl.Traversal{hcl.TraverseRoot{}, step})
}

func newUnitGraph(resources, modules []*hclsyntax.Block, g *localGraph) *unitGraph {
	refs := newUnitRefs(resources, modules)
	u := &unitGraph{resources: len(resources), units: len(resources) + len(modules)}

	localUnits := newLocalUnits(g, refs)
	u.dataUnits = u.readUnits(g, localUnits, refs, dataBlockReads(g))

	blocks := make([]*hclsyntax.Block, 0, u.units)
	blocks = append(blocks, resources...)
	blocks = append(blocks, modules...)
	edges := make([][]int, u.units)
	u.viaLocals = make([][]int, u.units)
	u.readsData = make([]bool, u.units)
	for unit, block := range blocks {
		reads := refs.classify(g, terraform.BodyTraversals(block.Body))
		set := map[int]struct{}{}
		for _, w := range reads.units {
			set[w] = struct{}{}
		}
		via := map[int]struct{}{}
		readsData := reads.data
		for _, l := range reads.locals {
			for _, w := range localUnits.of(l) {
				via[w] = struct{}{}
				set[w] = struct{}{}
			}
			readsData = readsData || g.deps[l].data
		}
		if readsData {
			for _, w := range u.dataUnits {
				set[w] = struct{}{}
			}
		}
		edges[unit] = sortedKeys(set)
		u.viaLocals[unit] = sortedKeys(via)
		u.readsData[unit] = readsData
	}

	u.edges = edges
	u.components, u.cyclic = leveled(stronglyConnected(edges), edges)
	return u
}

// leveled orders components by the length of the longest chain of components
// they read, in file order within a level. It is still a dependency order, and
// the blocks of one level read none of each other, so a refresh of the locals
// or data blocks before the first of them serves them all.
func leveled(components, edges [][]int) (ordered [][]int, cyclic []bool) {
	component := make([]int, len(edges))
	for i, c := range components {
		for _, unit := range c {
			component[unit] = i
		}
	}
	level := make([]int, len(components))
	cycles := make([]bool, len(components))
	for i, c := range components {
		for _, unit := range c {
			for _, w := range edges[unit] {
				if component[w] != i {
					level[i] = max(level[i], level[component[w]]+1)
				}
			}
		}
		cycles[i] = len(c) > 1 || slices.Contains(edges[c[0]], c[0])
	}
	order := make([]int, len(components))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		if level[a] != level[b] {
			return level[a] - level[b]
		}
		return components[a][0] - components[b][0]
	})
	ordered = make([][]int, len(components))
	cyclic = make([]bool, len(components))
	for i, from := range order {
		ordered[i], cyclic[i] = components[from], cycles[from]
	}
	return ordered, cyclic
}

// dataBlockReads is what the data blocks of the module read.
func dataBlockReads(g *localGraph) []hcl.Traversal {
	var out []hcl.Traversal
	for _, b := range g.dataBlocks {
		out = append(out, terraform.BodyTraversals(b.Body)...)
	}
	return out
}

// readUnits is the units traversals read, directly and through locals.
func (u *unitGraph) readUnits(g *localGraph, locals *localUnits, refs *unitRefs, traversals []hcl.Traversal) []int {
	reads := refs.classify(g, traversals)
	set := map[int]struct{}{}
	for _, w := range reads.units {
		set[w] = struct{}{}
	}
	for _, l := range reads.locals {
		for _, w := range locals.of(l) {
			set[w] = struct{}{}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[int]struct{}) []int {
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// localUnits is the units each local reads, directly or through the locals it
// reads, computed on demand. A local in a cycle sees only the part of the cycle
// before it closes, which is as much as Terraform gives it.
type localUnits struct {
	g       *localGraph
	refs    *unitRefs
	memo    map[int][]int
	visited map[int]bool
}

func newLocalUnits(g *localGraph, refs *unitRefs) *localUnits {
	return &localUnits{g: g, refs: refs, memo: map[int][]int{}, visited: map[int]bool{}}
}

func (l *localUnits) of(v int) []int {
	if units, ok := l.memo[v]; ok {
		return units
	}
	if l.visited[v] {
		return nil
	}
	l.visited[v] = true
	reads := l.refs.classify(l.g, l.g.exprs[v].Variables())
	set := map[int]struct{}{}
	for _, w := range reads.units {
		set[w] = struct{}{}
	}
	for _, w := range reads.locals {
		for _, unit := range l.of(w) {
			set[unit] = struct{}{}
		}
	}
	l.visited[v] = false
	units := sortedKeys(set)
	l.memo[v] = units
	return units
}
