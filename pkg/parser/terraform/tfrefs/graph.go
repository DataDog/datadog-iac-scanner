/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfrefs reads the references a Terraform configuration makes to its
// data blocks and locals.
package tfrefs

import (
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	dataRoot  = "data"
	localRoot = "local"
)

// DataKey names a data block in the graph DataCycles reads.
func DataKey(typ, name string) string {
	return dataRoot + "." + typ + "." + name
}

// DataCycles returns the data blocks, named by DataKey, that read their own
// result, directly or through other data blocks and locals. Terraform rejects
// such a cycle. Evaluating one anyway feeds the block its previous result on
// every pass, and a function such as jsonencode nests that result once more,
// so its size doubles with each pass. reads gives the traversals each block's
// configuration reads, locals those of each local. A constant type and name
// select one block. A constant type with no single name selects every block of
// that type, and a data reference that does not name a type selects every data
// block: evaluation reads that whole object, which includes the block being
// rendered. A local reference that does not name one local selects every
// local, for the same reason. Inside a dynamic block's content the iterator
// name shadows a local of that name.
func DataCycles(reads, locals map[string][]hcl.Traversal) map[string]bool {
	byType := make(map[string][]string, len(reads))
	allData := make([]string, 0, len(reads))
	for key := range reads {
		allData = append(allData, key)
		if typ, ok := dataKeyType(key); ok {
			byType[typ] = append(byType[typ], key)
		}
	}
	allLocals := make([]string, 0, len(locals))
	for name := range locals {
		allLocals = append(allLocals, "local."+name)
	}
	edges := make(map[string][]string, len(reads)+len(locals))
	for key, traversals := range reads {
		edges[key] = dataEdges(traversals, byType, allData, allLocals)
	}
	for name, traversals := range locals {
		edges["local."+name] = dataEdges(traversals, byType, allData, allLocals)
	}
	var cyclic map[string]bool
	for key := range reads {
		if reachesItself(edges, key) {
			if cyclic == nil {
				cyclic = map[string]bool{}
			}
			cyclic[key] = true
		}
	}
	return cyclic
}

// bodyRefs walks body. shadowed holds the dynamic iterator names in scope,
// which hide a root of the same name inside their content.
func bodyRefs(out []Ref, body *hclsyntax.Body, shadowed []string) []Ref {
	for _, attr := range body.Attributes {
		out = appendUnshadowed(out, Of(attr.Expr), shadowed)
	}
	for _, block := range body.Blocks {
		out = blockRefs(out, block, shadowed)
	}
	return out
}

func blockRefs(out []Ref, block *hclsyntax.Block, shadowed []string) []Ref {
	if !dynamicblock.Is(block) {
		return bodyRefs(out, block.Body, shadowed)
	}
	for name, attr := range block.Body.Attributes {
		if name == "iterator" {
			continue
		}
		out = appendUnshadowed(out, Of(attr.Expr), shadowed)
	}
	inContent := make([]string, len(shadowed)+1)
	copy(inContent, shadowed)
	inContent[len(shadowed)] = dynamicblock.IteratorName(block)
	for _, inner := range block.Body.Blocks {
		if inner.Type == "content" {
			out = bodyRefs(out, inner.Body, inContent)
			continue
		}
		out = blockRefs(out, inner, shadowed)
	}
	return out
}

func appendUnshadowed(out, refs []Ref, shadowed []string) []Ref {
	for _, ref := range refs {
		if slices.Contains(shadowed, ref.Traversal.RootName()) {
			continue
		}
		out = append(out, ref)
	}
	return out
}

// staticStepName returns the name an attribute or a constant string index
// gives a reference step.
func staticStepName(step hcl.Traverser) (string, bool) {
	switch s := step.(type) {
	case hcl.TraverseAttr:
		return s.Name, true
	case hcl.TraverseIndex:
		if s.Key.IsKnown() && !s.Key.IsNull() && s.Key.Type() == cty.String {
			return s.Key.AsString(), true
		}
	}
	return "", false
}

// cycleStepName is a step evaluation can slice out of a root object. An empty
// index or one containing "." is excluded: evaluation reads the whole object
// for those, so they must not select a single block.
func cycleStepName(step hcl.Traverser) (string, bool) {
	name, ok := staticStepName(step)
	if !ok || name == "" || strings.ContainsAny(name, ".\x00") {
		return "", false
	}
	return name, true
}

func dataKeyType(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, dataRoot+".")
	if !ok {
		return "", false
	}
	typ, _, ok := strings.Cut(rest, ".")
	return typ, ok && typ != ""
}

// dataEdges returns the data blocks and locals the traversals read. byType,
// allData and allLocals are the blocks and locals in this scope; a reference
// evaluation cannot narrow selects all of them.
func dataEdges(traversals []hcl.Traversal, byType map[string][]string, allData, allLocals []string) []string {
	var out []string
	for _, traversal := range traversals {
		out = appendTraversalEdges(out, traversal, byType, allData, allLocals)
	}
	return out
}

func appendTraversalEdges(out []string, traversal hcl.Traversal, byType map[string][]string, allData, allLocals []string) []string {
	switch traversal.RootName() {
	case localRoot:
		if name, ok := specificLocal(traversal); ok {
			return append(out, "local."+name)
		}
		return append(out, allLocals...)
	case dataRoot:
		switch kind, typ, name := classifyData(traversal); kind {
		case dataOne:
			return append(out, DataKey(typ, name))
		case dataType:
			return append(out, byType[typ]...)
		case dataAll:
			return append(out, allData...)
		}
	}
	return out
}

type dataRefKind int

const (
	dataOne dataRefKind = iota + 1
	dataType
	dataAll
)

// classifyData reports how much of data a traversal reads. A constant type and
// name is one block. A constant type whose name is missing or not a single
// step is every block of that type. Anything else that still roots at data is
// every data block.
func classifyData(traversal hcl.Traversal) (kind dataRefKind, typ, name string) {
	if len(traversal) < 2 {
		return dataAll, "", ""
	}
	typ, ok := cycleStepName(traversal[1])
	if !ok {
		return dataAll, "", ""
	}
	if len(traversal) < 3 {
		return dataType, typ, ""
	}
	name, ok = cycleStepName(traversal[2])
	if !ok {
		return dataType, typ, ""
	}
	return dataOne, typ, name
}

func specificLocal(traversal hcl.Traversal) (string, bool) {
	if len(traversal) < 2 {
		return "", false
	}
	return cycleStepName(traversal[1])
}

// reachesItself reports whether a path of at least one edge leads from start
// back to start.
func reachesItself(edges map[string][]string, start string) bool {
	seen := map[string]bool{}
	stack := append([]string(nil), edges[start]...)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node == start {
			return true
		}
		if seen[node] {
			continue
		}
		seen[node] = true
		stack = append(stack, edges[node]...)
	}
	return false
}

// LocalTraversalName returns the local a local.<name> or local["<name>"]
// traversal reads.
func LocalTraversalName(traversal hcl.Traversal) (string, bool) {
	if traversal.RootName() != localRoot || len(traversal) < 2 {
		return "", false
	}
	return staticStepName(traversal[1])
}
