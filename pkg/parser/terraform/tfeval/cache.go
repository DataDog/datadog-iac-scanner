/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"sort"
	"strings"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// evalCacheKey identifies a module evaluation by its inputs alone: dir + package
// root + resolved inputs.
//
// The module address and call chain are deliberately absent. They describe where
// a module was called from, not what it evaluates to, so including them made a
// module reached by N distinct paths evaluate N times for identical results. With
// branching factor B and depth D that is B^D evaluations where only D+1 distinct
// ones exist — a nesting depth of 15 with two calls per level reaches 65k
// evaluations, and enough depth exhausts any memory limit from a handful of
// files. Callers re-stamp the address and chain onto a cached result instead,
// which is a per-resource string rewrite rather than a re-evaluation.
type evalCacheKey struct {
	dir         string
	packageRoot string
	inputs      string // canonical encoding of the resolved input map
}

// evalCacheEntry holds the result of a completed module evaluation.
// visitedDirs is the set of child dirs that were added to allVisited *inside* this
// evaluation (not including the module dir itself, which is tracked by the caller).
//
// baseAddr and baseChainLen record the position the entry was first evaluated at,
// so a caller reaching the same module by another path can rewrite the recorded
// address and chain onto the result. Outputs need no rewrite: they are values, and
// values do not depend on the path taken to reach them.
type evalCacheEntry struct {
	resources    []ResolvedResource
	outputs      map[string]cty.Value
	visitedDirs  []string
	baseAddr     string
	baseChainLen int
}

// rebase returns the cached resources as they would have been recorded had the
// module been evaluated at addr/chain instead of the position it was first
// evaluated at.
//
// Attributes and Body are shared rather than copied. They are the expensive part
// of a resolved resource and they are identical for identical inputs, so sharing
// them is what makes reuse cheap; both are treated as read-only after evaluation.
func (entry *evalCacheEntry) rebase(addr string, chain []CallSite) []ResolvedResource {
	if entry.baseAddr == addr && entry.baseChainLen == len(chain) {
		return entry.resources
	}
	out := make([]ResolvedResource, len(entry.resources))
	for i := range entry.resources {
		r := entry.resources[i]
		r.ModuleAddress = rebaseAddr(r.ModuleAddress, entry.baseAddr, addr)
		r.CallChain = rebaseChain(r.CallChain, entry.baseChainLen, chain)
		out[i] = r
	}
	return out
}

// rebaseAddr swaps the prefix a cached address was recorded under for the current
// one, keeping the part that describes position *within* the cached subtree.
func rebaseAddr(recorded, baseAddr, addr string) string {
	suffix := recorded
	if baseAddr != "" {
		suffix = strings.TrimPrefix(recorded, baseAddr)
		suffix = strings.TrimPrefix(suffix, ".")
	}
	if suffix == "" {
		return addr
	}
	return joinAddr(addr, suffix)
}

// rebaseChain replaces the leading hops a cached chain was recorded under with the
// current caller's hops, preserving the hops taken inside the cached subtree.
func rebaseChain(recorded []CallSite, baseLen int, chain []CallSite) []CallSite {
	if baseLen > len(recorded) {
		baseLen = len(recorded)
	}
	inner := recorded[baseLen:]
	if len(inner) == 0 {
		return cloneChain(chain)
	}
	out := make([]CallSite, 0, len(chain)+len(inner))
	out = append(out, chain...)
	out = append(out, inner...)
	return out
}

// canonicalInputsKey returns a stable string for a set of resolved module inputs.
// Map keys are sorted; values are JSON-encoded via cty/json (which itself sorts object
// attribute names). Unknown or unencodable values fall back to their type name.
func canonicalInputsKey(inputs map[string]cty.Value) string {
	if len(inputs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(encodeCtyForKey(inputs[k]))
		b.WriteByte('\n')
	}
	return b.String()
}

// encodeCtyForKey encodes a cty.Value to a stable string for use inside a cache key.
// cty/json is used because it produces sorted, deterministic output for object/map types.
// The null check must precede the known check because null values are also considered known.
// All DynamicPseudoType values are unknown (IsKnown()==false), so they are handled by
// the unknown branch and the DynamicPseudoType case never needs a special guard.
func encodeCtyForKey(v cty.Value) string {
	if v.IsNull() {
		// Include the type so cty.NullVal(cty.String) and cty.NullVal(cty.Number)
		// do not collide.
		return "null(" + v.Type().FriendlyName() + ")"
	}
	if !v.IsKnown() {
		return "?" + v.Type().FriendlyName()
	}
	data, err := ctyjson.Marshal(v, v.Type())
	if err != nil {
		return "?" + v.Type().FriendlyName()
	}
	return string(data)
}
