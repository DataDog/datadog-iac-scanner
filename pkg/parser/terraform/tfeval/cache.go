/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"sort"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// evalCacheKey: dir + package root + addr + inputs + call chain.
// Chain splits identical-input callers; pre-pass and main loop share the same chain and hit the same entry.
type evalCacheKey struct {
	dir         string
	packageRoot string
	addr        string
	inputs      string // canonical encoding of the resolved input map
	chain       string // canonical encoding of the module call chain
}

// chainKey encodes each hop as calledFrom#line#module.name; joined by "/".
func chainKey(chain []CallSite) string {
	if len(chain) == 0 {
		return ""
	}
	parts := make([]string, len(chain))
	for i, s := range chain {
		parts[i] = s.CalledFrom + "#" + strconv.Itoa(s.CalledLine) + "#module." + s.ModuleName
	}
	return strings.Join(parts, "/")
}

// evalCacheEntry holds the result of a completed module evaluation.
// visitedDirs is the set of child dirs that were added to allVisited *inside* this
// evaluation (not including the module dir itself, which is tracked by the caller).
type evalCacheEntry struct {
	resources   []ResolvedResource
	outputs     map[string]cty.Value
	visitedDirs []string
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
