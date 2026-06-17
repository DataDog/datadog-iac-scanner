/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"encoding/json"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// UnknownAttributePlaceholder is stored for cty unknown values when converting
// to the document shape rules consume, so keys stay present and MissingAttribute
// checks do not treat unresolved expressions as absent (which would false-positive).
const UnknownAttributePlaceholder = "__DD_TFEVAL_UNKNOWN__"

// AttributesToDocument converts a resolved resource's attributes into the
// map[string]interface{} shape the rule pipeline consumes. Every attribute is
// always included: unknown or unsupported values use UnknownAttributePlaceholder
// so presence-based rules do not fire false positives on unresolved expressions.
func AttributesToDocument(r *ResolvedResource) map[string]interface{} {
	out := make(map[string]interface{}, len(r.Attributes))
	for key, val := range r.Attributes {
		out[key] = ctyValueToDocument(val)
	}
	return out
}

// ctyValueToDocument converts a cty.Value to a JSON-serializable value.
// Unknowns and any type that cannot be represented become UnknownAttributePlaceholder
// so every attribute key is preserved in the output document.
func ctyValueToDocument(v cty.Value) interface{} {
	if !v.IsKnown() {
		return UnknownAttributePlaceholder
	}
	if v.IsNull() {
		return nil
	}

	t := v.Type()
	switch t {
	case cty.String:
		return v.AsString()
	case cty.Bool:
		return v.True()
	case cty.Number:
		// json.Number avoids float64 precision loss for large integers.
		return json.Number(v.AsBigFloat().Text('f', -1))
	}

	switch {
	case t.IsTupleType(), t.IsListType(), t.IsSetType():
		return ctySeqToDocument(v)
	case t.IsObjectType(), t.IsMapType():
		return ctyMapToDocument(v)
	}
	return UnknownAttributePlaceholder
}

// ctySeqToDocument converts a tuple/list/set to a slice.
func ctySeqToDocument(v cty.Value) []interface{} {
	list := make([]interface{}, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		_, ev := it.Element()
		list = append(list, ctyValueToDocument(ev))
	}
	return list
}

// ctyMapToDocument converts an object/map to a Go map; non-string or unknown
// keys are skipped (keys are always strings in well-formed Terraform).
func ctyMapToDocument(v cty.Value) map[string]interface{} {
	obj := make(map[string]interface{}, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		key, ev := it.Element()
		if key.Type() != cty.String || !key.IsKnown() {
			continue
		}
		obj[key.AsString()] = ctyValueToDocument(ev)
	}
	return obj
}

// CalledLocalDirs returns the resolved directories of every local module called
// from dir. Remote/registry sources are ignored.
func CalledLocalDirs(dir string) []string {
	bodies, err := parseDir(dir)
	if err != nil {
		return nil
	}
	moduleBlocks := collectModuleBlocks(bodies)

	emptyCtx := &hcl.EvalContext{}
	var dirs []string
	for _, mb := range moduleBlocks {
		source := knownString(mb.Body.Attributes["source"], emptyCtx)
		if source == "" || !tfmodules.LooksLikeLocalModuleSource(StripGetterPrefix(source)) {
			continue
		}
		dirs = append(dirs, resolveLocalDir(dir, source))
	}
	return dirs
}
