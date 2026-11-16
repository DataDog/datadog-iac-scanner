/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"maps"

	"github.com/zclconf/go-cty/cty"
)

// mergeIncludes merges the included files under the unit: the unit wins over
// its includes, and a later include over an earlier one. Locals are never
// merged.
func mergeIncludes(unit *config, includes []*include) *config {
	merged := unit
	for i := len(includes) - 1; i >= 0; i-- {
		inc := includes[i]
		switch inc.strategy {
		case mergeNone:
			continue
		case mergeDeep:
			merged = mergeConfigs(inc.cfg, merged, true)
		default:
			merged = mergeConfigs(inc.cfg, merged, false)
		}
	}
	return merged
}

// mergeConfigs returns base overridden by over. Deep merges maps and objects
// recursively and concatenates lists.
func mergeConfigs(base, over *config, deep bool) *config {
	out := &config{
		file:        over.file,
		locals:      over.locals,
		source:      base.source,
		inputsRange: base.inputsRange,
		excluded:    base.excluded || over.excluded,
		attrs:       map[string]cty.Value{},
		inputs:      map[string]Input{},
	}
	if over.source != nil {
		out.source = over.source
	}
	out.dependencies = maps.Clone(base.dependencies)
	if out.dependencies == nil {
		out.dependencies = map[string]dependency{}
	}
	maps.Copy(out.dependencies, over.dependencies)
	out.extraArgs = mergeExtraArguments(base.extraArgs, over.extraArgs)
	out.generated = maps.Clone(base.generated)
	if out.generated == nil {
		out.generated = map[string]GeneratedFile{}
	}
	maps.Copy(out.generated, over.generated)
	out.remoteState = base.remoteState
	if over.remoteState != nil {
		out.remoteState = over.remoteState
	}
	if over.inputs != nil {
		out.inputsRange = over.inputsRange
	}
	for name, value := range base.attrs {
		out.attrs[name] = value
	}
	for name, value := range over.attrs {
		if prev, ok := out.attrs[name]; ok && deep {
			value = deepMerge(prev, value)
		}
		out.attrs[name] = value
	}
	for name, input := range base.inputs {
		out.inputs[name] = input
	}
	for name, input := range over.inputs {
		if prev, ok := out.inputs[name]; ok && deep {
			input.Value = deepMerge(prev.Value, input.Value)
		}
		out.inputs[name] = input
	}
	return out
}

// deepMerge merges maps and objects key by key and concatenates lists and
// tuples; anything else is replaced by over.
func deepMerge(base, over cty.Value) cty.Value {
	if !mergeable(base) || !mergeable(over) {
		return over
	}
	bt, ot := base.Type(), over.Type()
	switch {
	case isMapLike(bt) && isMapLike(ot):
		out := base.AsValueMap()
		if out == nil {
			out = map[string]cty.Value{}
		}
		for name, value := range over.AsValueMap() {
			if prev, ok := out[name]; ok {
				value = deepMerge(prev, value)
			}
			out[name] = value
		}
		return cty.ObjectVal(out)
	case isListLike(bt) && isListLike(ot):
		return cty.TupleVal(append(base.AsValueSlice(), over.AsValueSlice()...))
	}
	return over
}

func mergeable(v cty.Value) bool {
	return v != cty.NilVal && v.IsKnown() && !v.IsNull()
}

func isMapLike(t cty.Type) bool { return t.IsObjectType() || t.IsMapType() }

func isListLike(t cty.Type) bool { return t.IsListType() || t.IsTupleType() || t.IsSetType() }
