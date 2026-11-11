/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"encoding/json"
	"math/big"
	"reflect"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// The members of a plan configuration expression.
const (
	exprConstant   = "constant_value"
	exprReferences = "references"
)

// planUnknown stands for a value after_unknown marks unknown.
type planUnknown struct{}

const (
	numberBase      = 10
	numberPrecision = 512
)

// withUnknown overlays after_unknown on planned values: Terraform leaves an
// unknown value out of the planned values and marks it true there.
func withUnknown(v, unknown any) any {
	switch u := unknown.(type) {
	case bool:
		if u {
			return planUnknown{}
		}
	case map[string]any:
		obj, ok := v.(map[string]any)
		if !ok {
			if v != nil {
				return v
			}
			obj = map[string]any{}
		}
		out := make(map[string]any, len(obj)+len(u))
		for k, e := range obj {
			out[k] = e
		}
		for k, ue := range u {
			if e := withUnknown(obj[k], ue); e != nil {
				out[k] = e
			}
		}
		return out
	case []any:
		list, ok := v.([]any)
		if !ok {
			if v != nil {
				return v
			}
			list = make([]any, len(u))
		}
		out := make([]any, max(len(list), len(u)))
		copy(out, list)
		for i, ue := range u {
			out[i] = withUnknown(out[i], ue)
		}
		return out
	}
	return v
}

// hashedAttributes are planned as a hash of the configured text
// (aws_instance.user_data is planned as its SHA1); a configured constant
// gives the text back.
var hashedAttributes = map[string]bool{"user_data": true, "user_data_base64": true}

// configLevel is the configuration of one block level: the union of the
// bodies written for it, since a planned set does not keep their order.
type configLevel struct {
	bodies []map[string]any
	// elements holds the bodies of a nested block list one per element, in
	// the order the configuration writes them. It is set only when a single
	// body writes the list.
	elements []map[string]any
}

// expr returns the expression of attribute k in some body, and whether every
// body writes the same constant for it.
func (c configLevel) expr(k string) (expr map[string]any, constant any, isConstant bool) {
	isConstant = len(c.bodies) > 0
	for i, body := range c.bodies {
		e, ok := body[k].(map[string]any)
		if !ok || !isExpression(e) {
			isConstant = false
			continue
		}
		if expr == nil {
			expr = e
		}
		cv, has := e["constant_value"]
		_, refs := e["references"]
		if !has || refs || cv == nil || (i > 0 && !reflect.DeepEqual(cv, constant)) {
			isConstant = false
			continue
		}
		constant = cv
	}
	return expr, constant, isConstant && expr != nil
}

// nested returns the bodies of nested block type k, and whether a body writes
// it as a block.
func (c configLevel) nested(k string) (configLevel, bool) {
	var out configLevel
	found := false
	for _, body := range c.bodies {
		switch v := body[k].(type) {
		case []any:
			found = true
			for _, e := range v {
				if m, ok := e.(map[string]any); ok {
					out.bodies = append(out.bodies, m)
				}
			}
			if len(c.bodies) == 1 && len(out.bodies) == len(v) {
				out.elements = out.bodies
			}
		case map[string]any:
			if !isExpression(v) {
				found = true
				out.bodies = append(out.bodies, v)
			}
		}
	}
	return out, found
}

func (c configLevel) keys() []string {
	var out []string
	seen := map[string]bool{}
	for _, body := range c.bodies {
		for k := range body {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// isExpression reports whether v is one attribute's configuration rather than
// a nested block body: only constant_value and references, or nothing for an
// expression the plan has neither for (timestamp()).
func isExpression(v map[string]any) bool {
	for k := range v {
		if k != exprConstant && k != exprReferences {
			return false
		}
	}
	return true
}

// planSplit splits planned values into what the configuration writes and the
// computed rest.
type planSplit struct {
	// dynamic lists the dot-joined attribute paths (names only) of values the
	// configuration does not show but that are kept as written: lists of
	// objects, which may come from a dynamic block.
	dynamic []string
}

// object splits one block level. A nil cfg is a resource without
// configuration: every value counts as written.
func (s *planSplit) object(obj map[string]any, cfg *configLevel, prefix string) (attrs, computed map[string]any) {
	attrs = map[string]any{}
	computed = map[string]any{}
	for k, v := range obj {
		if v == nil {
			continue
		}
		s.splitKey(attrs, computed, k, v, cfg, joinPath(prefix, k))
	}
	addWriteOnly(attrs, obj, cfg)
	return attrs, computed
}

// splitKey puts one planned value on the configured or the computed side.
func (s *planSplit) splitKey(attrs, computed map[string]any, k string, v any, cfg *configLevel, path string) {
	if cfg == nil {
		attrs[k] = v
		return
	}
	if nested, ok := cfg.nested(k); ok {
		a, c := s.blocks(v, &nested, path)
		attrs[k] = a
		if c != nil {
			computed[k] = c
		}
		return
	}
	expr, constant, isConstant := cfg.expr(k)
	switch {
	case expr != nil && constantNull(expr):
		// Written null is unset: keep the attribute absent; after_unknown
		// and provider defaults belong in computed (plan 3.2 / 3.9).
		computed[k] = v
	case expr != nil && isConstant && isObjectTree(constant):
		// A constant object (or list of objects) may write null for a field;
		// Terraform then plans a provider default ("" / [] / false). Null is
		// unset: keep the field absent and put the planned default in computed.
		a, c := splitConstantTree(v, constant)
		attrs[k] = a
		if c != nil {
			computed[k] = c
		}
	case expr != nil:
		attrs[k] = writtenValue(k, v, constant, isConstant)
	case isObjectList(v):
		s.dynamic = append(s.dynamic, objectListPaths(v, path)...)
		attrs[k] = v
	default:
		computed[k] = v
	}
}

// writtenValue restores a configured constant the plan lost: an unknown
// marker over a constant, and a hash standing in for configured text.
func writtenValue(k string, v, constant any, isConstant bool) any {
	if !isConstant {
		return v
	}
	if _, unknown := v.(planUnknown); unknown {
		return dropNullFields(constant)
	}
	if str, ok := constant.(string); ok && hashedAttributes[k] {
		return str
	}
	return v
}

// isObjectTree reports a constant made of objects (and lists of them).
func isObjectTree(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		return true
	case []any:
		return len(x) > 0 && isObjectTree(x[0])
	}
	return false
}

// splitConstantTree projects a planned value against a constant object tree:
// null fields are absent (their planned defaults go to computed). List order
// follows the planned value; constant elements are matched by non-null fields
// because Terraform may reorder set-nested blocks between config and plan.
func splitConstantTree(planned, constant any) (attrs, computed any) {
	switch c := constant.(type) {
	case map[string]any:
		return splitConstantObject(planned, c)
	case []any:
		return splitConstantList(planned, c)
	default:
		return planned, nil
	}
}

func splitConstantObject(planned any, constant map[string]any) (attrs, computed any) {
	p, _ := planned.(map[string]any)
	if p == nil {
		p = map[string]any{}
	}
	outAttrs := map[string]any{}
	outComputed := map[string]any{}
	for k, cv := range constant {
		pv, hasPlanned := p[k]
		if cv == nil {
			if hasPlanned {
				outComputed[k] = pv
			}
			continue
		}
		if isObjectTree(cv) {
			a, c := splitConstantTree(pv, cv)
			outAttrs[k] = a
			if c != nil {
				outComputed[k] = c
			}
			continue
		}
		if !hasPlanned {
			outAttrs[k] = cv
			continue
		}
		if _, unknown := pv.(planUnknown); unknown {
			outAttrs[k] = cv
			continue
		}
		outAttrs[k] = pv
	}
	for k, pv := range p {
		if _, inConst := constant[k]; inConst {
			continue
		}
		outComputed[k] = pv
	}
	if len(outComputed) == 0 {
		return outAttrs, nil
	}
	return outAttrs, outComputed
}

func splitConstantList(planned any, constant []any) (attrs, computed any) {
	list, ok := planned.([]any)
	if !ok {
		if planned == nil {
			list = make([]any, len(constant))
		} else {
			return planned, nil
		}
	}
	outAttrs := make([]any, len(list))
	outComputed := make([]any, len(list))
	used := make([]bool, len(constant))
	found := false
	for i, pe := range list {
		j := matchConstantElement(pe, constant, used)
		if j < 0 {
			outAttrs[i], outComputed[i] = pe, map[string]any{}
			continue
		}
		used[j] = true
		cm, ok := constant[j].(map[string]any)
		if !ok {
			outAttrs[i], outComputed[i] = pe, map[string]any{}
			continue
		}
		a, c := splitConstantObject(pe, cm)
		outAttrs[i] = a
		if c == nil {
			outComputed[i] = map[string]any{}
		} else {
			outComputed[i] = c
			found = true
		}
	}
	if !found {
		return outAttrs, nil
	}
	return outAttrs, outComputed
}

// matchConstantElement picks an unused constant object whose non-null fields
// agree with planned (unknown planned values may match any constant).
func matchConstantElement(planned any, constant []any, used []bool) int {
	pm, ok := planned.(map[string]any)
	if !ok {
		return -1
	}
	best, bestScore := -1, -1
	for i, c := range constant {
		if used[i] {
			continue
		}
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		score := 0
		match := true
		for k, cv := range cm {
			if cv == nil || isObjectTree(cv) {
				continue
			}
			pv, has := pm[k]
			if !has {
				match = false
				break
			}
			if _, unknown := pv.(planUnknown); unknown {
				score++
				continue
			}
			if !reflect.DeepEqual(pv, cv) {
				match = false
				break
			}
			score++
		}
		if match && score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

// dropNullFields removes null entries from a constant object tree so a wholly
// unknown planned value still projects written null as absent.
func dropNullFields(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if e == nil {
				continue
			}
			out[k] = dropNullFields(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = dropNullFields(e)
		}
		return out
	default:
		return v
	}
}

// addWriteOnly marks write-only attributes the configuration sets and the
// plan omits: their value is never known.
func addWriteOnly(attrs, obj map[string]any, cfg *configLevel) {
	if cfg == nil {
		return
	}
	for _, k := range cfg.keys() {
		if _, planned := obj[k]; planned || !strings.HasSuffix(k, "_wo") {
			continue
		}
		if expr, _, _ := cfg.expr(k); expr != nil && !constantNull(expr) {
			attrs[k] = planUnknown{}
		}
	}
}

// blocks splits a nested block list; computed is nil when no element has a
// computed value.
func (s *planSplit) blocks(v any, cfg *configLevel, path string) (attrs, computed any) {
	switch l := v.(type) {
	case map[string]any:
		v = []any{l}
	case []any:
	default:
		return v, nil
	}
	list := v.([]any)
	outAttrs := make([]any, len(list))
	outComputed := make([]any, len(list))
	found := false
	aligned := alignedElements(list, cfg)
	for i, e := range list {
		obj, ok := e.(map[string]any)
		if !ok {
			outAttrs[i], outComputed[i] = e, map[string]any{}
			continue
		}
		level := cfg
		if aligned != nil {
			level = &configLevel{bodies: []map[string]any{aligned[i]}}
		}
		a, c := s.object(obj, level, path)
		outAttrs[i], outComputed[i] = a, c
		found = found || len(c) > 0
	}
	if !found {
		return outAttrs, nil
	}
	return outAttrs, outComputed
}

// alignedElements returns the configuration body of each planned element when
// the configuration writes one body per element and each body agrees with the
// constants of the element at its position, so an element knows only what its
// own body writes. A list the plan may have reordered or expanded (a set, a
// dynamic block) gives nil: its elements share the union of the bodies.
func alignedElements(list []any, cfg *configLevel) []map[string]any {
	if cfg == nil || len(cfg.elements) != len(list) {
		return nil
	}
	for i, e := range list {
		planned, ok := e.(map[string]any)
		if !ok || !agrees(planned, cfg.elements[i]) {
			return nil
		}
	}
	return cfg.elements
}

// agrees reports whether every constant a body writes for an attribute equals
// the planned value, when the plan has a known one.
func agrees(planned, body map[string]any) bool {
	level := configLevel{bodies: []map[string]any{body}}
	for k := range body {
		_, constant, isConstant := level.expr(k)
		pv, planHas := planned[k]
		if !isConstant || !planHas || pv == nil {
			continue
		}
		if _, unknown := pv.(planUnknown); unknown {
			continue
		}
		if !reflect.DeepEqual(pv, constant) {
			return false
		}
	}
	return true
}

func constantNull(expr map[string]any) bool {
	cv, has := expr["constant_value"]
	_, refs := expr["references"]
	return has && cv == nil && !refs
}

func isObjectList(v any) bool {
	l, ok := v.([]any)
	if !ok || len(l) == 0 {
		return false
	}
	_, obj := l[0].(map[string]any)
	return obj
}

// objectListPaths lists the attribute paths (names only) inside a list of
// objects.
func objectListPaths(v any, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(v any, prefix string)
	walk = func(v any, prefix string) {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e, prefix)
			}
		case map[string]any:
			for k, e := range x {
				path := joinPath(prefix, k)
				if !seen[path] {
					seen[path] = true
					out = append(out, path)
				}
				walk(e, path)
			}
		}
	}
	walk(v, prefix)
	return out
}

// planValue converts a decoded JSON value to cty: numbers are json.Number,
// planUnknown is an unknown value.
func planValue(v any) cty.Value {
	switch x := v.(type) {
	case nil:
		return cty.NullVal(cty.DynamicPseudoType)
	case planUnknown:
		return cty.DynamicVal
	case bool:
		return cty.BoolVal(x)
	case string:
		return cty.StringVal(x)
	case json.Number:
		f, _, err := big.ParseFloat(string(x), numberBase, numberPrecision, big.ToNearestEven)
		if err != nil {
			return cty.StringVal(string(x))
		}
		return cty.NumberVal(f)
	case float64:
		return cty.NumberFloatVal(x)
	case []any:
		elems := make([]cty.Value, len(x))
		for i, e := range x {
			elems[i] = planValue(e)
		}
		return cty.TupleVal(elems)
	case map[string]any:
		attrs := make(map[string]cty.Value, len(x))
		for k, e := range x {
			attrs[k] = planValue(e)
		}
		return cty.ObjectVal(attrs)
	}
	return cty.DynamicVal
}

func planValues(m map[string]any) map[string]cty.Value {
	out := make(map[string]cty.Value, len(m))
	for k, v := range m {
		out[k] = planValue(v)
	}
	return out
}
