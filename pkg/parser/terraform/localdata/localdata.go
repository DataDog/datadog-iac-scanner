/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package localdata computes configuration-only provider data sources.
package localdata

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// EvalFunc belongs to partial document rendering, never native evaluation.
type EvalFunc func(hcl.Expression) (cty.Value, bool)

// Diagnostic is a safe producer failure without input values or live contexts.
type Diagnostic struct {
	Summary, Detail string
	Subject         hcl.Range
}

// Configuration supplies values and block structure to the shared provider decoder.
// Native evaluation supplies its completed value snapshot; partial rendering has
// a separate HCL adapter and never feeds its recovered text back into evaluation.
type Configuration interface {
	Attribute(string) (cty.Value, bool)
	Blocks(context.Context, string) BlockResult
	Origin(string) hcl.Range
	StructureKnown() bool
	// DocumentRendering selects partial text projection, never native facts.
	DocumentRendering() bool
}

// BlockResult keeps known siblings alongside structural uncertainty or failure.
// No getter failure is hidden in mutable adapter state.
type BlockResult struct {
	Items       []Configuration
	Unresolved  bool
	Diagnostics []Diagnostic
}

// Result binds computed values to the failures which produced them.
type Result struct {
	Attributes map[string]cty.Value
	// DocumentAttributes is the partial legacy rendering from the same decode.
	// It never supplies native evaluation facts.
	DocumentAttributes map[string]string
	Diagnostics        []Diagnostic
}

// Source is a stable provider definition shared by native and document adapters.
type Source struct {
	render     func(decoder, Configuration) map[string]string
	attributes []string
}

var sources = map[string]*Source{
	awsIAMPolicyDocumentType: {render: policyDocumentAttributes, attributes: []string{"json", "minified_json"}},
	googleIAMPolicyType:      {render: googleIAMPolicyAttributes, attributes: []string{"policy_data"}},
}

func Lookup(typ string) (*Source, bool) { s, ok := sources[typ]; return s, ok }

// Evaluate decodes once and makes incomplete or failed computations uncertain.
// Known invalid siblings remain failures even when another input is unknown.
func (s *Source) Evaluate(ctx context.Context, input Configuration) Result {
	d := decoder{ctx: ctx, document: input.DocumentRendering(), state: &decodeState{unresolved: !input.StructureKnown()}}
	var rendered map[string]string
	if ctx.Err() == nil {
		rendered = s.render(d, input)
	}
	result := Result{Attributes: make(map[string]cty.Value, len(s.attributes)), Diagnostics: d.state.diagnostics}
	if d.document && !d.state.documentIncomplete && ctx.Err() == nil {
		result.DocumentAttributes = rendered
	}
	for _, name := range s.attributes {
		if value, ok := rendered[name]; ok && !d.state.unresolved && len(d.state.diagnostics) == 0 && ctx.Err() == nil {
			result.Attributes[name] = cty.StringVal(value)
		} else {
			result.Attributes[name] = cty.UnknownVal(cty.String)
		}
	}
	return result
}
func Types() []string {
	out := make([]string, 0, len(sources))
	for typ := range sources {
		out = append(out, typ)
	}
	sort.Strings(out)
	return out
}

type decodeState struct {
	unresolved         bool
	documentIncomplete bool
	diagnostics        []Diagnostic
}
type decoder struct {
	ctx      context.Context
	document bool
	state    *decodeState
}

func (d decoder) invalid(input Configuration, name, reason string) {
	d.state.diagnostics = append(d.state.diagnostics, Diagnostic{
		Summary: "Invalid local data source configuration",
		Detail:  fmt.Sprintf("The %q input %s.", name, reason), Subject: input.Origin(name),
	})
}
func (d decoder) value(input Configuration, name string) (cty.Value, bool) {
	if d.ctx.Err() != nil {
		d.state.unresolved = true
		return cty.DynamicVal, false
	}
	v, present := input.Attribute(name)
	if !present {
		return cty.NilVal, false
	}
	if v == cty.NilVal {
		d.invalid(input, name, "has no evaluated value")
		return cty.NilVal, false
	}
	v, _ = v.Unmark()
	if v.IsNull() {
		return cty.NilVal, false
	}
	if !v.IsKnown() {
		d.state.unresolved = true
		return v, false
	}
	return v, true
}
func (d decoder) stringValue(input Configuration, name string, v cty.Value) string {
	v, _ = v.Unmark()
	if !v.IsKnown() {
		d.state.unresolved = true
		return ""
	}
	if v.IsNull() {
		return ""
	}
	s, err := convert.Convert(v, cty.String)
	if err != nil {
		d.invalid(input, name, "must contain a string-convertible value")
		return ""
	}
	return s.AsString()
}
func (d decoder) str(input Configuration, name string) string {
	v, ok := d.value(input, name)
	if !ok {
		return ""
	}
	return d.stringValue(input, name, v)
}
func (d decoder) list(input Configuration, name string) []string {
	v, ok := d.value(input, name)
	if !ok {
		return nil
	}
	ty := v.Type()
	if !ty.IsListType() && !ty.IsTupleType() && !ty.IsSetType() {
		d.invalid(input, name, "must be a collection of string-convertible values")
		// Preserve permissive legacy text without treating it as a native fact.
		if d.document {
			if value := d.stringValue(input, name, v); value != "" {
				return []string{value}
			}
		}
		return nil
	}
	out := make([]string, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		if d.ctx.Err() != nil {
			d.state.unresolved = true
			break
		}
		_, elem := it.Element()
		out = append(out, d.stringValue(input, name, elem))
	}
	return out
}
func (d decoder) blocks(input Configuration, name string) []Configuration {
	result := input.Blocks(d.ctx, name)
	d.state.unresolved = d.state.unresolved || result.Unresolved
	d.state.documentIncomplete = d.state.documentIncomplete || result.Unresolved
	d.state.diagnostics = append(d.state.diagnostics, result.Diagnostics...)
	return result.Items
}

// ValueConfiguration adapts an already evaluated native configuration. Subject
// is an authoritative declaration fallback where precise field origins are absent.
// Incomplete records actual unresolved dynamic expansion, not count variability.
type ValueConfiguration struct {
	Value      cty.Value
	Subject    *hcl.Range
	Incomplete bool
}

func (v ValueConfiguration) Origin(string) hcl.Range {
	if v.Subject == nil {
		return hcl.Range{}
	}
	return *v.Subject
}
func (v ValueConfiguration) DocumentRendering() bool { return false }
func (v ValueConfiguration) StructureKnown() bool    { return !v.Incomplete }
func (v ValueConfiguration) Attribute(name string) (cty.Value, bool) {
	value, _ := v.Value.Unmark()
	ty := value.Type()
	if ty.IsObjectType() && ty.HasAttribute(name) {
		return value.GetAttr(name), true
	}
	if ty.IsMapType() && value.IsKnown() && !value.IsNull() && value.HasIndex(cty.StringVal(name)).True() {
		return value.Index(cty.StringVal(name)), true
	}
	return cty.NilVal, false
}
func (v ValueConfiguration) Blocks(ctx context.Context, name string) BlockResult {
	var result BlockResult
	value, ok := v.Attribute(name)
	if !ok {
		return result
	}
	value, _ = value.Unmark()
	add := func(item cty.Value) {
		if ctx.Err() != nil {
			result.Unresolved = true
			return
		}
		item, _ = item.Unmark()
		if !item.IsKnown() {
			result.Unresolved = true
			return
		}
		if item.IsNull() {
			return
		}
		if item.Type().IsObjectType() || item.Type().IsMapType() {
			result.Items = append(result.Items, ValueConfiguration{Value: item, Subject: v.Subject})
			return
		}
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			Summary: "Invalid local data source configuration",
			Detail:  fmt.Sprintf("The %q blocks must contain objects.", name), Subject: v.Origin(name),
		})
	}
	if !value.IsKnown() {
		result.Unresolved = true
		return result
	}
	if value.IsNull() {
		return result
	}
	ty := value.Type()
	if ty.IsListType() || ty.IsTupleType() || ty.IsSetType() {
		for it := value.ElementIterator(); it.Next(); {
			if ctx.Err() != nil {
				result.Unresolved = true
				break
			}
			_, item := it.Element()
			add(item)
		}
	} else {
		add(value)
	}
	return result
}
