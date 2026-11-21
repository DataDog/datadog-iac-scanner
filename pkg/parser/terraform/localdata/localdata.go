/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package localdata renders the data sources Terraform computes from their
// configuration alone, such as aws_iam_policy_document, into the attributes
// resources read from them. Without them, a policy assembled by such a data
// source is only a reference to it.
package localdata

import (
	"context"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// EvalFunc evaluates an expression of a data source body, reporting false when
// it cannot be evaluated. A field that cannot be evaluated is left out.
type EvalFunc func(hcl.Expression) (cty.Value, bool)

// Source renders the attributes a data source computes from its body. A done
// ctx stops dynamic block expansion, and the document is then not rendered.
type Source func(ctx context.Context, body hcl.Body, eval EvalFunc) map[string]string

type sourceDefinition struct {
	render     Source
	attributes []string
}

var sources = map[string]sourceDefinition{
	awsIAMPolicyDocumentType: {render: policyDocumentAttributes, attributes: []string{"json", "minified_json"}},
	googleIAMPolicyType:      {render: googleIAMPolicyAttributes, attributes: []string{"policy_data"}},
}

// Lookup returns the Source for a data source type.
func Lookup(typ string) (Source, bool) {
	s, ok := sources[typ]
	return s.render, ok
}

// ConfigBlocks describes the nested blocks of the locally computed data
// sources. A JSON configuration needs the schema to distinguish these blocks
// from object-valued arguments.
func ConfigBlocks(typ, parent string) []hcl.BlockHeaderSchema {
	switch typ {
	case awsIAMPolicyDocumentType:
		switch parent {
		case "":
			return documentSchema.Blocks
		case "statement":
			return statementSchema.Blocks
		}
	case googleIAMPolicyType:
		switch parent {
		case "":
			return googlePolicySchema.Blocks
		case "binding":
			return googleBindingSchema.Blocks
		case "audit_config":
			return googleAuditConfigSchema.Blocks
		}
	}
	return nil
}

// Evaluate computes the source's attributes without rendering unresolved values
// as text. A computed string is known only when every input consumed by the
// source was known; otherwise string operations on it must remain uncertain.
// Lookup remains the partial rendering path for rule documents.
func Evaluate(ctx context.Context, typ string, body hcl.Body, eval EvalFunc) map[string]cty.Value {
	source, ok := sources[typ]
	if !ok {
		return nil
	}
	unresolved := false
	computed := source.render(ctx, body, func(expr hcl.Expression) (cty.Value, bool) {
		v, known := eval(expr)
		if !known || !v.IsWhollyKnown() {
			unresolved = true
			return cty.DynamicVal, false
		}
		return v, true
	})
	out := make(map[string]cty.Value, len(source.attributes))
	for _, name := range source.attributes {
		if value, exists := computed[name]; exists && !unresolved && ctx.Err() == nil {
			out[name] = cty.StringVal(value)
		} else {
			out[name] = cty.UnknownVal(cty.String)
		}
	}
	return out
}

// Types returns the data source types Lookup knows, sorted.
func Types() []string {
	out := make([]string, 0, len(sources))
	for typ := range sources {
		out = append(out, typ)
	}
	sort.Strings(out)
	return out
}

type decoder struct {
	ctx  context.Context
	eval EvalFunc
	// skipped is set when a dynamic block could not be expanded, so the
	// document read may lack blocks it declares.
	skipped *bool
}

func newDecoder(ctx context.Context, eval EvalFunc) decoder {
	return decoder{ctx: ctx, eval: eval, skipped: new(bool)}
}

func (d decoder) value(attr *hcl.Attribute) (cty.Value, bool) {
	if attr == nil {
		return cty.NilVal, false
	}
	v, ok := d.eval(attr.Expr)
	if !ok || v.IsNull() {
		return cty.NilVal, false
	}
	v, _ = v.UnmarkDeep()
	return v, true
}

func (d decoder) str(attr *hcl.Attribute) string {
	v, ok := d.value(attr)
	if !ok {
		return ""
	}
	return toString(v)
}

// list reads a list of strings, leaving an element that is not a known string
// empty so the positions of the others hold. Empty strings are kept: IAM
// condition values use "" (for example s3:prefix for the bucket root).
func (d decoder) list(attr *hcl.Attribute) []string {
	v, ok := d.value(attr)
	if !ok || !v.IsKnown() {
		return nil
	}
	ty := v.Type()
	if !ty.IsListType() && !ty.IsTupleType() && !ty.IsSetType() {
		if s := toString(v); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		_, elem := it.Element()
		out = append(out, toString(elem))
	}
	return out
}

func toString(v cty.Value) string {
	if !ctyutil.Materialized(v) {
		return ""
	}
	s, err := convert.Convert(v, cty.String)
	if err != nil {
		return ""
	}
	str, _ := ctyutil.ConcreteString(s)
	return str
}
