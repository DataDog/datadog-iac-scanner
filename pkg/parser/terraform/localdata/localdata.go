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
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// EvalFunc evaluates an expression of a data source body, reporting false when
// it cannot be evaluated. A field that cannot be evaluated is left out.
type EvalFunc func(hcl.Expression) (cty.Value, bool)

// Source renders the attributes a data source computes from its body.
type Source func(body hcl.Body, eval EvalFunc) map[string]string

var sources = map[string]Source{
	awsIAMPolicyDocumentType: policyDocumentAttributes,
	googleIAMPolicyType:      googleIAMPolicyAttributes,
}

// Lookup returns the Source for a data source type.
func Lookup(typ string) (Source, bool) {
	s, ok := sources[typ]
	return s, ok
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
	eval EvalFunc
	// skipped is set when a dynamic block could not be expanded, so the
	// document read may lack blocks it declares.
	skipped *bool
	// budget is how many more blocks the dynamic blocks of the document may
	// generate, nested ones included, so nesting cannot multiply the per-block
	// cap.
	budget *int
}

func newDecoder(eval EvalFunc) decoder {
	budget := dynamicblock.MaxGeneratedPerResource
	return decoder{eval: eval, skipped: new(bool), budget: &budget}
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
