/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/zclconf/go-cty/cty"
)

// terms converts cty values to OPA terms with the value package's rules: an
// unknown value is the placeholder; a known string that holds UnknownMarker
// keeps its other characters and replaces each mark with the placeholder;
// null object attributes are absent, null list elements stay null.
type terms struct {
	placeholder *ast.Term
	// unknown is set when a conversion produced the placeholder.
	unknown bool
}

// term converts v; a null v gives nil.
func (t *terms) term(v cty.Value) *ast.Term {
	v, _ = v.UnmarkDeep()
	return t.convert(v)
}

func (t *terms) convert(v cty.Value) *ast.Term {
	if !v.IsKnown() {
		t.unknown = true
		return t.placeholder
	}
	if v.IsNull() {
		return nil
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		s := v.AsString()
		if !value.HasUnknownMarker(s) {
			return ast.StringTerm(s)
		}
		placeholder, _ := t.placeholder.Value.(ast.String)
		s, _ = value.Substitute(s, string(placeholder))
		t.unknown = true
		return ast.StringTerm(s)
	case ty == cty.Bool:
		return ast.BooleanTerm(v.True())
	case ty == cty.Number:
		return ast.NumberTerm(number(v.AsBigFloat()))
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		return t.array(v)
	case ty.IsMapType() || ty.IsObjectType():
		return t.object(v)
	case ty == cty.DynamicPseudoType:
		t.unknown = true
		return t.placeholder
	}
	return nil
}

func (t *terms) array(v cty.Value) *ast.Term {
	elems := make([]*ast.Term, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		et := t.convert(e)
		if et == nil {
			et = ast.NullTerm()
		}
		elems = append(elems, et)
	}
	return ast.ArrayTerm(elems...)
}

func (t *terms) object(v cty.Value) *ast.Term {
	pairs := make([][2]*ast.Term, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		k, e := it.Element()
		if et := t.convert(e); et != nil {
			pairs = append(pairs, [2]*ast.Term{ast.StringTerm(k.AsString()), et})
		}
	}
	return ast.ObjectTerm(pairs...)
}

func number(n *big.Float) json.Number {
	if n.IsInt() {
		if i, acc := n.Int64(); acc == big.Exact {
			return json.Number(strconv.FormatInt(i, 10))
		}
	}
	return json.Number(n.Text('g', -1))
}
