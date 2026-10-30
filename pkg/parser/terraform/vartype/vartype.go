/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package vartype reads the type constraint of a Terraform variable block and
// conforms values to it, as Terraform does before a module reads them. The
// plain Terraform parser conforms root-module variables with it; module
// evaluation (tfeval) still keeps its own copy of the same conversion.
package vartype

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// Constraint is a variable's type with the defaults of its optional object
// attributes.
type Constraint struct {
	// Type is cty.DynamicPseudoType when the variable accepts any value.
	Type     cty.Type
	Defaults *typeexpr.Defaults
}

// Any is the constraint of a variable without a type.
var Any = Constraint{Type: cty.DynamicPseudoType}

// Parse reads the type argument of a variable block. JSON configuration
// writes the constraint as a string, which is parsed as a native expression.
// It returns false when expr is not a valid type constraint.
func Parse(expr hcl.Expression) (Constraint, bool) {
	if text, ok := stringConstraint(expr); ok {
		rng := expr.Range()
		parsed, diags := hclsyntax.ParseExpression([]byte(text), rng.Filename, rng.Start)
		if diags.HasErrors() {
			return Any, false
		}
		expr = parsed
	}
	ty, defaults, diags := typeexpr.TypeConstraintWithDefaults(expr)
	if diags.HasErrors() {
		return Any, false
	}
	return Constraint{Type: ty, Defaults: defaults}, true
}

// stringConstraint returns the text of a JSON constraint, which a JSON
// expression reads as verbatim without an evaluation context.
func stringConstraint(expr hcl.Expression) (string, bool) {
	if _, native := expr.(hclsyntax.Expression); native {
		return "", false
	}
	v, diags := expr.Value(nil)
	if diags.HasErrors() || v.Type() != cty.String || !ctyutil.Materialized(v) {
		return "", false
	}
	return v.AsString(), true
}

// Conform applies the optional attribute defaults to v and converts it to the
// type. When v does not convert, it returns v with its defaults applied and
// the conversion error: the root-module parser then reads the variable as
// unknown, as Terraform rejects the value, while tfeval's own copy of this
// conversion keeps the value as given.
func (c Constraint) Conform(v cty.Value) (cty.Value, error) {
	if c.Defaults != nil {
		v = c.Defaults.Apply(v)
	}
	converted, err := convert.Convert(v, c.Type)
	if err != nil {
		return v, err
	}
	return converted, nil
}
