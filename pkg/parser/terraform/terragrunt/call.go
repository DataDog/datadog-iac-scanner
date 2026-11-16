/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// CallLabel names the module call of every unit: module.terragrunt.
const CallLabel = "terragrunt"

// unitDirSource is the source of a unit without terraform.source: the unit
// directory is the module.
const unitDirSource = "./"

// Call is a module call a unit makes, as tfeval.SyntheticCall describes one.
type Call struct {
	Label      string
	Source     string
	Version    string
	CallerFile string
	// Range is where a finding the inputs do not control points.
	Range hcl.Range
	// Body holds one attribute per input, positioned where it is set.
	Body *hclsyntax.Body
}

// Call is the module call the unit makes, and its inputs. Inputs the unit's
// own file sets are arguments positioned where they are set. ok is false when
// the unit makes no call that can be evaluated.
func (u *Unit) Call() (call *Call, inputs map[string]cty.Value, ok bool) {
	if u.Skip || !u.SourceKnown {
		return nil, nil, false
	}
	source, version := moduleSource(u.Source)
	if source == "" {
		source = unitDirSource
	}
	body := &hclsyntax.Body{Attributes: hclsyntax.Attributes{}}
	inputs = make(map[string]cty.Value, len(u.Inputs))
	for name, input := range u.Inputs {
		inputs[name] = input.Value
		// Attribution reports argument lines in the caller file, so an input
		// an included file sets falls back to the call anchor.
		if input.Range.Filename != u.ConfigFile {
			continue
		}
		body.Attributes[name] = &hclsyntax.Attribute{
			Name:      name,
			Expr:      &hclsyntax.LiteralValueExpr{Val: input.Value, SrcRange: input.Range},
			SrcRange:  input.Range,
			NameRange: input.Range,
		}
	}
	return &Call{
		Label:      CallLabel,
		Source:     source,
		Version:    version,
		CallerFile: u.ConfigFile,
		Range:      u.anchor(),
		Body:       body,
	}, inputs, true
}

// anchor is where a finding the inputs do not control points in the unit.
func (u *Unit) anchor() hcl.Range {
	switch {
	case u.SourceRange.Filename == u.ConfigFile:
		return u.SourceRange
	case u.InputsRange.Filename == u.ConfigFile:
		return u.InputsRange
	}
	start := hcl.Pos{Line: 1, Column: 1}
	return hcl.Range{Filename: u.ConfigFile, Start: start, End: start}
}
