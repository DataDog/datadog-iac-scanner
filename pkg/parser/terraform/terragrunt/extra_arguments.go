/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// extraArguments is an extra_arguments block passing variables to plan or
// apply.
type extraArguments struct {
	label string
	// args are the -var-file and -var arguments, in order.
	args []varArgument
	rng  hcl.Range
}

// varArgument is a -var-file path (file set) or a -var assignment.
type varArgument struct {
	file     string
	optional bool
	name     string
	value    string
}

// evaluateExtraArguments keeps the extra_arguments blocks applying to plan
// or apply, with their variable arguments: arguments first, then
// required_var_files, then optional_var_files, as Terragrunt passes them.
func evaluateExtraArguments(body *hclsyntax.Body, evalCtx *hcl.EvalContext) []extraArguments {
	var out []extraArguments
	for _, block := range blocksOfType(body, "extra_arguments") {
		if len(block.Labels) == 0 || !coversPlanOrApply(attributeValue(block.Body, "commands", evalCtx)) {
			continue
		}
		extra := extraArguments{label: block.Labels[0], rng: block.Range()}
		extra.args = parseVarArguments(knownStrings(attributeValue(block.Body, "arguments", evalCtx)))
		for _, file := range knownStrings(attributeValue(block.Body, "required_var_files", evalCtx)) {
			extra.args = append(extra.args, varArgument{file: file})
		}
		for _, file := range knownStrings(attributeValue(block.Body, "optional_var_files", evalCtx)) {
			extra.args = append(extra.args, varArgument{file: file, optional: true})
		}
		out = append(out, extra)
	}
	return out
}

func coversPlanOrApply(commands cty.Value) bool {
	for _, command := range knownStrings(commands) {
		if command == cmdPlan || command == cmdApply {
			return true
		}
	}
	return false
}

const (
	flagVarFile = "var-file"
	flagVar     = "var"
)

// parseVarArguments reads -var-file and -var, as one argument or two.
func parseVarArguments(args []string) []varArgument {
	var out []varArgument
	for i := 0; i < len(args); i++ {
		flag, value, inline := strings.Cut(args[i], "=")
		flag = strings.TrimLeft(flag, "-")
		if flag != flagVarFile && flag != flagVar {
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				break
			}
			i++
			value = args[i]
		}
		if flag == flagVarFile {
			out = append(out, varArgument{file: value})
			continue
		}
		if name, assigned, ok := strings.Cut(value, "="); ok {
			out = append(out, varArgument{name: name, value: assigned})
		}
	}
	return out
}

// mergeExtraArguments overrides blocks by label, keeping the base order.
func mergeExtraArguments(base, over []extraArguments) []extraArguments {
	out := append([]extraArguments(nil), base...)
	for _, extra := range over {
		replaced := false
		for i := range out {
			if out[i].label == extra.label {
				out[i], replaced = extra, true
			}
		}
		if !replaced {
			out = append(out, extra)
		}
	}
	return out
}

// varOverrides reads the variable values extra arguments pass, resolving var
// files from the unit directory. Missing or unreadable files are skipped.
func (e *Evaluator) varOverrides(ctx context.Context, extras []extraArguments, dir string) []VarOverride {
	contextLogger := logger.FromContext(ctx)
	var out []VarOverride
	for _, extra := range extras {
		for _, arg := range extra.args {
			if arg.file == "" {
				out = append(out, VarOverride{Name: arg.name, Input: Input{Value: varValue(arg.value), Range: extra.rng}})
				continue
			}
			overrides, err := e.readVarFile(dir, arg.file)
			if err != nil {
				if !arg.optional {
					contextLogger.Debug().Msgf("terragrunt: var file %s: %v", arg.file, err)
				}
				continue
			}
			out = append(out, overrides...)
		}
	}
	return out
}

func (e *Evaluator) readVarFile(dir, file string) ([]VarOverride, error) {
	path, err := e.confine(dir, file)
	if err != nil {
		return nil, err
	}
	src, err := e.fsys.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".json") {
		value, jsonErr := parseTfvars(src, path)
		if jsonErr != nil {
			return nil, jsonErr
		}
		start := hcl.Pos{Line: 1, Column: 1}
		values := valueMap(value)
		out := make([]VarOverride, 0, len(values))
		for _, name := range sortedKeys(values) {
			out = append(out, VarOverride{Name: name, Input: Input{
				Value: values[name], Range: hcl.Range{Filename: path, Start: start, End: start},
			}})
		}
		return out, nil
	}
	parsed, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diags
	}
	attrs, diags := parsed.Body.JustAttributes()
	if diags.HasErrors() {
		return nil, diags
	}
	out := make([]VarOverride, 0, len(attrs))
	for _, name := range sortedKeys(attrs) {
		attr := attrs[name]
		value, valueDiags := attr.Expr.Value(nil)
		if valueDiags.HasErrors() {
			continue
		}
		out = append(out, VarOverride{Name: name, Input: Input{Value: value, Range: attr.Range}})
	}
	return out, nil
}

// varValue reads a -var value as Terraform does for complex types: an HCL
// literal when it parses as one, the raw string otherwise.
func varValue(raw string) cty.Value {
	expr, diags := hclsyntax.ParseExpression([]byte(raw), "", hcl.Pos{Line: 1, Column: 1})
	if !diags.HasErrors() {
		if value, valueDiags := expr.Value(nil); !valueDiags.HasErrors() && value.IsWhollyKnown() {
			if ty := value.Type(); !ty.IsPrimitiveType() {
				return value
			}
		}
	}
	return cty.StringVal(raw)
}

func knownStrings(v cty.Value) []string {
	if v == cty.NilVal || !v.IsWhollyKnown() || v.IsNull() || !v.CanIterateElements() {
		return nil
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, elem := it.Element()
		if s, ok := knownString(elem); ok {
			out = append(out, s)
		}
	}
	return out
}
