/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	mergeShallow = "shallow"
	mergeDeep    = "deep"
	mergeNone    = "no_merge"
)

// scope is what the path functions answer while one file is evaluated.
type scope struct {
	// terragruntPath is the config get_terragrunt_dir reports: the including
	// unit while an included file is evaluated.
	terragruntPath string
	// originalPath is the unit get_original_terragrunt_dir reports, also
	// through read_terragrunt_config.
	originalPath string
	// includes maps include names to the files they include.
	includes     map[string]string
	includeOrder []string
	depth        int
	reading      map[string]bool
}

// config is one evaluated file, or a unit merged with its includes.
type config struct {
	file        string
	locals      map[string]cty.Value
	source      *Input
	inputs      map[string]Input
	inputsRange hcl.Range
	// excluded is set by an exclude block known to cover plan or apply.
	excluded bool
	attrs    map[string]cty.Value
}

type include struct {
	name     string
	path     string
	expose   bool
	strategy string
	cfg      *config
}

// evaluateConfig evaluates one file in Terragrunt's order: include, locals,
// then the rest. An included file's own include blocks are ignored, as in
// Terragrunt.
func (e *Evaluator) evaluateConfig(ctx context.Context, path string, s *scope, withIncludes bool) (*config, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	src, err := e.fsys.ReadFile(path)
	if err != nil {
		return nil, err
	}
	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1, Byte: 0})
	if diags.HasErrors() {
		return nil, diags
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected body type %T", file.Body)
	}

	funcs := e.functions(ctx, s)
	vars := map[string]cty.Value{
		"dependency": cty.DynamicVal,
		"values":     cty.DynamicVal,
	}
	evalCtx := &hcl.EvalContext{Variables: vars, Functions: funcs}
	vars["feature"] = evaluateFeatures(body, evalCtx)

	var includes []*include
	if withIncludes {
		includes = e.evaluateIncludes(ctx, body, evalCtx, path, s)
	} else if len(blocksOfType(body, "include")) > 0 {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Msgf("terragrunt: ignoring include blocks of included file %s", path)
	}
	vars["include"] = exposedIncludes(includes)

	locals := evaluateLocals(ctx, body, evalCtx)
	vars[varLocal] = cty.ObjectVal(locals)

	cfg := &config{file: path, locals: locals, attrs: map[string]cty.Value{}}
	evaluateBody(ctx, body, evalCtx, cfg)
	if !withIncludes {
		return cfg, nil
	}
	return mergeIncludes(cfg, includes), nil
}

// evaluateIncludes resolves the include blocks, then evaluates each included
// file in the unit's scope, so path functions there describe the unit.
func (e *Evaluator) evaluateIncludes(
	ctx context.Context, body *hclsyntax.Body, evalCtx *hcl.EvalContext, path string, s *scope,
) []*include {
	contextLogger := logger.FromContext(ctx)
	blocks := blocksOfType(body, "include")
	includes := make([]*include, 0, len(blocks))
	s.includes = map[string]string{}
	s.includeOrder = nil
	for _, block := range blocks {
		inc := &include{strategy: mergeShallow}
		if len(block.Labels) > 0 {
			inc.name = block.Labels[0]
		}
		target, ok := knownString(attributeValue(block.Body, "path", evalCtx))
		if !ok {
			contextLogger.Debug().Msgf("terragrunt: include %q of %s has no known path", inc.name, path)
			continue
		}
		resolved, err := e.confine(filepath.Dir(path), target)
		if err != nil {
			contextLogger.Warn().Msgf("terragrunt: include %q of %s: %v", inc.name, path, err)
			continue
		}
		inc.path = resolved
		if v := attributeValue(block.Body, "expose", evalCtx); v.Type() == cty.Bool && v.IsKnown() && !v.IsNull() {
			inc.expose = v.True()
		}
		if strategy, ok := knownString(attributeValue(block.Body, "merge_strategy", evalCtx)); ok {
			inc.strategy = strategy
		}
		s.includes[inc.name] = resolved
		s.includeOrder = append(s.includeOrder, inc.name)
		includes = append(includes, inc)
	}
	kept := includes[:0]
	for _, inc := range includes {
		cfg, err := e.evaluateConfig(ctx, inc.path, s, false)
		if err != nil {
			contextLogger.Warn().Msgf("terragrunt: include %q of %s: %v", inc.name, path, err)
			continue
		}
		inc.cfg = cfg
		kept = append(kept, inc)
	}
	return kept
}

// exposedIncludes is the include variable: the exposed files by name.
func exposedIncludes(includes []*include) cty.Value {
	exposed := map[string]cty.Value{}
	for _, inc := range includes {
		if inc.expose && inc.name != "" {
			exposed[inc.name] = inc.cfg.object()
		}
	}
	return cty.ObjectVal(exposed)
}

// evaluateFeatures is the feature variable: each flag's default.
func evaluateFeatures(body *hclsyntax.Body, evalCtx *hcl.EvalContext) cty.Value {
	features := map[string]cty.Value{}
	for _, block := range blocksOfType(body, "feature") {
		if len(block.Labels) == 0 {
			continue
		}
		value := attributeValue(block.Body, "default", evalCtx)
		if value == cty.NilVal {
			value = cty.NullVal(cty.DynamicPseudoType)
		}
		features[block.Labels[0]] = cty.ObjectVal(map[string]cty.Value{paramValue: value})
	}
	return cty.ObjectVal(features)
}

// evaluateBody evaluates terraform.source, inputs, skip, exclude and the other
// top-level attributes into cfg.
func evaluateBody(ctx context.Context, body *hclsyntax.Body, evalCtx *hcl.EvalContext, cfg *config) {
	for _, block := range blocksOfType(body, "terraform") {
		if attr, ok := block.Body.Attributes["source"]; ok {
			cfg.source = &Input{Value: evalExpr(ctx, attr.Expr, evalCtx), Range: attr.SrcRange}
		}
	}
	for name, attr := range body.Attributes {
		value := evalExpr(ctx, attr.Expr, evalCtx)
		if name == "inputs" {
			cfg.inputs = inputsWithRanges(attr, value)
			cfg.inputsRange = attr.SrcRange
		}
		cfg.attrs[name] = value
	}
	for _, block := range blocksOfType(body, "exclude") {
		if excludesPlanOrApply(block.Body, evalCtx) {
			cfg.excluded = true
		}
	}
}

// excludesPlanOrApply reports whether an exclude block is known to exclude
// the unit from plan or apply.
func excludesPlanOrApply(body *hclsyntax.Body, evalCtx *hcl.EvalContext) bool {
	cond := attributeValue(body, "if", evalCtx)
	if cond.Type() != cty.Bool || !cond.IsKnown() || cond.IsNull() || cond.False() {
		return false
	}
	actions := attributeValue(body, "actions", evalCtx)
	if actions == cty.NilVal || !actions.IsWhollyKnown() || actions.IsNull() || !actions.CanIterateElements() {
		return false
	}
	for it := actions.ElementIterator(); it.Next(); {
		_, action := it.Element()
		if s, ok := knownString(action); ok {
			switch s {
			case "all", "all_except_output", cmdPlan, cmdApply:
				return true
			}
		}
	}
	return false
}

// skipped reports whether skip or exclude take the unit out of plan and apply.
func (c *config) skipped() bool {
	v := c.attrs["skip"]
	return c.excluded || (v != cty.NilVal && v.Type() == cty.Bool && v.IsKnown() && !v.IsNull() && v.True())
}

// object is how read_terragrunt_config and exposed includes present a config.
func (c *config) object() cty.Value {
	out := make(map[string]cty.Value, len(c.attrs)+3)
	for name, value := range c.attrs {
		out[name] = value
	}
	out["locals"] = cty.ObjectVal(c.locals)
	inputs := make(map[string]cty.Value, len(c.inputs))
	for name, input := range c.inputs {
		inputs[name] = input.Value
	}
	out["inputs"] = cty.ObjectVal(inputs)
	if c.source != nil {
		out["terraform"] = cty.ObjectVal(map[string]cty.Value{"source": c.source.Value})
	}
	return cty.ObjectVal(out)
}

func blocksOfType(body *hclsyntax.Body, typ string) []*hclsyntax.Block {
	var out []*hclsyntax.Block
	for _, block := range body.Blocks {
		if block.Type == typ {
			out = append(out, block)
		}
	}
	return out
}

// attributeValue evaluates an attribute, cty.NilVal when it is absent.
func attributeValue(body *hclsyntax.Body, name string, evalCtx *hcl.EvalContext) cty.Value {
	attr, ok := body.Attributes[name]
	if !ok {
		return cty.NilVal
	}
	return evalExpr(context.Background(), attr.Expr, evalCtx)
}

// evalExpr evaluates expr, unknown when evaluation fails. A failing object or
// tuple constructor is rebuilt item by item, so one failing item does not
// hide the others.
func evalExpr(ctx context.Context, expr hclsyntax.Expression, evalCtx *hcl.EvalContext) cty.Value {
	value, diags := expr.Value(evalCtx)
	if !diags.HasErrors() {
		return value
	}
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsExpr:
		items := make(map[string]cty.Value, len(e.Items))
		for _, item := range e.Items {
			key, keyDiags := item.KeyExpr.Value(evalCtx)
			name, ok := knownString(key)
			if keyDiags.HasErrors() || !ok {
				continue
			}
			items[name] = evalExpr(ctx, item.ValueExpr, evalCtx)
		}
		return cty.ObjectVal(items)
	case *hclsyntax.TupleConsExpr:
		elems := make([]cty.Value, len(e.Exprs))
		for i, elem := range e.Exprs {
			elems[i] = evalExpr(ctx, elem, evalCtx)
		}
		return cty.TupleVal(elems)
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msgf("terragrunt: %s: %s", expr.Range(), diags.Error())
	return cty.DynamicVal
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
