/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	mergeShallow = "shallow"
	mergeDeep    = "deep"
	mergeNone    = "no_merge"

	keySource = "source"
	funcMerge = "merge"
	parentDir = ".."

	// maxReadDepth caps nested read_terragrunt_config calls.
	maxReadDepth = 10
)

// scope is what the path functions answer while one file is evaluated.
type scope struct {
	// configPath is the config whose directory get_terragrunt_dir reports: the
	// unit while an included file is evaluated.
	configPath string
	// originalPath is the unit get_original_terragrunt_dir reports, also
	// through read_terragrunt_config.
	originalPath string
	includes     map[string]string
	includeOrder []string
	depth        int
	reading      map[string]bool
}

// item is an evaluated value and the item of a real file that sets it.
type item struct {
	value cty.Value
	rng   model.SourceLocation
}

// config is one evaluated file, or a unit merged with its includes.
type config struct {
	locals map[string]cty.Value
	source *item
	inputs map[string]item
	// inputsUnknown is set when the keys of an inputs attribute are not known.
	inputsUnknown bool
	// excluded is set by an exclude block known to cover plan or apply.
	excluded bool
	attrs    map[string]cty.Value
}

type include struct {
	name     string
	expose   bool
	strategy string
	cfg      *config
}

// evalFile evaluates one file in Terragrunt's order: include, locals, then the
// rest. An included file's own include blocks are ignored, as in Terragrunt.
func (t *translator) evalFile(path string, body *hclsyntax.Body, s *scope, withIncludes bool) (*config, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	vars := map[string]cty.Value{"dependency": cty.DynamicVal, "values": cty.DynamicVal}
	ctx := &hcl.EvalContext{Variables: vars, Functions: t.functions(s)}
	vars["feature"] = t.features(body, ctx)

	var includes []*include
	if withIncludes {
		var err error
		if includes, err = t.evalIncludes(body, ctx, path, s); err != nil {
			return nil, err
		}
	} else if len(blocksOfType(body, "include")) > 0 {
		t.debugf("ignoring include blocks of included file %s", path)
	}
	vars["include"] = exposedIncludes(includes)

	locals := t.evalLocals(body, ctx)
	vars[varLocal] = cty.ObjectVal(locals)

	cfg := t.evalBody(body, ctx)
	cfg.locals = locals
	return mergeIncludes(cfg, includes), nil
}

// evalIncludes resolves the include blocks, then evaluates each included file
// in the unit's scope, so path functions there describe the unit. An include
// that cannot be loaded is an error: the unit would lose arbitrary values.
func (t *translator) evalIncludes(body *hclsyntax.Body, ctx *hcl.EvalContext, path string, s *scope) ([]*include, error) {
	dir := filepath.Dir(vfs.AbsOrClean(t.fsys, path))
	s.includes = map[string]string{}
	s.includeOrder = nil
	var includes []*include
	var paths []string
	for _, block := range blocksOfType(body, "include") {
		inc := &include{strategy: mergeShallow}
		if len(block.Labels) > 0 {
			inc.name = block.Labels[0]
		}
		target, ok := knownString(t.attr(block.Body, "path", ctx))
		if !ok {
			return nil, fmt.Errorf("include %q has no known path", inc.name)
		}
		resolved, err := t.confine(dir, target)
		if err != nil {
			return nil, fmt.Errorf("include %q: %w", inc.name, err)
		}
		if v, ok := knownBool(t.attr(block.Body, "expose", ctx)); ok {
			inc.expose = v
		}
		if v, ok := knownString(t.attr(block.Body, "merge_strategy", ctx)); ok {
			switch v {
			case mergeShallow, mergeDeep, mergeNone:
				inc.strategy = v
			default:
				return nil, fmt.Errorf("include %q: unknown merge_strategy %q", inc.name, v)
			}
		}
		s.includes[inc.name] = resolved
		s.includeOrder = append(s.includeOrder, inc.name)
		includes = append(includes, inc)
		paths = append(paths, resolved)
	}
	for i, inc := range includes {
		cfg, err := t.evalIncluded(paths[i], s)
		if err != nil {
			return nil, fmt.Errorf("include %q: %w", inc.name, err)
		}
		inc.cfg = cfg
	}
	return includes, nil
}

func (t *translator) evalIncluded(path string, s *scope) (*config, error) {
	body, err := t.parseFile(path)
	if err != nil {
		return nil, err
	}
	return t.evalFile(path, body, s, false)
}

// parseFile reads and parses a configuration file.
func (t *translator) parseFile(path string) (*hclsyntax.Body, error) {
	src, err := tfmodules.ReadConfigFile(t.ctx, t.fsys, path, "")
	if err != nil {
		return nil, err
	}
	body, diags := parseBody(t.ctx, src, path)
	if diags.HasErrors() {
		return nil, diags
	}
	if body == nil {
		return nil, errors.New("not a native syntax file")
	}
	return body, nil
}

// confine resolves target from dir and rejects paths leaving the repository.
func (t *translator) confine(dir, target string) (string, error) {
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, filepath.FromSlash(target))
	}
	return functions.ConfinePath(t.root, t.fsys, filepath.Clean(target))
}

// exposedIncludes is the include variable. A single unlabeled exposed include
// is the variable itself, labeled ones are its attributes.
func exposedIncludes(includes []*include) cty.Value {
	exposed := map[string]cty.Value{}
	for _, inc := range includes {
		if !inc.expose {
			continue
		}
		if inc.name == "" {
			return inc.cfg.object()
		}
		exposed[inc.name] = inc.cfg.object()
	}
	return cty.ObjectVal(exposed)
}

// evalBody evaluates terraform.source, inputs, exclude and the other top-level
// attributes.
func (t *translator) evalBody(body *hclsyntax.Body, ctx *hcl.EvalContext) *config {
	cfg := &config{attrs: map[string]cty.Value{}, inputs: map[string]item{}}
	for _, block := range blocksOfType(body, "terraform") {
		if a, ok := block.Body.Attributes[keySource]; ok && cfg.source == nil {
			cfg.source = &item{value: t.evalExpr(a.Expr, ctx), rng: toRange(a.SrcRange)}
		}
	}
	for name, a := range body.Attributes {
		value := t.evalExpr(a.Expr, ctx)
		if name == "inputs" {
			cfg.inputs, cfg.inputsUnknown = inputsOf(a, value)
			continue
		}
		cfg.attrs[name] = value
	}
	for _, block := range blocksOfType(body, "exclude") {
		if t.excludesPlanOrApply(block.Body, ctx) {
			cfg.excluded = true
		}
	}
	return cfg
}

// excludesPlanOrApply reports whether an exclude block is known to exclude the
// unit from plan or apply.
func (t *translator) excludesPlanOrApply(body *hclsyntax.Body, ctx *hcl.EvalContext) bool {
	if cond, ok := knownBool(t.attr(body, "if", ctx)); !ok || !cond {
		return false
	}
	actions, _ := t.attr(body, "actions", ctx).UnmarkDeep()
	if actions == cty.NilVal || !actions.IsWhollyKnown() || actions.IsNull() || !actions.CanIterateElements() {
		return false
	}
	for it := actions.ElementIterator(); it.Next(); {
		_, action := it.Element()
		if s, ok := knownString(action); ok {
			switch s {
			case "all", "all_except_output", "plan", "apply":
				return true
			}
		}
	}
	return false
}

// skipped reports whether skip or exclude take the unit out of plan and apply.
func (c *config) skipped() bool {
	skip, ok := knownBool(c.attrs["skip"])
	return c.excluded || (ok && skip)
}

// object is how read_terragrunt_config and exposed includes present a config.
func (c *config) object() cty.Value {
	out := make(map[string]cty.Value, len(c.attrs)+3)
	for name, value := range c.attrs {
		out[name] = value
	}
	out["locals"] = cty.ObjectVal(c.locals)
	if c.inputsUnknown {
		out["inputs"] = cty.DynamicVal
	} else {
		inputs := make(map[string]cty.Value, len(c.inputs))
		for name, in := range c.inputs {
			inputs[name] = in.value
		}
		out["inputs"] = cty.ObjectVal(inputs)
	}
	if c.source != nil {
		out["terraform"] = cty.ObjectVal(map[string]cty.Value{"source": c.source.value})
	}
	return cty.ObjectVal(out)
}

// mergeIncludes merges the included files under the unit: the unit wins over
// its includes, and a later include over an earlier one. Locals are never
// merged.
func mergeIncludes(unit *config, includes []*include) *config {
	merged := unit
	for i := len(includes) - 1; i >= 0; i-- {
		switch inc := includes[i]; inc.strategy {
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
		locals:        over.locals,
		source:        base.source,
		inputsUnknown: base.inputsUnknown || over.inputsUnknown,
		excluded:      base.excluded || over.excluded,
		attrs:         map[string]cty.Value{},
		inputs:        map[string]item{},
	}
	if over.source != nil {
		out.source = over.source
	}
	for name, value := range base.attrs {
		out.attrs[name] = value
	}
	// As in Terragrunt, skip is never inherited: only the unit's own counts.
	delete(out.attrs, "skip")
	for name, value := range over.attrs {
		if prev, ok := out.attrs[name]; ok && deep {
			value = deepMerge(prev, value)
		}
		out.attrs[name] = value
	}
	for name, in := range base.inputs {
		out.inputs[name] = in
	}
	for name, in := range over.inputs {
		if prev, ok := out.inputs[name]; ok && deep {
			in.value = deepMerge(prev.value, in.value)
		}
		out.inputs[name] = in
	}
	return out
}

// deepMerge merges maps and objects key by key and concatenates lists and
// tuples; anything else is replaced by over.
func deepMerge(base, over cty.Value) cty.Value {
	base, _ = base.UnmarkDeep()
	over, _ = over.UnmarkDeep()
	if !ctyutil.Materialized(base) || !ctyutil.Materialized(over) {
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

func isMapLike(t cty.Type) bool { return t.IsObjectType() || t.IsMapType() }

func isListLike(t cty.Type) bool { return t.IsListType() || t.IsTupleType() || t.IsSetType() }
