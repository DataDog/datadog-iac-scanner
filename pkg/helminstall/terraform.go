/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"bytes"
	"math/big"
	"path/filepath"
	"strings"

	tffunctions "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// A Terraform helm_release installs a local chart under its name, in its
// namespace, "default" when it has none, with its values documents then its
// set entries. Its module is evaluated with the defaults of its variables and
// its locals; what depends on anything else is left out.

// maxLocalPasses bounds the passes resolving locals that refer to each other.
const maxLocalPasses = 8

const (
	helmReleaseType = "helm_release"
	setListKind     = "set_list"
)

func (d *discovery) terraform(path string) {
	// Only a module declaring a release is evaluated: most Terraform installs
	// no chart.
	if data := d.read(path); !bytes.Contains(data, []byte(`"`+helmReleaseType+`"`)) {
		return
	}
	dir := filepath.Dir(path)
	if d.tfDirs == nil {
		d.tfDirs = map[string]bool{}
	}
	if d.tfDirs[dir] {
		return
	}
	d.tfDirs[dir] = true
	bodies := d.terraformModule(dir)
	ctx := d.terraformContext(dir, bodies)
	for _, body := range bodies {
		for _, block := range body.Blocks {
			if block.Type == "resource" && len(block.Labels) == 2 && block.Labels[0] == helmReleaseType {
				d.helmRelease(dir, block, ctx)
			}
		}
	}
}

// terraformModule parses the Terraform files of the module at dir.
func (d *discovery) terraformModule(dir string) []*hclsyntax.Body {
	var bodies []*hclsyntax.Body
	for _, e := range readDir(d.fsys(), dir) {
		if e.IsDir() || filepath.Ext(e.Name()) != ".tf" {
			continue
		}
		file := filepath.Join(dir, e.Name())
		src := d.read(file)
		if src == nil {
			continue
		}
		parsed, diags := hclsyntax.ParseConfig(src, file, hcl.InitialPos)
		if diags.HasErrors() {
			continue
		}
		if body, ok := parsed.Body.(*hclsyntax.Body); ok {
			bodies = append(bodies, body)
		}
	}
	return bodies
}

// terraformContext evaluates the variables and locals of a module.
func (d *discovery) terraformContext(dir string, bodies []*hclsyntax.Body) *hcl.EvalContext {
	vars, locals := terraformDeclarations(bodies)
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(vars),
			"path": cty.ObjectVal(map[string]cty.Value{
				"module": cty.StringVal(dir), "root": cty.StringVal(dir), "cwd": cty.StringVal(dir),
			}),
			"terraform": cty.ObjectVal(map[string]cty.Value{"workspace": cty.StringVal("default")}),
		},
		Functions: tffunctions.EvalFuncs(dir, d.fsys()),
	}
	resolveLocals(ctx, locals)
	return ctx
}

// terraformDeclarations returns the variables of a module, with their
// defaults, and the expressions of its locals.
func terraformDeclarations(bodies []*hclsyntax.Body) (vars map[string]cty.Value, locals map[string]hclsyntax.Expression) {
	vars = map[string]cty.Value{}
	locals = map[string]hclsyntax.Expression{}
	for _, body := range bodies {
		for _, block := range body.Blocks {
			switch {
			case block.Type == "variable" && len(block.Labels) == 1:
				vars[block.Labels[0]] = cty.DynamicVal
				if attr, ok := block.Body.Attributes["default"]; ok {
					if v, diags := attr.Expr.Value(nil); !diags.HasErrors() {
						vars[block.Labels[0]] = v
					}
				}
			case block.Type == "locals":
				for name, attr := range block.Body.Attributes {
					locals[name] = attr.Expr
				}
			}
		}
	}
	return vars, locals
}

// resolveLocals evaluates the locals into ctx, each pass resolving those whose
// references the previous ones resolved.
func resolveLocals(ctx *hcl.EvalContext, locals map[string]hclsyntax.Expression) {
	values := map[string]cty.Value{}
	for name := range locals {
		values[name] = cty.DynamicVal
	}
	for pass, changed := 0, true; pass < maxLocalPasses && changed; pass++ {
		ctx.Variables["local"] = cty.ObjectVal(values)
		changed = false
		for name, expr := range locals {
			if values[name].IsWhollyKnown() {
				continue
			}
			if v, diags := expr.Value(ctx); !diags.HasErrors() && v.IsWhollyKnown() {
				values[name] = v
				changed = true
			}
		}
	}
	ctx.Variables["local"] = cty.ObjectVal(values)
}

// knownAttr returns the value of an attribute of body when it is known.
func knownAttr(body *hclsyntax.Body, name string, ctx *hcl.EvalContext) (cty.Value, bool) {
	attr, ok := body.Attributes[name]
	if !ok {
		return cty.NilVal, false
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !v.IsWhollyKnown() || v.IsNull() {
		return cty.NilVal, false
	}
	return v, true
}

// knownString returns the value of a string attribute of body when it is known.
func knownString(body *hclsyntax.Body, name string, ctx *hcl.EvalContext) (string, bool) {
	v, ok := knownAttr(body, name, ctx)
	if !ok || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

func (d *discovery) helmRelease(dir string, block *hclsyntax.Block, ctx *hcl.EvalContext) {
	body := block.Body
	if repo, ok := knownString(body, "repository", ctx); ok && repo != "" {
		return
	}
	chart, ok := knownString(body, "chart", ctx)
	if !ok || strings.Contains(chart, "://") {
		return
	}
	chartDir, ok := d.idx.chartDir(localPath(dir, chart))
	if !ok {
		return
	}
	inst := Installation{
		Namespace: "default",
		Source:    "Terraform " + helmReleaseType + "." + block.Labels[1] + " in " + dir,
		Origin:    OriginDescriptor,
	}
	if name, ok := knownString(body, "name", ctx); ok {
		inst.Release = name
	}
	if ns, ok := knownString(body, "namespace", ctx); ok {
		inst.Namespace = ns
	}
	inst.Layers = append(inst.Layers, helmReleaseValues(body, ctx)...)
	if set := helmReleaseSets(body, ctx); len(set.Set)+len(set.SetString) > 0 {
		inst.Layers = append(inst.Layers, set)
	}
	d.idx.add(chartDir, &inst)
}

// helmReleaseValues returns the values documents of a helm_release.
func helmReleaseValues(body *hclsyntax.Body, ctx *hcl.EvalContext) []Layer {
	values, ok := knownAttr(body, "values", ctx)
	if !ok || !values.CanIterateElements() {
		return nil
	}
	var layers []Layer
	for it := values.ElementIterator(); it.Next(); {
		_, doc := it.Element()
		if doc.Type() != cty.String {
			continue
		}
		if parsed, err := ParseValues([]byte(doc.AsString())); err == nil {
			layers = append(layers, Layer{Values: parsed})
		}
	}
	return layers
}

// helmReleaseSets returns the set, set_sensitive and set_list entries of a
// helm_release, as attributes or blocks.
func helmReleaseSets(body *hclsyntax.Body, ctx *hcl.EvalContext) Layer {
	var set Layer
	for _, kind := range []string{"set", "set_sensitive", setListKind} {
		if v, ok := knownAttr(body, kind, ctx); ok && v.CanIterateElements() {
			for it := v.ElementIterator(); it.Next(); {
				_, e := it.Element()
				if e.Type().IsObjectType() || e.Type().IsMapType() {
					addSetEntry(&set, e.AsValueMap(), kind == setListKind)
				}
			}
		}
		for _, b := range body.Blocks {
			if b.Type != kind {
				continue
			}
			entry := map[string]cty.Value{}
			for name := range b.Body.Attributes {
				if v, ok := knownAttr(b.Body, name, ctx); ok {
					entry[name] = v
				}
			}
			addSetEntry(&set, entry, kind == setListKind)
		}
	}
	return set
}

// addSetEntry adds a set entry to layer: name, value and type, or for a list
// its items.
func addSetEntry(layer *Layer, entry map[string]cty.Value, list bool) {
	name, ok := ctyText(entry["name"])
	if !ok {
		return
	}
	if list {
		if items, ok := ctyList(entry["value"]); ok {
			layer.Set = append(layer.Set, setListExpr(name, items, func(s string) string { return s }))
		}
		return
	}
	value, ok := ctyText(entry["value"])
	if !ok {
		return
	}
	if typ, _ := ctyText(entry["type"]); typ == "string" {
		layer.SetString = append(layer.SetString, SetExpr(name, value))
	} else {
		layer.Set = append(layer.Set, SetExpr(name, value))
	}
}

// ctyText is the text of a known primitive value.
func ctyText(v cty.Value) (string, bool) {
	if v == cty.NilVal || v.IsNull() || !v.IsKnown() {
		return "", false
	}
	switch v.Type() {
	case cty.String:
		return v.AsString(), true
	case cty.Bool:
		if v.True() {
			return "true", true
		}
		return "false", true
	case cty.Number:
		bf := v.AsBigFloat()
		if bf.IsInt() {
			i, _ := bf.Int(new(big.Int))
			return i.String(), true
		}
		return bf.Text('f', -1), true
	}
	return "", false
}

func ctyList(v cty.Value) ([]string, bool) {
	if v == cty.NilVal || v.IsNull() || !v.IsWhollyKnown() || !v.CanIterateElements() {
		return nil, false
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		t, ok := ctyText(e)
		if !ok {
			return nil, false
		}
		out = append(out, t)
	}
	return out, true
}
