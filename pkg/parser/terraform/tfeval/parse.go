/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

const blockTypeModule = "module"

// reservedModuleAttrs are module-block keys that are not passed as inputs.
var reservedModuleAttrs = map[string]bool{
	"source":     true,
	"version":    true,
	"providers":  true,
	"count":      true,
	"for_each":   true,
	"depends_on": true,
}

// parseDir parses HCL and JSON config in dir (non-recursively) and returns
// their bodies. Files that fail to parse are skipped. Reads go through fsys so
// content-push scans only ever see pushed files.
func parseDir(ctx context.Context, dir, packageRoot string, allow map[string]struct{}, fsys vfs.FS) ([]*hclsyntax.Body, error) {
	if fsys == nil {
		fsys = vfs.Default()
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	byName := make(map[string]fs.DirEntry, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			byName[entry.Name()] = entry
		}
	}
	names := tfmodules.SelectConfigNames(entries, dir, allow, "")
	sort.Strings(names)

	bodies := make([]*hclsyntax.Body, 0, len(names))
	for _, name := range names {
		entry, ok := byName[name]
		if !ok {
			continue
		}
		path, ok := tfmodules.ConfinedFilePath(ctx, entry, dir, packageRoot)
		if !ok {
			continue
		}
		src, rErr := fsys.ReadFile(filepath.Clean(path))
		if rErr != nil {
			continue
		}
		if body, ok := parseConfigBody(src, path); ok {
			bodies = append(bodies, body)
		}
	}
	return bodies, nil
}

func parseConfigBody(src []byte, path string) (*hclsyntax.Body, bool) {
	if tfpath.IsJSONConfig(path) {
		return parseJSONAsHCLBody(src, path)
	}
	f, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, false
	}
	body, ok := f.Body.(*hclsyntax.Body)
	return body, ok
}

// variableDecl is what a variable block declares about the values it accepts.
type variableDecl struct {
	def hclsyntax.Expression
	// ty is cty.DynamicPseudoType when the variable has no type constraint.
	ty          cty.Type
	defaults    *typeexpr.Defaults
	nonNullable bool
}

func newVariableDecl(body *hclsyntax.Body) variableDecl {
	decl := variableDecl{ty: cty.DynamicPseudoType}
	if def, ok := body.Attributes["default"]; ok {
		decl.def = def.Expr
	}
	if attr, ok := body.Attributes["type"]; ok {
		decl.ty, decl.defaults = variableType(attr)
	}
	if attr, ok := body.Attributes["nullable"]; ok {
		if v, diags := attr.Expr.Value(nil); !diags.HasErrors() && v.Type() == cty.Bool && ctyutil.Materialized(v) {
			decl.nonNullable = v.False()
		}
	}
	return decl
}

func variableType(attr *hclsyntax.Attribute) (cty.Type, *typeexpr.Defaults) {
	var expr hcl.Expression = attr.Expr
	// JSON configuration writes the constraint as a string.
	if lit, ok := attr.Expr.(*hclsyntax.LiteralValueExpr); ok && lit.Val.Type() == cty.String && ctyutil.Materialized(lit.Val) {
		parsed, diags := hclsyntax.ParseExpression([]byte(lit.Val.AsString()), attr.SrcRange.Filename, attr.SrcRange.Start)
		if diags.HasErrors() {
			return cty.DynamicPseudoType, nil
		}
		expr = parsed
	}
	ty, defaults, diags := typeexpr.TypeConstraintWithDefaults(expr)
	if diags.HasErrors() {
		return cty.DynamicPseudoType, nil
	}
	return ty, defaults
}

// conform applies the variable's optional attribute defaults and converts v to
// its type, leaving v as given when it does not convert.
func (d variableDecl) conform(v cty.Value) cty.Value {
	if d.defaults != nil {
		v = d.defaults.Apply(v)
	}
	converted, err := convert.Convert(v, d.ty)
	if err != nil {
		return v
	}
	return converted
}

// collectBlocks partitions blocks across all bodies into variables, locals,
// module calls, resources, and outputs.
func collectBlocks(bodies []*hclsyntax.Body) (
	varDecls map[string]variableDecl,
	localExprs map[string]hclsyntax.Expression,
	modules []*hclsyntax.Block,
	resources []*hclsyntax.Block,
	outputs map[string]hclsyntax.Expression,
) {
	varDecls = map[string]variableDecl{}
	localExprs = map[string]hclsyntax.Expression{}
	outputs = map[string]hclsyntax.Expression{}

	for _, body := range bodies {
		for _, block := range body.Blocks {
			switch block.Type {
			case "variable":
				if len(block.Labels) != 1 {
					continue
				}
				varDecls[block.Labels[0]] = newVariableDecl(block.Body)
			case "locals":
				for name, attr := range block.Body.Attributes {
					localExprs[name] = attr.Expr
				}
			case blockTypeModule:
				modules = append(modules, block)
			case "resource":
				resources = append(resources, block)
			case "output":
				if len(block.Labels) != 1 {
					continue
				}
				if val, ok := block.Body.Attributes["value"]; ok {
					outputs[block.Labels[0]] = val.Expr
				}
			}
		}
	}
	return varDecls, localExprs, modules, resources, outputs
}

func collectModuleBlocks(bodies []*hclsyntax.Body) []*hclsyntax.Block {
	var modules []*hclsyntax.Block
	for _, body := range bodies {
		for _, block := range body.Blocks {
			if block.Type == blockTypeModule {
				modules = append(modules, block)
			}
		}
	}
	return modules
}

// resolveLocalDir resolves a local module source path relative to callerDir.
func resolveLocalDir(callerDir, source string) string {
	clean := tfmodules.StripGetterPrefix(source)
	if filepath.IsAbs(clean) {
		return filepath.Clean(clean)
	}
	return filepath.Clean(filepath.Join(callerDir, clean))
}

// LoadRootVars reads the variable definitions files Terraform loads on its own
// from dir (see tfpath.AutoloadedVarFiles) and returns a variable map for use as
// root-module inputs, reading through the evaluator's filesystem. Later files
// override earlier ones. Files that fail to read or parse are silently skipped.
// Only files listed in dir are read: MemFS records ReadFile misses as
// escalation signals, so absent files must not be probed.
func (e *Evaluator) LoadRootVars(dir string) map[string]cty.Value {
	fsys := e.fsys
	entries, _ := fsys.ReadDir(dir)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}

	out := map[string]cty.Value{}
	emptyCtx := &hcl.EvalContext{}
	for _, name := range tfpath.AutoloadedVarFiles(names) {
		p := filepath.Clean(filepath.Join(dir, name))
		src, err := fsys.ReadFile(p)
		if err != nil {
			continue
		}
		for attrName, attr := range parseVarsFile(src, p) {
			v, attrDiags := attr.Expr.Value(emptyCtx)
			if !attrDiags.HasErrors() && v.IsKnown() {
				out[attrName] = v
			}
		}
	}
	return out
}

// parseVarsFile returns the assignments of a variable definitions file, in
// native or JSON syntax.
func parseVarsFile(src []byte, path string) hcl.Attributes {
	var file *hcl.File
	var diags hcl.Diagnostics
	if tfpath.IsTFVarsJSON(path) {
		file, diags = hcljson.Parse(src, path)
	} else {
		file, diags = hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	}
	if diags.HasErrors() || file == nil {
		return nil
	}
	attrs, _ := file.Body.JustAttributes()
	return attrs
}

// parseResourceInstanceKey splits an expanded resource Name into its base label, instance key,
// whether the key is a count index (true) vs a for_each string key (false), and whether the
// name contained any expansion brackets at all.
//   - "foo"        → ("foo", "",    false, false) — no expansion
//   - "foo[0]"     → ("foo", "0",   true,  true)  — count
//   - `foo["bar"]` → ("foo", "bar", false, true)  — for_each (including empty-string key)
func parseResourceInstanceKey(name string) (base, key string, isCount, expanded bool) {
	// for_each: name ends with `"]` and contains `["`
	if strings.HasSuffix(name, `"]`) {
		if idx := strings.LastIndex(name, `["`); idx >= 0 {
			quoted := name[idx+1 : len(name)-1] // `"bar"`
			unquoted, err := strconv.Unquote(quoted)
			if err != nil {
				unquoted = strings.Trim(quoted, `"`)
			}
			return name[:idx], unquoted, false, true
		}
	}
	// count: name ends with [N] where N is an integer
	if strings.HasSuffix(name, "]") {
		if idx := strings.LastIndex(name, "["); idx >= 0 {
			inner := name[idx+1 : len(name)-1]
			if _, err := strconv.Atoi(inner); err == nil {
				return name[:idx], inner, true, true
			}
		}
	}
	return name, "", false, false
}

// ResourceBaseName strips any count/for_each instance suffix from a resource Name
// (e.g. "k[0]" → "k", `k["dev"]` → "k"). Used by callers that need the bare label
// for rule matching or source-line lookups.
func ResourceBaseName(name string) string {
	if idx := strings.IndexByte(name, '['); idx >= 0 {
		return name[:idx]
	}
	return name
}

func blockLabel(b *hclsyntax.Block) string {
	if len(b.Labels) == 0 {
		return ""
	}
	return b.Labels[0]
}

// isEmptyCollection returns true when attr evaluates to a known empty collection under ctx.
// Unknown or unevaluable for_each expressions return false (conservative: keep the block).
func isEmptyCollection(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) bool {
	if attr == nil {
		return false
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !ctyutil.Materialized(v) {
		return false
	}
	t := v.Type()
	if t.IsObjectType() || t.IsMapType() || t.IsListType() || t.IsTupleType() || t.IsSetType() {
		return v.LengthInt() == 0
	}
	return false
}

// isLiteralZero returns true when attr evaluates to the number zero under ctx.
// Unknown or unevaluable count expressions return false (conservative: keep the block).
func isLiteralZero(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) bool {
	if attr == nil {
		return false
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() {
		return false
	}
	n, ok := ctyutil.LiteralInt(v)
	return ok && n == 0
}

// objectOrEmpty wraps m as a cty object; cty.ObjectVal panics on empty maps.
func objectOrEmpty(m map[string]cty.Value) cty.Value {
	if len(m) == 0 {
		return cty.EmptyObjectVal
	}
	return cty.ObjectVal(m)
}

func joinAddr(parent, seg string) string {
	if parent == "" {
		return seg
	}
	return parent + "." + seg
}

// cloneChain copies the slice to avoid aliasing across sibling recursions.
func cloneChain(chain []CallSite) []CallSite {
	if len(chain) == 0 {
		return nil
	}
	out := make([]CallSite, len(chain))
	copy(out, chain)
	return out
}
