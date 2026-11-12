/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"sort"

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
// their bodies, with the source of each parsed file by the filename its ranges
// carry. Files that fail to parse are skipped. Reads go through fsys so
// content-push scans only ever see pushed files.
func parseDir(
	ctx context.Context, dir, packageRoot string, allow map[string]struct{}, fsys vfs.FS,
) ([]*hclsyntax.Body, map[string][]byte, error) {
	if fsys == nil {
		fsys = vfs.Default()
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	byName := make(map[string]fs.DirEntry, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			byName[entry.Name()] = entry
		}
	}
	names := tfmodules.SelectConfigNames(entries, dir, allow, "")
	sort.Strings(names)
	// Override files apply last regardless of their name, so locals, variable
	// defaults and module attributes they set win over the directory's other
	// files, matching the order module discovery assembles the same directory in.
	names = tfpath.OrderOverrideLast(names, func(name string) string { return name })

	bodies := make([]*hclsyntax.Body, 0, len(names))
	sources := make(map[string][]byte, len(names))
	for _, name := range names {
		entry, ok := byName[name]
		if !ok {
			continue
		}
		path, ok := tfmodules.ConfinedFilePath(ctx, entry, dir, packageRoot)
		if !ok {
			continue
		}
		src, rErr := tfmodules.ReadConfigFile(ctx, fsys, path, packageRoot)
		if rErr != nil {
			continue
		}
		if body, ok := parseConfigBody(src, path); ok {
			bodies = append(bodies, body)
			sources[path] = src
		}
	}
	return bodies, sources, nil
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

// blockTypeEphemeral is the ephemeral resource block type; its blocks expand
// and are addressed like resources, in their own namespace.
const blockTypeEphemeral = "ephemeral"

// collectBlocks partitions blocks across all bodies into variables, locals,
// module calls, resources (ephemeral resource blocks included), and outputs.
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
			case blockTypeResource, blockTypeEphemeral:
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
	return varDecls, localExprs, mergeModuleOverrideBlocks(modules), resources, outputs
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
	return mergeModuleOverrideBlocks(modules)
}

// mergeModuleOverrideBlocks folds a later module block of the same name into
// the first one, attribute by attribute, so an override block that restates a
// module overlays only the attributes it sets. bodies arrive in override-last
// order (see parseDir), so the first block with a given name is always the
// base: a valid, non-override configuration never repeats a module name in
// one directory. The merged block keeps the base block's identity (position,
// labels) so call-site reporting is unaffected.
func mergeModuleOverrideBlocks(blocks []*hclsyntax.Block) []*hclsyntax.Block {
	if len(blocks) < 2 {
		return blocks
	}
	order := make([]string, 0, len(blocks))
	byLabel := make(map[string]*mergedModuleBlock, len(blocks))
	for _, block := range blocks {
		label := blockLabel(block)
		if label == "" {
			// An unlabeled block is invalid and resolveModuleCall already rejects
			// it; keep it as its own entry rather than merging it by mistake.
			order = append(order, fmt.Sprintf("\x00%p", block))
			byLabel[order[len(order)-1]] = &mergedModuleBlock{block: block, attrs: block.Body.Attributes}
			continue
		}
		existing, ok := byLabel[label]
		if !ok {
			attrs := make(hclsyntax.Attributes, len(block.Body.Attributes))
			maps.Copy(attrs, block.Body.Attributes)
			byLabel[label] = &mergedModuleBlock{block: block, attrs: attrs}
			order = append(order, label)
			continue
		}
		maps.Copy(existing.attrs, block.Body.Attributes)
	}
	merged := make([]*hclsyntax.Block, len(order))
	for i, key := range order {
		merged[i] = byLabel[key].finalize()
	}
	return merged
}

type mergedModuleBlock struct {
	block *hclsyntax.Block
	attrs hclsyntax.Attributes
}

// finalize builds the effective block: the base block's identity with the
// merged attribute set. It is a no-op copy when nothing overlaid it.
func (m *mergedModuleBlock) finalize() *hclsyntax.Block {
	bodyCopy := *m.block.Body
	bodyCopy.Attributes = m.attrs
	blockCopy := *m.block
	blockCopy.Body = &bodyCopy
	return &blockCopy
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
	return e.LoadRootVarsWithContext(context.Background(), dir)
}

// LoadRootVarsWithContext preserves the scan boundary for linked variable files.
func (e *Evaluator) LoadRootVarsWithContext(ctx context.Context, dir string) map[string]cty.Value {
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
		src, err := tfmodules.ReadConfigFile(ctx, fsys, p, "")
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

func blockLabel(b *hclsyntax.Block) string {
	if len(b.Labels) == 0 {
		return ""
	}
	return b.Labels[0]
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
