/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
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

// parseDir parses all .tf files in dir (non-recursively) and returns their bodies.
// Files that fail to parse are skipped.
func parseDir(dir string) ([]*hclsyntax.Body, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".tf") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	bodies := make([]*hclsyntax.Body, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		src, rErr := os.ReadFile(filepath.Clean(path))
		if rErr != nil {
			continue
		}
		f, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			continue
		}
		if body, ok := f.Body.(*hclsyntax.Body); ok {
			bodies = append(bodies, body)
		}
	}
	return bodies, nil
}

// collectBlocks partitions blocks across all bodies into variables, locals,
// module calls, resources, and outputs.
func collectBlocks(bodies []*hclsyntax.Body) (
	varExprs map[string]hclsyntax.Expression,
	localExprs map[string]hclsyntax.Expression,
	modules []*hclsyntax.Block,
	resources []*hclsyntax.Block,
	outputs map[string]hclsyntax.Expression,
) {
	varExprs = map[string]hclsyntax.Expression{}
	localExprs = map[string]hclsyntax.Expression{}
	outputs = map[string]hclsyntax.Expression{}

	for _, body := range bodies {
		for _, block := range body.Blocks {
			switch block.Type {
			case "variable":
				if len(block.Labels) != 1 {
					continue
				}
				var defExpr hclsyntax.Expression
				if def, ok := block.Body.Attributes["default"]; ok {
					defExpr = def.Expr
				}
				varExprs[block.Labels[0]] = defExpr
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
	return varExprs, localExprs, modules, resources, outputs
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

// knownString evaluates attr and returns its string value, or "" if unknown/unset.
func knownString(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) string {
	if attr == nil {
		return ""
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() || v.IsNull() || v.Type() != cty.String {
		return ""
	}
	return v.AsString()
}

// resolveLocalDir resolves a local module source path relative to callerDir.
func resolveLocalDir(callerDir, source string) string {
	clean := StripGetterPrefix(source)
	if filepath.IsAbs(clean) {
		return filepath.Clean(clean)
	}
	return filepath.Clean(filepath.Join(callerDir, clean))
}

// StripGetterPrefix removes go-getter scheme prefixes so the source can be treated as a path.
// Compound prefixes like "git::file://./path" are fully stripped in two passes.
func StripGetterPrefix(source string) string {
	source = strings.TrimSpace(source)
	for _, scheme := range []string{"git::", "hg::", "http::", "https::"} {
		if after, ok := strings.CutPrefix(source, scheme); ok {
			source = after
			break
		}
	}
	source = strings.TrimPrefix(source, "file://")
	return source
}

// isEmptyCollection returns true when attr evaluates to a known empty collection under ctx.
// Unknown or unevaluable for_each expressions return false (conservative: keep the block).
func isEmptyCollection(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) bool {
	if attr == nil {
		return false
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() || v.IsNull() {
		return false
	}
	t := v.Type()
	if t.IsObjectType() || t.IsMapType() || t.IsListType() || t.IsTupleType() || t.IsSetType() {
		return v.LengthInt() == 0
	}
	return false
}

// LoadRootVars reads terraform.tfvars and *.auto.tfvars from dir and returns a
// variable map for use as root-module inputs. Terraform loads terraform.tfvars
// first, then *.auto.tfvars in lexicographic order; later files override earlier
// ones. Files that fail to read or parse are silently skipped.
func LoadRootVars(dir string) map[string]cty.Value {
	candidates := []string{filepath.Join(dir, "terraform.tfvars")}
	entries, _ := os.ReadDir(dir)
	var autoFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".auto.tfvars") {
			autoFiles = append(autoFiles, e.Name())
		}
	}
	sort.Strings(autoFiles)
	for _, name := range autoFiles {
		candidates = append(candidates, filepath.Join(dir, name))
	}

	out := map[string]cty.Value{}
	emptyCtx := &hcl.EvalContext{}
	for _, p := range candidates {
		src, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			continue
		}
		f, diags := hclsyntax.ParseConfig(src, p, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			continue
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for name, attr := range body.Attributes {
			v, attrDiags := attr.Expr.Value(emptyCtx)
			if !attrDiags.HasErrors() && v.IsKnown() {
				out[name] = v
			}
		}
	}
	return out
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
	if idx := strings.LastIndex(name, "["); idx >= 0 {
		inner := strings.TrimSuffix(name[idx+1:], "]")
		if _, err := strconv.Atoi(inner); err == nil {
			return name[:idx], inner, true, true
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

// isLiteralZero returns true when attr evaluates to the number zero under ctx.
// Unknown or unevaluable count expressions return false (conservative: keep the block).
func isLiteralZero(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) bool {
	if attr == nil {
		return false
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() || v.IsNull() {
		return false
	}
	if v.Type() == cty.Number {
		f, _ := v.AsBigFloat().Float64()
		return f == 0
	}
	return false
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
