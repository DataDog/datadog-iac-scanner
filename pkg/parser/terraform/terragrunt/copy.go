/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// globList reads a list of strings attribute; prev is kept when it is absent
// or not wholly known.
func (t *translator) globList(body *hclsyntax.Body, name string, ctx *hcl.EvalContext, prev []string) []string {
	v, _ := t.attr(body, name, ctx).UnmarkDeep()
	if v == cty.NilVal || !v.IsWhollyKnown() || v.IsNull() || !v.CanIterateElements() {
		return prev
	}
	out := []string{}
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		s, ok := knownString(e)
		if !ok {
			return prev
		}
		out = append(out, s)
	}
	return out
}

// copiedModuleFiles returns the Terraform files of the unit's directory that
// Terragrunt copies next to its module, as absolute paths.
func (t *translator) copiedModuleFiles(filter CopyFilter) []string {
	var out []string
	dir := filepath.Dir(t.absUnit)
	for _, name := range t.fileNames(t.unitDir) {
		if tfpath.IsConfig(name) && filter.Copies(name) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out
}

// copiesAnything tells whether the unit directory has a copied entry besides
// terragrunt.hcl.
func (t *translator) copiesAnything(filter CopyFilter) bool {
	entries, err := t.fsys.ReadDir(t.unitDir)
	if err != nil || !t.confined(t.unitDir) {
		return false
	}
	for _, e := range entries {
		if e.Name() != tfpath.TerragruntUnit && filter.Traverses(e.Name()) {
			return true
		}
	}
	return false
}

// CopyFilter is Terragrunt's filter on the files of the unit directory copied
// next to the module. Globs are relative to the unit directory.
type CopyFilter struct{ Include, Exclude []string }

// Copies tells whether the file at rel (slash separated, relative to the unit
// directory) is copied: a file matching include_in_copy and not exclude_from_copy
// is, one matching exclude_from_copy is not, and any other is unless hidden.
func (f CopyFilter) Copies(rel string) bool {
	excluded := matchesPath(f.Exclude, rel)
	if matchesPath(f.Include, rel) && !excluded {
		return true
	}
	if excluded {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// Traverses tells whether the directory at rel must be listed: it is copied, or
// an include glob can match below it. A hidden directory is otherwise left out.
func (f CopyFilter) Traverses(rel string) bool {
	if f.Copies(rel) {
		return true
	}
	if matchesPath(f.Exclude, rel) {
		return false
	}
	dir := strings.Split(rel, "/")
	for _, g := range f.Include {
		segs := strings.Split(filepath.ToSlash(strings.TrimPrefix(g, "./")), "/")
		if len(segs) <= len(dir) && !slices.Contains(segs, "**") {
			continue
		}
		ok := true
		for i := range dir {
			if i >= len(segs) {
				break
			}
			if segs[i] == "**" {
				break
			}
			if m, err := path.Match(segs[i], dir[i]); err != nil || !m {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// matchesPath tells whether rel, or a directory holding it, matches a glob.
func matchesPath(globs []string, rel string) bool {
	for _, g := range globs {
		g = filepath.ToSlash(strings.TrimPrefix(g, "./"))
		for p := rel; p != "." && p != "/" && p != ""; p = path.Dir(p) {
			if ok, err := path.Match(g, p); err == nil && ok {
				return true
			}
		}
	}
	return false
}
