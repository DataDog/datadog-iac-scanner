/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"maps"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// dirStatic is dependency analysis of parsed syntax, shared by every instance
// of a directory. None of these answers depends on the evaluated input values.
type dirStatic struct {
	resourceAttrs          map[string][]string
	resources              *blockGraph
	siblings               []siblingReads
	moduleOrder            []int
	dataReadsData          bool
	dataReadsLocals        bool
	dataReadsResources     bool
	dataReadsModules       bool
	needsResourcePreinject bool
}

func newDirStatic(dp *dirParse) *dirStatic {
	s := &dirStatic{
		resourceAttrs: referencedResourceAttrs(dp),
		resources:     newBlockGraph(dp),
		siblings:      callSiblingReads(dp.modules),
	}
	for _, b := range dp.locals.dataBlocks {
		s.dataReadsData = s.dataReadsData || bodyReadsResource(b.Body, dataRoot)
		s.dataReadsLocals = s.dataReadsLocals || bodyReadsResource(b.Body, localRoot)
		s.dataReadsResources = s.dataReadsResources || bodyReadsResource(b.Body, dp.resourceTypes)
		s.dataReadsModules = s.dataReadsModules || bodyReadsResource(b.Body, moduleRoot)
	}
	s.dataReadsResources = s.dataReadsResources || (s.dataReadsLocals && dp.locals.readsResources)
	s.dataReadsModules = s.dataReadsModules || (s.dataReadsLocals && dp.locals.readsModules)
	s.needsResourcePreinject = dp.locals.readsResources || s.dataReadsResources || modulesReadResources(dp)
	// Module-dependent data needs full output publications between calls;
	// keep its existing orchestration outside the module/local DAG path.
	if !s.dataReadsModules {
		s.moduleOrder = moduleDependencyOrder(dp)
	}
	return s
}

func modulesReadResources(dp *dirParse) bool {
	if len(dp.resourceTypes) == 0 {
		return false
	}
	for _, mb := range dp.modules {
		if bodyReadsResource(mb.Body, dp.resourceTypes) {
			return true
		}
	}
	return false
}

// referencedResourceAttrs records top-level reads of declared managed resources.
// Without provider schemas an unset resource attribute may be computed. Add it
// as unknown to the reference value, rather than letting try/can mistake it for
// a missing key. Configured values and nested ordinary objects are unchanged.
// Direct traversal aliases through locals are followed without runtime object
// identity or marks, so no evaluator metadata escapes into values.
func referencedResourceAttrs(dp *dirParse) map[string][]string {
	r := resourceAttrReader{
		expanded: map[string]bool{}, locals: dp.localExprs,
		aliases: map[string]hcl.Traversal{}, attrs: map[string][]string{},
	}
	for _, b := range dp.resources {
		if len(b.Labels) != 2 {
			continue
		}
		_, count := b.Body.Attributes[metaArgCount]
		_, each := b.Body.Attributes[metaArgForEach]
		r.expanded[b.Labels[0]+"."+b.Labels[1]] = count || each
	}
	for _, body := range dp.bodies {
		_ = hclsyntax.VisitAll(body, r.visit)
	}
	for key, names := range r.attrs {
		slices.Sort(names)
		r.attrs[key] = slices.Compact(names)
	}
	return r.attrs
}

type resourceAttrReader struct {
	expanded map[string]bool
	locals   map[string]hclsyntax.Expression
	aliases  map[string]hcl.Traversal
	attrs    map[string][]string
}

func (r *resourceAttrReader) visit(node hclsyntax.Node) hcl.Diagnostics {
	if expr, ok := node.(hclsyntax.Expression); ok {
		r.record(r.resolve(expr))
	}
	if splat, ok := node.(*hclsyntax.SplatExpr); ok {
		if each, ok := splat.Each.(*hclsyntax.RelativeTraversalExpr); ok && each.Source == splat.Item {
			r.record(append(slices.Clone(r.resolve(splat.Source)), append(hcl.Traversal{hcl.TraverseSplat{}}, each.Traversal...)...))
		}
	}
	return nil
}

func (r *resourceAttrReader) record(t hcl.Traversal) {
	if len(t) < 3 || t.IsRelative() {
		return
	}
	name, ok := t[1].(hcl.TraverseAttr)
	if !ok {
		return
	}
	key := t.RootName() + "." + name.Name
	expands, declared := r.expanded[key]
	if !declared {
		return
	}
	rest := t[2:]
	switch rest[0].(type) {
	case hcl.TraverseSplat:
		rest = rest[1:]
	case hcl.TraverseIndex, hcl.TraverseAttr:
		if expands {
			rest = rest[1:]
		}
	}
	if len(rest) == 0 {
		return
	}
	if attr, ok := traversalAttribute(rest[0]); ok {
		switch attr {
		case metaArgCount, metaArgForEach, "provider", metaArgDependsOn, blockTypeLifecycle, blockTypeConnection, blockTypeProvisioner:
			// Terraform owns these arguments/blocks; they are not provider outputs.
			return
		}
		r.attrs[key] = append(r.attrs[key], attr)
	}
}

// resolve memoizes simple traversal aliases once per local. Ordinary object
// construction and other value transformations are deliberately not aliases.
func (r *resourceAttrReader) resolve(expr hclsyntax.Expression) hcl.Traversal {
	switch x := expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		t := x.Traversal
		if t.RootName() != rootLocal || len(t) < 2 {
			return t
		}
		name, ok := traversalAttribute(t[1])
		if !ok {
			return nil
		}
		alias, seen := r.aliases[name]
		if !seen {
			r.aliases[name] = nil
			alias = r.resolve(r.locals[name])
			r.aliases[name] = alias
		}
		if len(alias) == 0 {
			return nil
		}
		return append(slices.Clone(alias), t[2:]...)
	case *hclsyntax.RelativeTraversalExpr:
		return append(slices.Clone(r.resolve(x.Source)), x.Traversal...)
	case *hclsyntax.IndexExpr:
		key, _ := x.Key.Value(nil)
		if key == cty.NilVal {
			key = cty.DynamicVal
		}
		return append(slices.Clone(r.resolve(x.Collection)), hcl.TraverseIndex{Key: key})
	case *hclsyntax.ParenthesesExpr:
		return r.resolve(x.Expression)
	}
	return nil
}

func withReferencedResourceAttrs(attrs map[string]cty.Value, names []string) map[string]cty.Value {
	copied := false
	for _, name := range names {
		if _, set := attrs[name]; set {
			continue
		}
		if !copied {
			attrs = maps.Clone(attrs)
			if attrs == nil {
				attrs = map[string]cty.Value{}
			}
			copied = true
		}
		attrs[name] = cty.DynamicVal
	}
	return attrs
}

func traversalAttribute(step hcl.Traverser) (string, bool) {
	switch x := step.(type) {
	case hcl.TraverseAttr:
		return x.Name, true
	case hcl.TraverseIndex:
		if x.Key.IsKnown() && !x.Key.IsNull() && x.Key.Type() == cty.String {
			return x.Key.AsString(), true
		}
	}
	return "", false
}
