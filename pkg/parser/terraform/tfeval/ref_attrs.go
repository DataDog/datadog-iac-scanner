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

// refKind is the namespace a resource reference reads.
type refKind uint8

const (
	refManaged refKind = iota
	refData
	refEphemeral
)

// refKey identifies a block by what a reference names.
type refKey struct {
	kind      refKind
	typ, name string
}

// referencedAttrs holds, for each block, the attributes of its instances that
// try, can, count or for_each read. A block's configuration does not say which
// of the attributes it leaves out the provider computes, so an attribute read
// there that the block does not set is taken to be one: unknown until apply, as
// Terraform has it, not a missing key that try or can would step past. Reading
// the other attributes of a block, or the keys of a value it does set, is
// unchanged.
type referencedAttrs map[refKey][]string

// collectReferencedAttrs finds the attributes read where an unknown value and
// a missing key differ: the arguments of try and can, and the count and
// for_each of a block.
func collectReferencedAttrs(bodies []*hclsyntax.Body) referencedAttrs {
	refs := referencedAttrs{}
	record := func(expr hclsyntax.Expression) {
		_ = hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
			refs.addNode(node)
			return nil
		})
	}
	for _, body := range bodies {
		_ = hclsyntax.VisitAll(body, func(node hclsyntax.Node) hcl.Diagnostics {
			switch n := node.(type) {
			case *hclsyntax.FunctionCallExpr:
				if n.Name == "try" || n.Name == "can" {
					for _, arg := range n.Args {
						record(arg)
					}
				}
			case *hclsyntax.Block:
				if !expandsBlock(n) {
					break
				}
				for _, name := range [...]string{metaArgCount, metaArgForEach} {
					if attr, ok := n.Body.Attributes[name]; ok {
						record(attr.Expr)
					}
				}
			}
			return nil
		})
	}
	for key, attrs := range refs {
		slices.Sort(attrs)
		refs[key] = slices.Compact(attrs)
	}
	return refs
}

// expandsBlock reports whether b is a block count and for_each expand.
func expandsBlock(b *hclsyntax.Block) bool {
	switch b.Type {
	case blockTypeResource, blockTypeData, blockTypeEphemeral, blockTypeModule:
		return true
	}
	return false
}

func (r referencedAttrs) add(key refKey, attr string) {
	r[key] = append(r[key], attr)
}

func (r referencedAttrs) addNode(node hclsyntax.Node) {
	switch n := node.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		if key, rest, ok := referenceOf(n.Traversal); ok {
			if attr, ok := firstAttribute(rest); ok {
				r.add(key, attr)
			}
		}
	case *hclsyntax.RelativeTraversalExpr:
		if key, ok := instanceReference(n.Source); ok {
			if attr, ok := firstAttribute(n.Traversal); ok {
				r.add(key, attr)
			}
		}
	case *hclsyntax.SplatExpr:
		each, isRelative := n.Each.(*hclsyntax.RelativeTraversalExpr)
		if !isRelative {
			return
		}
		if key, ok := instanceReference(n.Source); ok {
			if attr, ok := firstAttribute(each.Traversal); ok {
				r.add(key, attr)
			}
		}
	}
}

// instanceReference is the block an expression reading its instances names:
// the block's reference itself, or an index of it.
func instanceReference(expr hclsyntax.Expression) (refKey, bool) {
	if index, ok := expr.(*hclsyntax.IndexExpr); ok {
		expr = index.Collection
	}
	scope, ok := expr.(*hclsyntax.ScopeTraversalExpr)
	if !ok {
		return refKey{}, false
	}
	key, rest, ok := referenceOf(scope.Traversal)
	if !ok {
		return refKey{}, false
	}
	for _, step := range rest {
		if _, isIndex := step.(hcl.TraverseIndex); !isIndex {
			return refKey{}, false
		}
	}
	return key, true
}

// referenceOf splits a traversal naming a block, type.name for a resource and
// data.type.name or ephemeral.type.name for the others, from the steps after.
func referenceOf(t hcl.Traversal) (key refKey, rest hcl.Traversal, ok bool) {
	if len(t) < 2 || t.IsRelative() {
		return refKey{}, nil, false
	}
	root := t.RootName()
	switch root {
	case blockTypeModule, rootLocal, rootVar, rootEach, metaArgCount, rootSelf, rootPath, rootTerraform:
		return refKey{}, nil, false
	case blockTypeData, blockTypeEphemeral:
		if len(t) < 3 {
			return refKey{}, nil, false
		}
		typ, okType := traverserName(t[1])
		name, okName := traverserName(t[2])
		if !okType || !okName {
			return refKey{}, nil, false
		}
		kind := refData
		if root == blockTypeEphemeral {
			kind = refEphemeral
		}
		return refKey{kind: kind, typ: typ, name: name}, t[3:], true
	}
	name, okName := traverserName(t[1])
	if !okName {
		return refKey{}, nil, false
	}
	return refKey{kind: refManaged, typ: root, name: name}, t[2:], true
}

// firstAttribute is the attribute a run of steps reads, past the indexes
// selecting an instance.
func firstAttribute(steps hcl.Traversal) (string, bool) {
	for _, step := range steps {
		switch s := step.(type) {
		case hcl.TraverseAttr:
			return s.Name, true
		case hcl.TraverseIndex, hcl.TraverseSplat:
		default:
			return "", false
		}
	}
	return "", false
}

// withUnset returns attrs with each attribute read of the block that it does
// not set as an unknown value.
func (r referencedAttrs) withUnset(
	kind refKind, typ, name string, attrs map[string]cty.Value,
) map[string]cty.Value {
	var out map[string]cty.Value
	for _, attr := range r[refKey{kind: kind, typ: typ, name: name}] {
		if _, set := attrs[attr]; set {
			continue
		}
		if out == nil {
			out = maps.Clone(attrs)
			if out == nil {
				out = map[string]cty.Value{}
			}
		}
		out[attr] = cty.DynamicVal
	}
	if out == nil {
		return attrs
	}
	return out
}
