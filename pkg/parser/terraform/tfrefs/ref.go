/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfrefs

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Kind is the kind of object a reference reads.
type Kind uint8

const (
	KindOther Kind = iota // a traversal Terraform would reject, or an unrecognized root
	KindVar
	KindLocal
	KindResource // <type>.<name>
	KindData     // data.<type>.<name>
	KindEphemeral
	KindModule // module.<name>
	KindEach
	KindCount
	KindSelf
	KindPath
	KindTerraform
)

// Ref is one object an expression reads. It classifies a traversal by its root name
// the way Terraform names the objects, without validating it as Terraform does.
// Every traversal rooted at data, ephemeral, local or module takes that kind,
// even when its name is missing or not a literal: Name is then empty.
type Ref struct {
	Kind Kind
	Type string // resource, data and ephemeral types; empty otherwise
	Name string // variable, local, module, resource or data name
	// Key is the literal instance key that follows the name, nil when absent or dynamic.
	Key        *cty.Value
	DynamicKey bool // an index follows the name and is not a literal
	Traversal  hcl.Traversal
}

var rootKinds = map[string]Kind{
	"var":       KindVar,
	localRoot:   KindLocal,
	dataRoot:    KindData,
	"ephemeral": KindEphemeral,
	"module":    KindModule,
	"each":      KindEach,
	"count":     KindCount,
	"self":      KindSelf,
	"path":      KindPath,
	"terraform": KindTerraform,
}

// Parse classifies one traversal.
func Parse(t hcl.Traversal) Ref {
	ref := Ref{Traversal: t}
	kind, known := rootKinds[t.RootName()]
	if !known {
		if len(t) < 2 {
			return ref
		}
		name, ok := t[1].(hcl.TraverseAttr)
		if !ok {
			return ref
		}
		ref.Kind, ref.Type, ref.Name = KindResource, t.RootName(), name.Name
		ref.Key = literalKey(t, 2)
		return ref
	}
	ref.Kind = kind
	switch kind {
	case KindVar, KindLocal, KindModule:
		if len(t) > 1 {
			if name, ok := staticStepName(t[1]); ok {
				ref.Name = name
				ref.Key = literalKey(t, 2)
			}
		}
	case KindData, KindEphemeral:
		if len(t) > 1 {
			if typ, ok := t[1].(hcl.TraverseAttr); ok {
				ref.Type = typ.Name
			}
		}
		if ref.Type != "" && len(t) > 2 {
			if name, ok := t[2].(hcl.TraverseAttr); ok {
				ref.Name = name.Name
				ref.Key = literalKey(t, 3)
			}
		}
	}
	return ref
}

func literalKey(t hcl.Traversal, i int) *cty.Value {
	if len(t) <= i {
		return nil
	}
	if index, ok := t[i].(hcl.TraverseIndex); ok {
		key := index.Key
		return &key
	}
	return nil
}

// nameEnd is the length of a traversal that stops right after the name.
func nameEnd(kind Kind) int {
	switch kind {
	case KindResource, KindVar, KindLocal, KindModule:
		return 2
	case KindData, KindEphemeral:
		return 3
	}
	return 0
}

// Of classifies the traversals expr reads, one Ref per expr.Variables() entry, in order.
func Of(expr hcl.Expression) []Ref {
	traversals := expr.Variables()
	if len(traversals) == 0 {
		return nil
	}
	indexed := indexedTraversals(expr)
	refs := make([]Ref, len(traversals))
	for i, t := range traversals {
		refs[i] = Parse(t)
		if refs[i].Name != "" && len(t) == nameEnd(refs[i].Kind) && indexed[t.SourceRange().Start] {
			refs[i].DynamicKey = true
		}
	}
	return refs
}

// indexedTraversals returns the start of every traversal an index expression
// applies to: hclsyntax keeps a literal index in the traversal and wraps the
// traversal in an IndexExpr for any other key.
func indexedTraversals(expr hcl.Expression) map[hcl.Pos]bool {
	native, ok := expr.(hclsyntax.Expression)
	if !ok {
		return nil
	}
	var out map[hcl.Pos]bool
	_ = hclsyntax.VisitAll(native, func(node hclsyntax.Node) hcl.Diagnostics {
		index, ok := node.(*hclsyntax.IndexExpr)
		if !ok {
			return nil
		}
		if collection, ok := index.Collection.(*hclsyntax.ScopeTraversalExpr); ok {
			if out == nil {
				out = map[hcl.Pos]bool{}
			}
			out[collection.Traversal.SourceRange().Start] = true
		}
		return nil
	})
	return out
}

// OfBody classifies the traversals a block body reads: those of its attributes
// and nested blocks, dynamic blocks included, or, for a JSON body, of its
// attributes, which hold its nested blocks as objects. Inside a dynamic
// block's content the iterator name shadows a root of that name, and the
// iterator attribute names the loop variable rather than reading it.
func OfBody(body hcl.Body) []Ref {
	if native, ok := body.(*hclsyntax.Body); ok {
		return bodyRefs(nil, native, nil)
	}
	attrs, _ := body.JustAttributes()
	var out []Ref
	for _, attr := range attrs {
		out = append(out, Of(attr.Expr)...)
	}
	return out
}

// Traversals returns the traversal of each ref.
func Traversals(refs []Ref) []hcl.Traversal {
	out := make([]hcl.Traversal, len(refs))
	for i, ref := range refs {
		out[i] = ref.Traversal
	}
	return out
}
