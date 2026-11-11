/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package refs classifies the references a Terraform expression makes.
package refs

import (
	"strings"

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
	Key *cty.Value
	// DynamicKey is set when an IndexExpr indexes the name with a non-literal key.
	DynamicKey bool
	// KeyExpr is that non-literal index key, when DynamicKey is set.
	KeyExpr hcl.Expression
	// RelAfter is the attribute names a RelativeTraversal reads past an IndexExpr
	// that wraps this traversal: aws_iam_role.r[expr].id gives ["id"].
	RelAfter  []string
	Traversal hcl.Traversal
}

var rootKinds = map[string]Kind{
	"var":       KindVar,
	"local":     KindLocal,
	"data":      KindData,
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
	case KindEach, KindCount:
		return 1
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
		if refs[i].Name != "" && len(t) == nameEnd(refs[i].Kind) {
			if info, ok := indexed[t.SourceRange().Start]; ok {
				refs[i].DynamicKey = true
				refs[i].KeyExpr = info.key
				refs[i].RelAfter = info.after
			}
		}
	}
	return refs
}

type indexInfo struct {
	key   hcl.Expression
	after []string
}

// indexedTraversals returns the start of every traversal an index expression
// applies to: hclsyntax keeps a literal index in the traversal and wraps the
// traversal in an IndexExpr for any other key. Relative attributes past the
// index (aws_iam_role.r[expr].id) are recorded on the collection traversal.
func indexedTraversals(expr hcl.Expression) map[hcl.Pos]indexInfo {
	native, ok := expr.(hclsyntax.Expression)
	if !ok {
		return nil
	}
	var out map[hcl.Pos]indexInfo
	record := func(index *hclsyntax.IndexExpr, after []string) {
		collection, ok := index.Collection.(*hclsyntax.ScopeTraversalExpr)
		if !ok {
			return
		}
		if out == nil {
			out = map[hcl.Pos]indexInfo{}
		}
		pos := collection.Traversal.SourceRange().Start
		info := out[pos]
		info.key = index.Key
		if len(after) > 0 {
			info.after = after
		}
		out[pos] = info
	}
	_ = hclsyntax.VisitAll(native, func(node hclsyntax.Node) hcl.Diagnostics {
		switch n := node.(type) {
		case *hclsyntax.RelativeTraversalExpr:
			if index, ok := n.Source.(*hclsyntax.IndexExpr); ok {
				var after []string
				for _, step := range n.Traversal {
					name, ok := staticStepName(step)
					if !ok {
						break
					}
					after = append(after, name)
				}
				record(index, after)
			}
		case *hclsyntax.IndexExpr:
			record(n, nil)
		}
		return nil
	})
	return out
}

// staticStepName returns the name an attribute or a constant string index
// gives a reference step.
func staticStepName(step hcl.Traverser) (string, bool) {
	switch s := step.(type) {
	case hcl.TraverseAttr:
		return s.Name, true
	case hcl.TraverseIndex:
		if s.Key.IsKnown() && !s.Key.IsNull() && s.Key.Type() == cty.String {
			return s.Key.AsString(), true
		}
	}
	return "", false
}

// ReadPath is the dotted attribute path the traversal reads past the
// referenced object, list indexes skipped: aws_x.f.metric_transformation[0].name
// gives "metric_transformation.name". It stops at a step that is neither an
// attribute nor a literal index.
func (r *Ref) ReadPath() string {
	if len(r.RelAfter) > 0 {
		return strings.Join(r.RelAfter, ".")
	}
	i := nameEnd(r.Kind)
	if i == 0 || len(r.Traversal) < i {
		return ""
	}
	if r.Key != nil {
		i++
	}
	var out []string
	for _, step := range r.Traversal[i:] {
		if name, ok := staticStepName(step); ok {
			out = append(out, name)
			continue
		}
		if idx, ok := step.(hcl.TraverseIndex); ok && idx.Key.IsKnown() && !idx.Key.IsNull() && idx.Key.Type() == cty.Number {
			continue
		}
		break
	}
	return strings.Join(out, ".")
}

// After returns the attribute names the traversal reads past the referenced
// object and its literal instance key: aws_s3_bucket.b[0].arn gives ["arn"].
// For a dynamic IndexExpr, RelAfter supplies attributes past the index.
func (r *Ref) After() []string {
	if len(r.RelAfter) > 0 {
		return r.RelAfter
	}
	i := nameEnd(r.Kind)
	if i == 0 || len(r.Traversal) < i {
		return nil
	}
	if r.Key != nil {
		i++
	}
	var out []string
	for _, step := range r.Traversal[i:] {
		name, ok := staticStepName(step)
		if !ok {
			break
		}
		out = append(out, name)
	}
	return out
}
