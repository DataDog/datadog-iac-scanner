/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package refs classifies the references a Terraform HCL expression makes.
package refs

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Kind is the namespace a Terraform traversal reads from.
type Kind uint8

const (
	KindOther Kind = iota
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

var kindNames = [...]string{
	KindOther:     "other",
	KindVar:       "var",
	KindLocal:     "local",
	KindResource:  "resource",
	KindData:      "data",
	KindEphemeral: "ephemeral",
	KindModule:    "module",
	KindEach:      "each",
	KindCount:     "count",
	KindSelf:      "self",
	KindPath:      "path",
	KindTerraform: "terraform",
}

// String returns the canonical namespace name for Kind.
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return kindNames[KindOther]
}

// Ref represents one object referenced by a Terraform HCL traversal.
type Ref struct {
	Kind       Kind
	Type       string // resource, data, or ephemeral type
	Name       string // variable, local, module, resource, or data label
	Key        *cty.Value
	DynamicKey bool
	KeyExpr    hcl.Expression
	RelAfter   []string
	Traversal  hcl.Traversal
}

var rootKinds = map[string]Kind{
	kindNames[KindVar]:       KindVar,
	kindNames[KindLocal]:     KindLocal,
	kindNames[KindData]:      KindData,
	kindNames[KindEphemeral]: KindEphemeral,
	kindNames[KindModule]:    KindModule,
	kindNames[KindEach]:      KindEach,
	kindNames[KindCount]:     KindCount,
	kindNames[KindSelf]:      KindSelf,
	kindNames[KindPath]:      KindPath,
	kindNames[KindTerraform]: KindTerraform,
}

// Parse classifies one HCL traversal.
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

// Of classifies every traversal read by expr in source order.
func Of(expr hcl.Expression) []Ref {
	if expr == nil {
		return nil
	}
	traversals := expr.Variables()
	if len(traversals) == 0 {
		return nil
	}
	indexed := indexedTraversals(expr)
	out := make([]Ref, len(traversals))
	for i, t := range traversals {
		out[i] = Parse(t)
		if out[i].Name != "" && len(t) == nameEnd(out[i].Kind) {
			if info, ok := indexed[t.SourceRange().Start]; ok {
				out[i].DynamicKey = true
				out[i].KeyExpr = info.key
				out[i].RelAfter = info.after
			}
		}
	}
	return out
}

type indexInfo struct {
	key   hcl.Expression
	after []string
}

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
			out = make(map[hcl.Pos]indexInfo)
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

// ReadPath returns the dotted attribute path read past the referenced object,
// skipping numeric list indexes.
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

// FirstAttr returns the top-level attribute read on the referenced object, or "".
func (r *Ref) FirstAttr() string {
	if len(r.RelAfter) > 0 {
		return r.RelAfter[0]
	}
	i := nameEnd(r.Kind)
	if i == 0 || len(r.Traversal) <= i {
		return ""
	}
	if r.Key != nil {
		i++
	}
	if len(r.Traversal) <= i {
		return ""
	}
	name, _ := staticStepName(r.Traversal[i])
	return name
}
