/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package dynamicblock expands Terraform dynamic blocks into the nested blocks
// they generate.
package dynamicblock

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

const (
	blockType   = "dynamic"
	contentType = "content"
	// MaxExpansion caps the blocks one dynamic block generates; a larger
	// for_each is kept as written rather than expanded in part.
	MaxExpansion = 256
	// MaxGeneratedPerResource caps the blocks the dynamic blocks under one resource
	// (or other top-level block) generate in total, nested ones included, so
	// nesting cannot multiply the per-block cap.
	MaxGeneratedPerResource = 1024
)

// Is reports whether b is a dynamic block.
func Is(b *hclsyntax.Block) bool {
	return b.Type == blockType && len(b.Labels) == 1
}

// GeneratedType is the type of the blocks b generates.
func GeneratedType(b *hclsyntax.Block) string {
	return b.Labels[0]
}

// Content returns the body every generated block is evaluated from.
func Content(b *hclsyntax.Block) *hclsyntax.Body {
	for _, inner := range b.Body.Blocks {
		if inner.Type == contentType {
			return inner.Body
		}
	}
	return nil
}

// IteratorName is the variable the content reads the current element through.
func IteratorName(b *hclsyntax.Block) string {
	if attr, ok := b.Body.Attributes["iterator"]; ok {
		if traversal, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() && len(traversal) == 1 {
			return traversal.RootName()
		}
	}
	return b.Labels[0]
}

// Expansion is what a dynamic block's for_each yields under an evaluation context.
type Expansion struct {
	// Iterators holds the iterator value of every block generated; empty unless Resolved.
	Iterators []cty.Value
	// Requested is how many blocks for_each asks for, whether or not they were
	// expanded; zero when for_each does not resolve.
	Requested int
	// Resolved is false when for_each cannot be resolved, or asks for more than
	// MaxExpansion blocks: how many blocks the dynamic block generates, possibly
	// none, is then unknown, and callers keep it as written so rules can tell a
	// block that may be absent from one that is present, and no generated block
	// is silently dropped.
	Resolved bool
	// OverCap is set when for_each resolves but asks for more than MaxExpansion.
	OverCap bool
}

// Expand evaluates the for_each of b under ctx.
func Expand(b *hclsyntax.Block, ctx *hcl.EvalContext) Expansion {
	attr, ok := b.Body.Attributes["for_each"]
	if !ok {
		return Expansion{}
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() || v.IsNull() || !v.CanIterateElements() || !v.Length().IsKnown() {
		return Expansion{}
	}
	requested := v.LengthInt()
	if requested > MaxExpansion {
		return Expansion{Requested: requested, OverCap: true}
	}
	iterators := make([]cty.Value, 0, requested)
	for it := v.ElementIterator(); it.Next(); {
		iterators = append(iterators, iterator(it.Element()))
	}
	return Expansion{Iterators: iterators, Requested: requested, Resolved: true}
}

func iterator(key, value cty.Value) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{"key": key, "value": value})
}

// Labels evaluates the labels of a generated block under ctx, which binds its
// iterator; none when they cannot be resolved.
func Labels(b *hclsyntax.Block, ctx *hcl.EvalContext) []string {
	attr, ok := b.Body.Attributes["labels"]
	if !ok {
		return nil
	}
	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || v.IsNull() || !v.IsWhollyKnown() || !v.CanIterateElements() {
		return nil
	}
	labels := make([]string, 0, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		_, label := it.Element()
		str, err := convert.Convert(label, cty.String)
		if err != nil {
			return nil
		}
		s, ok := ctyutil.ConcreteString(str)
		if !ok {
			return nil
		}
		labels = append(labels, s)
	}
	return labels
}
