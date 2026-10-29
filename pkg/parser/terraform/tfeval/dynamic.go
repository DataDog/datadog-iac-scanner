/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// addDynamicBlocks adds the nested blocks a dynamic block generates to out, in
// the shape a block written once per element would have. A dynamic block whose
// for_each or labels do not resolve is kept as written. Every resolved element
// is expanded: a cap would leave generated blocks without their content and
// their findings unreported.
//
// A dynamic block that reads no outer iteration generates identical blocks in
// every instance of the resource and every element of an enclosing dynamic
// block, so its expansion is computed once per resource block and shared.
// When ds wants a digest, the shared expansion folds one cached digest, and a
// varying one folds each element's digest.
func (e *Evaluator) addDynamicBlocks(out *nestedBlocks, b *hclsyntax.Block, ctx *hcl.EvalContext, st *bodyState, ds *digestState) {
	content := dynamicblock.Content(b)
	if e.addSharedDynamicBlocks(out, b, ctx, st, ds, content) {
		return
	}
	exp := dynamicblock.Expand(b, ctx)
	name := dynamicblock.IteratorName(b)
	resolved := content != nil && exp.Resolved
	var scopes []*hcl.EvalContext
	var paths [][]string
	if resolved {
		scopes, paths, resolved = generatedBlocks(b, exp.Iterators, name, ctx)
	}
	if !resolved {
		e.addKeptAsWritten(out, b, ctx, st, ds)
		return
	}
	st.recordDynamic(b, len(scopes))
	for i, scope := range scopes {
		val, dg, ok := e.evalBodyWithCore(content, scope, nil, st.inDynamic(name))
		out.add(paths[i], objectOrEmpty(val))
		if ds != nil {
			ds.foldDigest(tagRefDynElem, paths[i], dg, ok)
		}
	}
}

// addSharedDynamicBlocks expands a dynamic block whose expansion is identical
// in every instance and enclosing element: it reuses the block's memoized
// expansion when there is one, computes and memoizes it otherwise, and reports
// whether it handled the block. Blocks it does not handle (not invariant, no
// memo, or content-less) fall through to the per-instance expansion.
func (e *Evaluator) addSharedDynamicBlocks(
	out *nestedBlocks, b *hclsyntax.Block, ctx *hcl.EvalContext,
	st *bodyState, ds *digestState, content *hclsyntax.Body,
) bool {
	if content == nil || st == nil || st.memo == nil || st.memo.analysis == nil || !st.memo.analysis.dynOK[b] {
		return false
	}
	if exp, ok := st.memo.dynamicExpansion(b); ok {
		st.recordDynamic(b, len(exp.els))
		for i := range exp.els {
			out.add(exp.els[i].path, exp.els[i].val)
		}
		if ds != nil {
			ds.foldDigest(tagRefDynMemo, nil, exp.dg.d, exp.dg.ok)
		}
		return true
	}
	exp := dynamicblock.Expand(b, ctx)
	name := dynamicblock.IteratorName(b)
	scopes, paths, resolved := generatedBlocks(b, exp.Iterators, name, ctx)
	if !exp.Resolved || !resolved {
		// An invariant block whose expansion does not resolve is kept as
		// written, like any other unresolved dynamic block.
		e.addKeptAsWritten(out, b, ctx, st, ds)
		return true
	}
	els := make([]generatedBlock, len(scopes))
	ed := startDigest(st)
	for i, scope := range scopes {
		val, dg, ok := e.evalBodyWithCore(content, scope, nil, st.inDynamic(name))
		els[i] = generatedBlock{
			path: paths[i],
			val:  objectOrEmpty(val),
		}
		if ed != nil {
			ed.foldDigest(tagRefDynElem, paths[i], dg, ok)
		}
	}
	dgEntry, dgOK := ed.digest()
	entry := digestEntry{d: dgEntry, ok: dgOK}
	st.memo.storeDynamicExpansion(b, els, entry)
	st.recordDynamic(b, len(els))
	for i := range els {
		out.add(els[i].path, els[i].val)
	}
	if ds != nil {
		ds.foldDigest(tagRefDynMemo, nil, entry.d, entry.ok)
	}
	return true
}

// addKeptAsWritten adds a dynamic block that was not expanded as its written
// body.
func (e *Evaluator) addKeptAsWritten(out *nestedBlocks, b *hclsyntax.Block, ctx *hcl.EvalContext, st *bodyState, ds *digestState) {
	st.recordDynamic(b, keptAsWritten)
	val, dg, ok := e.evalBodyWithCore(b.Body, ctx, nil, st.withoutMemo())
	out.add(append([]string{b.Type}, b.Labels...), objectOrEmpty(val))
	if ds != nil {
		ds.foldDigest(tagRefDynWrite, append([]string{b.Type}, b.Labels...), dg, ok)
	}
}

// generatedBlocks binds each iterator in a child scope of ctx and resolves the
// path of the block it generates. ok is false when any label does not resolve:
// blocks generated with and without their labels would overwrite each other.
func generatedBlocks(
	b *hclsyntax.Block, iterators []cty.Value, name string, ctx *hcl.EvalContext,
) (scopes []*hcl.EvalContext, paths [][]string, ok bool) {
	scopes = make([]*hcl.EvalContext, len(iterators))
	paths = make([][]string, len(iterators))
	for i, it := range iterators {
		child := ctx.NewChild()
		child.Variables = map[string]cty.Value{name: it}
		labels, resolved := dynamicblock.Labels(b, child)
		if !resolved {
			return nil, nil, false
		}
		scopes[i] = child
		paths[i] = append([]string{dynamicblock.GeneratedType(b)}, labels...)
	}
	return scopes, paths, true
}

// DynamicCounts maps a dynamic block to how many blocks it generated, or to
// unknownDynamicCount when its evaluations disagreed (a nested dynamic block
// generates a different number under each element of its parent).
type DynamicCounts map[*hclsyntax.Block]int

const unknownDynamicCount = -1

// keptAsWritten records a dynamic block that was not expanded; it generated no
// blocks, but its as-written form is in the output.
const keptAsWritten = -2

func (st *bodyState) recordDynamic(b *hclsyntax.Block, n int) {
	if st == nil || st.dynamic == nil {
		return
	}
	if st.dynamic.counts == nil {
		st.dynamic.counts = make(DynamicCounts)
	}
	if prev, seen := st.dynamic.counts[b]; seen && prev != n {
		n = unknownDynamicCount
	}
	st.dynamic.counts[b] = n
}
