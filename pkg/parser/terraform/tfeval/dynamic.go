/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// addDynamicBlocks adds the nested blocks a dynamic block generates to out, in
// the shape a block written once per element would have. A dynamic block whose
// for_each or labels do not resolve is kept as written. A canceled ctx stops
// before further generated blocks are evaluated.
func (e *Evaluator) addDynamicBlocks(
	ctx context.Context, out *nestedBlocks, b *hclsyntax.Block, evalCtx *hcl.EvalContext, st *bodyState,
) {
	content := dynamicblock.Content(b)
	exp := dynamicblock.Expand(ctx, b, evalCtx)
	name := dynamicblock.IteratorName(b)
	resolved := content != nil && exp.Resolved
	var scopes []*hcl.EvalContext
	var paths [][]string
	if resolved {
		scopes, paths, resolved = generatedBlocks(ctx, b, exp.Iterators, name, evalCtx)
	}
	if !resolved {
		st.recordDynamic(b, keptAsWritten)
		out.add(append([]string{b.Type}, b.Labels...), objectOrEmpty(e.evalBodyWith(ctx, b.Body, evalCtx, nil, st.withoutMemo())))
		return
	}
	st.recordDynamic(b, len(scopes))
	for i, scope := range scopes {
		if ctx.Err() != nil {
			break
		}
		out.add(paths[i], objectOrEmpty(e.evalBodyWith(ctx, content, scope, nil, st.inDynamic(name))))
	}
}

// generatedBlocks binds each iterator in a child scope of evalCtx and resolves
// the path of the block it generates. ok is false when any label does not
// resolve: blocks generated with and without their labels would overwrite each
// other. A canceled ctx returns the scopes resolved so far.
func generatedBlocks(
	ctx context.Context, b *hclsyntax.Block, iterators []cty.Value, name string, evalCtx *hcl.EvalContext,
) (scopes []*hcl.EvalContext, paths [][]string, ok bool) {
	scopes = make([]*hcl.EvalContext, 0, len(iterators))
	paths = make([][]string, 0, len(iterators))
	for _, it := range iterators {
		if ctx.Err() != nil {
			break
		}
		child := evalCtx.NewChild()
		child.Variables = map[string]cty.Value{name: it}
		labels, resolved := dynamicblock.Labels(b, child)
		if !resolved {
			return nil, nil, false
		}
		scopes = append(scopes, child)
		paths = append(paths, append([]string{dynamicblock.GeneratedType(b)}, labels...))
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
