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
// for_each does not resolve, or asks for more blocks than the caps allow, is
// kept as written.
func (e *Evaluator) addDynamicBlocks(out map[string]cty.Value, b *hclsyntax.Block, ctx *hcl.EvalContext, st *bodyState) {
	content := dynamicblock.Content(b)
	exp := dynamicblock.Expand(b, ctx)
	resolved := content != nil && exp.Resolved
	if resolved && !st.reserveDynamic(len(exp.Iterators)) {
		st.noteDynamicOverflow(b, exp.Requested, dynamicblock.MaxGeneratedPerResource)
		resolved = false
	} else if content != nil && exp.OverCap {
		st.noteDynamicOverflow(b, exp.Requested, dynamicblock.MaxExpansion)
	}
	if !resolved {
		st.recordDynamic(b, 0)
		addNestedBlock(out, append([]string{b.Type}, b.Labels...), objectOrEmpty(e.evalBodyWith(b.Body, ctx, nil, st.withoutMemo())))
		return
	}
	st.recordDynamic(b, len(exp.Iterators))
	name := dynamicblock.IteratorName(b)
	for _, it := range exp.Iterators {
		child := ctx.NewChild()
		child.Variables = map[string]cty.Value{name: it}
		path := append([]string{dynamicblock.GeneratedType(b)}, dynamicblock.Labels(b, child)...)
		addNestedBlock(out, path, objectOrEmpty(e.evalBodyWith(content, child, nil, st.inDynamic(name))))
	}
}

// dynamicOverflow is a dynamic block kept as written because it asked for more
// blocks than a cap allows.
type dynamicOverflow struct {
	label     string
	requested int
	limit     int
}

// reserveDynamic claims n generated blocks of the resource instance's budget.
func (st *bodyState) reserveDynamic(n int) bool {
	if st == nil || st.dynamic == nil {
		return true
	}
	if st.dynamic.generated+n > dynamicblock.MaxGeneratedPerResource {
		return false
	}
	st.dynamic.generated += n
	return true
}

func (st *bodyState) noteDynamicOverflow(b *hclsyntax.Block, requested, limit int) {
	if st == nil || st.dynamic == nil {
		return
	}
	st.dynamic.overflow = append(st.dynamic.overflow, dynamicOverflow{
		label: dynamicblock.GeneratedType(b), requested: requested, limit: limit,
	})
}

// DynamicCounts maps a dynamic block to how many blocks it generated, or to
// unknownDynamicCount when its evaluations disagreed (a nested dynamic block
// generates a different number under each element of its parent).
type DynamicCounts map[*hclsyntax.Block]int

const unknownDynamicCount = -1

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
