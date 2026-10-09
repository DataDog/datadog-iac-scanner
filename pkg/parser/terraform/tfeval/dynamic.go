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
// for_each does not resolve is kept as written.
func (e *Evaluator) addDynamicBlocks(out map[string]cty.Value, b *hclsyntax.Block, ctx *hcl.EvalContext) {
	content := dynamicblock.Content(b)
	iterators, resolved := dynamicblock.Iterators(b, ctx)
	if content == nil || !resolved {
		addNestedBlock(out, append([]string{b.Type}, b.Labels...), objectOrEmpty(e.evalBody(b.Body, ctx, nil)))
		return
	}
	name := dynamicblock.IteratorName(b)
	for _, it := range iterators {
		child := ctx.NewChild()
		child.Variables = map[string]cty.Value{name: it}
		path := append([]string{dynamicblock.GeneratedType(b)}, dynamicblock.Labels(b, child)...)
		addNestedBlock(out, path, objectOrEmpty(e.evalBody(content, child, nil)))
	}
}
