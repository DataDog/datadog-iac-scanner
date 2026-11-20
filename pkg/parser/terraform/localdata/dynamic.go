/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const blockTypeDynamic = "dynamic"

var dynamicHeader = hcl.BlockHeaderSchema{Type: blockTypeDynamic, LabelNames: []string{"type"}}
var dynamicSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "for_each"}, {Name: "iterator"}},
	Blocks:     []hcl.BlockHeaderSchema{{Type: "content"}},
}

// RenderConfiguration adapts HCL solely for partial document rendering. Native
// evaluation uses ValueConfiguration and never re-evaluates expressions here.
type RenderConfiguration struct {
	Body hcl.Body
	Eval EvalFunc
}

func (r RenderConfiguration) DocumentRendering() bool { return true }
func (r RenderConfiguration) StructureKnown() bool    { return true }

// attribute extracts one optional field without asking JustAttributes to
// diagnose every legitimate nested block each time a provider reads a field.
func (r RenderConfiguration) attribute(name string) *hcl.Attribute {
	if body, ok := r.Body.(*hclsyntax.Body); ok {
		if attribute := body.Attributes[name]; attribute != nil {
			return attribute.AsHCLAttribute()
		}
		return nil
	}
	content, _, _ := r.Body.PartialContent(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: name}}})
	if content == nil {
		return nil
	}
	return content.Attributes[name]
}
func (r RenderConfiguration) Origin(name string) hcl.Range {
	if attribute := r.attribute(name); attribute != nil {
		return attribute.Range
	}
	return r.Body.MissingItemRange()
}
func (r RenderConfiguration) Attribute(name string) (cty.Value, bool) {
	attribute := r.attribute(name)
	if attribute == nil {
		return cty.NilVal, false
	}
	value, ok := r.Eval(attribute.Expr)
	if !ok {
		return cty.DynamicVal, true
	}
	return value, true
}

// blockContent adapts syntax blocks directly; asking PartialContent separately
// for every consumed block kind would repeatedly allocate remainder bodies.
func (r RenderConfiguration) blockContent(ctx context.Context, typ string) hcl.Blocks {
	if body, ok := r.Body.(*hclsyntax.Body); ok {
		var blocks hcl.Blocks
		for _, block := range body.Blocks {
			if ctx.Err() != nil {
				break
			}
			ordinary := block.Type == typ && len(block.Labels) == 0
			dynamic := block.Type == blockTypeDynamic && len(block.Labels) == 1
			if ordinary || dynamic {
				blocks = append(blocks, block.AsHCLBlock())
			}
		}
		return blocks
	}
	content, _, _ := r.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: typ}, dynamicHeader}})
	if content == nil {
		return nil
	}
	return content.Blocks
}
func (r RenderConfiguration) Blocks(ctx context.Context, typ string) BlockResult {
	blocks := r.blockContent(ctx, typ)
	out := BlockResult{Unresolved: ctx.Err() != nil}

	for _, block := range blocks {
		if ctx.Err() != nil {
			out.Unresolved = true
			break
		}
		if block.Type == typ {
			out.Items = append(out.Items, RenderConfiguration{Body: block.Body, Eval: r.Eval})
			continue
		}
		if block.Type != blockTypeDynamic || len(block.Labels) != 1 || block.Labels[0] != typ {
			continue
		}
		expanded := r.expand(ctx, block, typ)
		out.Items = append(out.Items, expanded.Items...)
		out.Unresolved = out.Unresolved || expanded.Unresolved
	}
	return out
}

func (r RenderConfiguration) expand(ctx context.Context, block *hcl.Block, typ string) BlockResult {
	var out BlockResult
	dyn, _, _ := block.Body.PartialContent(dynamicSchema)
	if dyn == nil || len(dyn.Blocks) != 1 || dyn.Attributes["for_each"] == nil {
		out.Unresolved = true
		return out
	}
	forEach, ok := r.Eval(dyn.Attributes["for_each"].Expr)
	if !ok || forEach == cty.NilVal {
		out.Unresolved = true
		return out
	}
	forEach, _ = forEach.Unmark()
	if forEach.IsNull() || !forEach.IsWhollyKnown() || !forEach.CanIterateElements() {
		out.Unresolved = true
		return out
	}
	name := typ
	if attr := dyn.Attributes["iterator"]; attr != nil {
		if kw := hcl.ExprAsKeyword(attr.Expr); kw != "" {
			name = kw
		}
	}
	for it := forEach.ElementIterator(); it.Next(); {
		if ctx.Err() != nil {
			out.Unresolved = true
			break
		}
		key, value := it.Element()
		vars := map[string]cty.Value{name: cty.ObjectVal(map[string]cty.Value{"key": key, "value": value})}
		bound := vars
		out.Items = append(out.Items, RenderConfiguration{
			Body: dyn.Blocks[0].Body,
			Eval: func(expr hcl.Expression) (cty.Value, bool) { return r.Eval(partial.Bind(expr, bound)) },
		})
	}
	return out
}
