/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"maps"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	lifecycleBlock = "lifecycle"
	localsBlock    = "locals"
)

// MergeOverrides applies the override files of one module directory the way
// Terraform does. bodies arrive in override-last order. An override block is
// merged into the base block of the same address: its attributes replace the
// base attributes by name, and a nested block type it sets replaces every
// base block of that type, dynamic ones included, except lifecycle, merged
// by argument. Locals merge by name. The merged block keeps the base block's
// position and file; each attribute keeps its own range. An override block
// without a base is kept as written. The input bodies are not modified.
func MergeOverrides(bodies []*hclsyntax.Body) []*hclsyntax.Body {
	firstOverride := len(bodies)
	for i, body := range bodies {
		if tfpath.IsOverrideFile(body.SrcRange.Filename) {
			firstOverride = i
			break
		}
	}
	if firstOverride == len(bodies) {
		return bodies
	}
	out, byKey, localsAt := indexBase(bodies[:firstOverride])
	for _, body := range bodies[firstOverride:] {
		rest := *body
		rest.Blocks = nil
		for _, block := range body.Blocks {
			if block.Type == localsBlock {
				if extra := mergeLocals(out, block, func(name string) (int, int, bool) {
					a, ok := localsAt[name]
					return a.body, a.block, ok
				}); extra != nil {
					rest.Blocks = append(rest.Blocks, extra)
				}
				continue
			}
			key, ok := overrideKey(block)
			if a, found := byKey[key]; ok && found {
				out[a.body].Blocks[a.block] = mergeBlock(out[a.body].Blocks[a.block], block)
				continue
			}
			rest.Blocks = append(rest.Blocks, block)
		}
		if len(rest.Blocks) > 0 || len(rest.Attributes) > 0 {
			out = append(out, &rest)
		}
	}
	return out
}

type at struct{ body, block int }

// indexBase copies the base bodies and indexes their blocks by override key
// and their locals by name.
func indexBase(bodies []*hclsyntax.Body) (out []*hclsyntax.Body, byKey, localsAt map[string]at) {
	out = make([]*hclsyntax.Body, 0, len(bodies))
	byKey, localsAt = map[string]at{}, map[string]at{}
	for i, body := range bodies {
		copied := *body
		copied.Blocks = append(hclsyntax.Blocks(nil), body.Blocks...)
		out = append(out, &copied)
		for j, block := range body.Blocks {
			if block.Type == localsBlock {
				for name := range block.Body.Attributes {
					localsAt[name] = at{i, j}
				}
				continue
			}
			if key, ok := overrideKey(block); ok {
				if _, seen := byKey[key]; !seen {
					byKey[key] = at{i, j}
				}
			}
		}
	}
	return out, byKey, localsAt
}

// overrideKey is the address an override block matches its base by.
func overrideKey(block *hclsyntax.Block) (string, bool) {
	switch block.Type {
	case "resource", "data", "ephemeral", "module", "variable", "output":
		return block.Type + "\x00" + strings.Join(block.Labels, "\x00"), len(block.Labels) > 0
	case "provider":
		if len(block.Labels) != 1 {
			return "", false
		}
		return "provider\x00" + block.Labels[0] + "\x00" + literalString(block.Body, "alias"), true
	}
	return "", false
}

func literalString(body *hclsyntax.Body, name string) string {
	attr, ok := body.Attributes[name]
	if !ok {
		return ""
	}
	v, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || !v.IsWhollyKnown() || v.IsNull() || v.Type() != cty.String {
		return ""
	}
	return v.AsString()
}

// mergeLocals replaces, in the base bodies, the locals the override block
// sets. It returns a block holding the locals no base declares, or nil.
func mergeLocals(out []*hclsyntax.Body, over *hclsyntax.Block, find func(string) (int, int, bool)) *hclsyntax.Block {
	var extra hclsyntax.Attributes
	for name, attr := range over.Body.Attributes {
		i, j, ok := find(name)
		if !ok {
			if extra == nil {
				extra = hclsyntax.Attributes{}
			}
			extra[name] = attr
			continue
		}
		base := out[i].Blocks[j]
		body := *base.Body
		body.Attributes = maps.Clone(base.Body.Attributes)
		body.Attributes[name] = attr
		copied := *base
		copied.Body = &body
		out[i].Blocks[j] = &copied
	}
	if extra == nil {
		return nil
	}
	body := *over.Body
	body.Attributes = extra
	copied := *over
	copied.Body = &body
	return &copied
}

func mergeBlock(base, over *hclsyntax.Block) *hclsyntax.Block {
	body := *base.Body
	body.Attributes = maps.Clone(base.Body.Attributes)
	if body.Attributes == nil {
		body.Attributes = hclsyntax.Attributes{}
	}
	maps.Copy(body.Attributes, over.Body.Attributes)

	replaced := map[string]bool{}
	for _, b := range over.Body.Blocks {
		if b.Type != lifecycleBlock {
			replaced[nestedType(b)] = true
		}
	}
	var baseLifecycle *hclsyntax.Block
	body.Blocks = nil
	for _, b := range base.Body.Blocks {
		switch {
		case b.Type == lifecycleBlock:
			baseLifecycle = b
		case !replaced[nestedType(b)]:
			body.Blocks = append(body.Blocks, b)
		}
	}
	for _, b := range over.Body.Blocks {
		if b.Type == lifecycleBlock && baseLifecycle != nil {
			b = mergeBlock(baseLifecycle, b)
			baseLifecycle = nil
		}
		body.Blocks = append(body.Blocks, b)
	}
	if baseLifecycle != nil {
		body.Blocks = append(body.Blocks, baseLifecycle)
	}
	copied := *base
	copied.Body = &body
	return &copied
}

// nestedType is the block type a nested block, or a dynamic block, makes.
func nestedType(b *hclsyntax.Block) string {
	if dynamicblock.Is(b) {
		return dynamicblock.GeneratedType(b)
	}
	return b.Type
}
